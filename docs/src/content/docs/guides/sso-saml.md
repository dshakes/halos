---
title: Single sign-on with SAML 2.0
description: Sign users into the Halos console through a SAML IdP (Okta, Entra ID, ADFS, Ping) next to, or instead of, OIDC.
---

halo-server is a SAML 2.0 service provider for the console login, alongside its [OIDC login](/halos/guides/sso-entra/). Use it when your IdP or your security policy offers only SAML to internal applications. A SAML login ends exactly like an OIDC one: the SCIM directory decides who is active, roles come from groups mapped in policy, and the session follows the TTL, idle timeout and revocation rules of [ADR-0036](/halos/adr/0036-admin-api-credentials-break-glass-and-session-policy/). Design and threat model: [ADR-0039](/halos/adr/0039-saml-login/).

> Steps follow each vendor's documentation; they were not run against live Okta, Entra ID, ADFS or Ping tenants for this release. Check screen names against yours.

## 1. Create the SP key pair

halo-server signs its AuthnRequests and decrypts encrypted assertions with its own key. A self-signed certificate is normal for SAML (IdPs pin it from metadata):

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
  -subj "/CN=halos-saml" -keyout saml-sp.key -out saml-sp.crt
kubectl create secret tls halos-saml --key saml-sp.key --cert saml-sp.crt
```

ECDSA P-256 keys also work. Rotate by publishing the new certificate at the IdP before switching.

## 2. Register Halos at the IdP

| Setting | Value |
|---|---|
| ACS / Reply / Single sign-on URL (HTTP-POST) | `https://<portal baseURL>/auth/saml/acs` |
| Entity ID / Audience / Identifier | `https://<portal baseURL>/auth/saml/metadata` (or your `--saml-entity-id`) |
| SP metadata (for IdPs that import it) | `https://<portal baseURL>/auth/saml/metadata` |
| Name ID | The user id Halos matches in policy and SCIM. Use an identifier the user cannot change: the UPN, the directory object id, or a persistent NameID. Never a mail attribute the user (or a delegated admin) can edit: whoever sets that value becomes that Halos user |
| Signing | Sign the assertion (or the response), SHA-256 |
| Group attribute | Name `groups` (or set `--saml-groups-attribute`), values the groups policy maps |

Per IdP:

- **Okta.** Applications > Create App Integration > SAML 2.0. Single sign-on URL and Audience URI from the table; Name ID format EmailAddress; Group Attribute Statements: name `groups`, filter to the groups Halos maps. Download the IdP metadata from the Sign On tab.
- **Entra ID.** Enterprise applications > New application > Create your own > Non-gallery; Single sign-on > SAML. Identifier and Reply URL from the table. Attributes & Claims > Add a group claim: **Groups assigned to the application** (see overage below). Entra's default groups claim name, `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`, is read by default; the values are group object ids. Download **Federation Metadata XML**, or use the App Federation Metadata URL.
- **ADFS.** Add Relying Party Trust > import the SP metadata URL (or enter the ACS and identifier by hand). Claim issuance: send UPN or email as Name ID, and group membership as `http://schemas.xmlsoap.org/claims/Group` (read by default). Metadata: `https://<adfs>/FederationMetadata/2007-06/FederationMetadata.xml`.
- **Ping (PingFederate / PingOne).** Create an SP connection with Browser SSO, SP-initiated, HTTP-POST ACS from the table. Map `memberOf` (read by default) or `groups`. Export the IdP metadata.

The IdP must offer the **HTTP-Redirect** SSO binding (every one above does): halo-server refuses metadata without it.

## 3. Configure halo-server

| Flag | Helm (`server.saml.*`) | Meaning |
|---|---|---|
| `--saml-idp-metadata-file` | `idpMetadataKey` (a key in `existingSecret`) | IdP metadata XML. Turns SAML on |
| `--saml-idp-metadata-url` | `idpMetadataURL` | Or fetch it at start (https). Restart to pick up a rotated IdP certificate |
| `--saml-sp-key-file`, `--saml-sp-cert-file` | `existingSecret` with `keyKey`/`certKey` (default `tls.key`/`tls.crt`) | SP key pair from step 1 |
| `--saml-entity-id` | `entityID` | Default `<baseURL>/auth/saml/metadata` |
| `--saml-user-attribute` | `userAttribute` | `Name` of the attribute holding the user id; default the Name ID. Same rule: an immutable identifier only |
| `--saml-groups-attribute` | `groupsAttribute` | Comma-separated attribute `Name`s (never matched against `FriendlyName`); default `groups`, `Group`, `memberOf` and the Entra ID and ADFS group claim URIs |
| `--saml-allow-idp-initiated` | `allowIdPInitiated` | Accept logins started from the IdP's app dashboard. Off: see below |

```yaml
server:
  portal: {baseURL: https://halos.acme.example}
  saml:
    existingSecret: halos-saml        # tls.key, tls.crt, plus idp-metadata.xml
    idpMetadataKey: idp-metadata.xml
```

Roles map groups exactly as for OIDC:

```yaml
identity:
  adminGroups: [halos-admins]
  roles:
    operator: [halos-oncall]
```

OIDC stays on as long as policy names `identity.issuer` and `clientID`; the login page then shows both buttons. To offer SAML only, leave those unset.

## 4. Behaviour to know

- **Signed assertions required.** halo-server refuses a response unless the assertion, or the whole response, is signed by a certificate in the IdP metadata. Encrypted assertions must use RSA-OAEP with AES-GCM, or AES-CBC inside a signed Response; rsa-1_5 is refused. In practice, if the IdP encrypts assertions, set it to sign the whole Response (Entra: "Sign SAML response and assertion"; Okta: Response signing on) and use AES-CBC: the SAML library's AES-GCM path is not interoperable today. Encryption is optional; TLS already protects the assertion in transit. A response with more than one assertion is refused. It also checks audience, recipient, destination, InResponseTo, a 60-second validity skew, and that each assertion id is used once.
- **IdP-initiated SSO is off.** A login must start at Halos (`/auth/saml/login`), so the response can be tied to the browser that asked for it (a `__Host-halo_saml` cookie, spent only once the response verifies). Turning on `--saml-allow-idp-initiated` lets IdP dashboard tiles work, and also lets an attacker sign a victim's browser into the attacker's account (login CSRF). Assertions are still single-use.
- **Groups overage (Entra ID).** Past 150 groups Entra sends a `groups.link` claim instead of groups. halo-server refuses that login (`login.denied`, `reason: groups_overage`) rather than log the user in with no roles. Emit **Groups assigned to the application**, or make [SCIM](/halos/guides/scim-provisioning/) authoritative.
- **MFA (`identity.requireAcr` / `requireAmr`).** Both apply to SAML logins and fail closed: if the assertion does not carry the evidence, the login is denied (403, `login.denied`, `reason: authn_context`). halo-server warns at start when policy has either and SAML is on.
  - `requireAcr`: an AuthnStatement's `AuthnContextClassRef` must be one of the values, so list SAML class URIs (for example `urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor`, or the value your IdP emits after MFA; Okta and Ping can be configured to send one). With exactly one value, halo-server also asks for it in the AuthnRequest (`RequestedAuthnContext`, exact).
  - `requireAmr`: read from the `http://schemas.microsoft.com/claims/authnmethodsreferences` attribute, which Entra ID and ADFS send. Its `http://schemas.microsoft.com/claims/multipleauthn` value counts as `mfa`, so `requireAmr: [mfa]` covers OIDC and SAML. Other IdPs do not send this attribute: there, `requireAmr` denies every SAML login. Use `requireAcr`, or add the attribute at the IdP.
  - Policy is shared with OIDC: a `requireAcr` of OIDC `acr` values only will deny SAML logins unless the IdP sends the same value as the class ref. List both forms if you use both protocols.
- **Logout** ends every Halos session of the user. It does not log out of the IdP (no SAML single logout).
- **Replicas.** Request and assertion ids are recorded in the shared Postgres store when `--database-url-file` is set, so a replayed response is refused on every replica.

## 5. Verify

1. `curl -s https://<baseURL>/auth/methods` shows `"saml":true`.
2. Sign in from the console with **Continue with SAML** (or **Continue** when SAML is the only method). `GET /api/v1/me` shows the expected `groups` and `roles`.
3. The audit log has a `login` entry with `method: saml`. A failed login is logged by halo-server with the reason (`saml acs failed`) and counted in `halo_server_auth_failures_total{flow="saml"}`.
