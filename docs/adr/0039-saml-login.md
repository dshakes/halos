---
title: "ADR-0039: SAML 2.0 login"
description: halo-server is a SAML 2.0 service provider next to its OIDC login, for IdPs that mandate SAML. crewjam/saml verifies signatures; Halos requires a signed assertion or response, a named audience, a bearer confirmation, a tight validity window, single-use request and assertion ids, and sends the result through the same directory, grants, revocation, session and audit path as OIDC.
status: accepted
date: 2026-11-01
---

# ADR-0039: SAML 2.0 login

- Status: accepted
- Date: 2026-11-01

## Context and problem statement

The console login is OpenID Connect only (authorization code with PKCE). Many enterprises run identity on an IdP, or under a policy, that offers only SAML 2.0 to internal applications: ADFS, Ping, older Okta and Entra ID tenants where app registrations for OIDC are restricted. For them Halos is unusable without a broker in front of it, and the security overview says "No SAML".

SAML is a new trust boundary. The browser carries an XML document from the IdP to halo-server; halo-server must decide from that document alone who the user is. XML signature verification has a long history of bypasses (signature wrapping, comment injection, canonicalization differences), and SAML adds its own: replay of a captured response, a response minted for another service provider, unsolicited (IdP-initiated) responses that cannot be tied to the browser presenting them.

## Decision drivers

- One identity model. A SAML login yields the same `Principal` as an OIDC login and passes the same SCIM directory, policy grants, session revocation epochs, session TTL and idle timeout, and audit events. No SAML-only roles or code path after the identity is known.
- Do not write XML-DSig. Use a maintained library and keep Halos' code to the checks the library leaves optional.
- Safe by default: signed assertions required, IdP-initiated SSO off, audience mandatory.
- Configuration in halo-server flags and files (like the OIDC client secret and break-glass hash), not in policy: an SP key is a server secret.
- OIDC and SAML can both be on; the login page offers whichever are configured.

## Considered options

1. **Keep OIDC only; tell customers to broker SAML (Keycloak, Dex, Auth0) into OIDC.** No new code, but one more identity component for the customer to run and secure, and the broker becomes the real trust boundary.
2. **Hand-written SAML on `encoding/xml` and `crypto`.** Smallest dependency footprint; reimplements exclusive canonicalization and reference processing, exactly where the published bypasses live. Rejected.
3. **`github.com/crewjam/saml` (with `russellhaering/goxmldsig`, `beevik/etree`, `mattermost/xml-roundtrip-validator`).** The most used Go SAML library; validates signatures over the element it then reads, checks issuer, destination, recipient, InResponseTo, conditions and audience, rejects XML that does not round-trip. Chosen, with Halos adding the checks below.
4. **`github.com/russellhaering/gosaml2`.** Comparable, smaller community; no advantage that outweighs option 3.

## Decision outcome

### Endpoints

- `GET /auth/saml/login`: builds an AuthnRequest, signs it (RSA-SHA256 or ECDSA-SHA256 with the SP key, HTTP-Redirect binding), stores its id in a sealed `halo_saml` cookie (HMAC with the session key, 10 minutes, `Path=/auth/saml`, `HttpOnly`, `SameSite=None; Secure` over https because the IdP posts back cross-site), and redirects to the IdP's HTTP-Redirect SSO endpoint. The IdP must offer that binding: the console CSP (`form-action 'self'`) forbids posting a form to the IdP.
- `POST /auth/saml/acs`: the assertion consumer service, HTTP-POST binding only. The artifact binding is refused (crewjam would make a back-channel call to the IdP; we do not need it). Body at most 256 KiB.
- `GET /auth/saml/metadata`: SP metadata (entity id, the POST ACS, the SP certificate for signing and encryption) to register at the IdP.
- `GET /auth/methods`: `{"oidc": bool, "saml": bool}` for the login page. Public; it reveals only which methods are on.

All three SAML routes answer 404 when SAML is not configured.

### Validation of a response

crewjam/saml (`ServiceProvider.ParseXMLResponse`) runs first:

1. The XML must round-trip (`xml-roundtrip-validator`), defeating parser-differential tricks.
2. If the Response carries a signature it must verify against a signing certificate from the IdP metadata; if it does not, every Assertion must carry one that verifies. A signature is accepted only over the element whose `ID` its `Reference` names, and the element verified is the element read.
3. Response `Destination`, when present (always, when the Response is signed), must equal the ACS URL. Response `Issuer` and assertion `Issuer` must equal the IdP entity id.
4. `InResponseTo` on the Response and on each SubjectConfirmation must equal the request id from the `halo_saml` cookie.
5. Each SubjectConfirmation's `Recipient` must equal the ACS URL; its `NotOnOrAfter` must not have passed.
6. Response and assertion `IssueInstant` no older than 90 seconds; `Conditions` `NotBefore`/`NotOnOrAfter` with crewjam's 180-second skew.
7. EncryptedAssertions are decrypted with the SP key, then held to the same rules.

Halos then adds (`internal/server/saml.go`):

- **Audience required.** crewjam accepts an assertion with no `AudienceRestriction`; Halos requires one naming the SP entity id (`--saml-entity-id`, default `<baseURL>/auth/saml/metadata`).
- **Bearer confirmation required.** At least one SubjectConfirmation with method `bearer`, so the Recipient check above always runs.
- **Tighter skew.** `Conditions` must hold within 60 seconds of halo-server's clock, and `NotOnOrAfter` must be present.
- **Single-use request id.** The cookie is cleared and its request id consumed in the shared store before the response is parsed; reusing it is refused.
- **Single-use assertion id.** SHA-256 of issuer and assertion `ID` is added to the store until the assertion could no longer be accepted (the later of `IssueInstant` + 90s and `NotOnOrAfter`, plus 180s). A second use is refused.
- **Panics are rejections.** crewjam dereferences `Subject` and `Conditions` of a verified assertion unchecked; the parse is wrapped so a malformed but signed assertion is a 401, not a dropped connection.

### Identity

- User id: the NameID, or `--saml-user-attribute`. Groups: every value of each attribute named (by `Name` or `FriendlyName`) in `--saml-groups-attribute`, default `groups`, `Group`, `memberOf`, `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`, `http://schemas.xmlsoap.org/claims/Group`.
- Entra ID groups overage (`http://schemas.microsoft.com/claims/groups.link` instead of groups) is refused with an actionable message and audited as `login.denied` (`reason: groups_overage`, `method: saml`), unless SCIM is authoritative. Graph resolution is OIDC-only: a SAML login has no Graph access token.
- Reserved ids (`service-account:`, `breakglass:`, canonicalized) are refused as for OIDC.
- From there the OIDC callback and the ACS share `issueSession`: SCIM `directoryGroups` (deactivated or unprovisioned users refused; authoritative groups win), `grants` from current policy, `revoked.issueAt` (the session starts past any revocation epoch), the policy-group filter and server-side session for large group sets, the session TTL and idle timeout (ADR-0036), and a `login` audit event, now with `method: oidc|saml`.
- Failed ACS posts are charged to the per-address failed-login budget shared with OIDC; metrics use flow `saml`.
- `identity.requireAcr`/`requireAmr` are OIDC claims and do not apply to SAML logins; require MFA at the IdP (Conditional Access, sign-on policy).

### Configuration

halo-server flags: `--saml-idp-metadata-file` or `--saml-idp-metadata-url` (https only, http to loopback for tests; fetched once at start, 10-second timeout, no redirects, 1 MiB cap), `--saml-sp-key-file` and `--saml-sp-cert-file` (PEM; RSA or ECDSA; the certificate must match the key), `--saml-entity-id`, `--saml-user-attribute`, `--saml-groups-attribute`, `--saml-allow-idp-initiated` (default off, warned at start). The IdP metadata must contain an entity id, an IDPSSODescriptor with a signing certificate and an HTTP-Redirect SingleSignOnService, or halo-server refuses to start. Helm: `server.saml.{existingSecret,keyKey,certKey,idpMetadataKey,idpMetadataURL,entityID,userAttribute,groupsAttribute,allowIdPInitiated}`.

## Security considerations

| Threat | Handling | Residual |
|---|---|---|
| XML signature wrapping (signed element moved, unsigned look-alike read) | The signature must reference the element being verified by `ID`; the verified element is the one unmarshalled; only direct children of the Response are considered; XML that does not round-trip is refused. Tested: a copy with the genuine signature and an altered subject, the genuine assertion nested inside it, is rejected | A future crewjam/goxmldsig bug. goxmldsig is pinned at v1.6.1: v1.4.0, which crewjam v0.5.1 requires, has a signature bypass (GO-2026-4753) |
| Unsigned assertion | Without a valid Response signature every assertion must be signed; an unsigned one is rejected. Tested | |
| Comment / canonicalization injection in NameID | Exclusive c14n without comments; Go's `encoding/xml` reads the full text of the element, which is what was signed | |
| Response for another SP | Audience must name our entity id (required, not optional); Recipient and Destination must be our ACS. Tested (wrong audience, no audience) | |
| Replay of a captured response | Request id single-use (cookie cleared, id consumed in the store); assertion id single-use until it would expire anyway; IssueInstant at most 90s old. Tested | Single-use is per store: in memory on one replica, shared across replicas when Postgres is configured (`storage.KV` on the shared Backend, as OIDC login state). Without Postgres, replicas do not share it, and running several without Postgres is already unsupported (ADR-0021) |
| Clock skew | NotBefore/NotOnOrAfter within 60s (Halos) and 180s (crewjam, applied first); IssueInstant within 90s | Hosts must run NTP |
| Login CSRF / session fixation (attacker's assertion posted into a victim's browser) | SP-initiated only by default: InResponseTo must match a request id sealed in this browser's cookie | With `--saml-allow-idp-initiated`, an attacker can sign a victim into the attacker's account. That is why it is off and warned |
| IdP-initiated SSO | Off by default; when on, a response with no request is accepted (InResponseTo cannot be checked) but still needs signature, audience, recipient, window and a fresh assertion id; a response arriving with a tracking cookie is still held to InResponseTo | See above |
| Encrypted assertions | Decrypted with the SP key (RSA-OAEP key transport, AES-CBC/GCM content), then the decrypted assertion must still verify unless the outer Response was signed | AES-CBC without an outer signature would be malleable; the signature requirement covers it |
| Artifact binding SSRF / back channel | Refused: only `SAMLResponse` is read, never `SAMLart`; metadata advertises the POST ACS only | |
| Metadata tampering | Metadata is server configuration (file, or an https URL fetched once at start) | Metadata fetched over https trusts the web PKI; pin a file for stronger assurance. A rotated IdP certificate needs a restart |
| Oversized or hostile XML | 256 KiB form limit; round-trip validation; panics in the library are caught | |
| Logging secrets | The private error is logged, never the response XML | |
| Reserved / spoofed ids | Service-account and break-glass prefixes refused | |

## Consequences

- **Good.** Enterprises on SAML-only IdPs can sign in without a broker; the security overview's "No SAML" gap closes.
- **Good.** One identity path after verification: directory, grants, revocation, sessions and audit cannot drift between protocols.
- **Bad.** Five new modules (`crewjam/saml`, `beevik/etree`, `russellhaering/goxmldsig`, `mattermost/xml-roundtrip-validator`, `jonboulle/clockwork`) and `golang.org/x/crypto` (crewjam's xmlenc imports `ripemd160`) in the server binary. x/crypto v0.33.0 carries advisories govulncheck reports as not called by Halos.
- **Bad.** No SAML single logout: `POST /auth/logout` ends Halos sessions; the IdP session is the IdP's.
- **Neutral.** FIPS builds: the SAML path uses only standard-library crypto, but an IdP signing with RSA-SHA1 or encrypting with RSA-OAEP-SHA1 may be refused in `fips140=only` mode. Use SHA-256.

## Implementation status (2026-11-01)

| Commitment | Code | Test | Status |
|---|---|---|---|
| SP login, ACS, metadata, methods; checks above; shared `issueSession` | `internal/server/saml.go`, `auth.go`, `server.go` | `internal/server/saml_test.go` `TestSAMLLogin` (valid, encrypted, unsigned, wrong/no audience, expired, skew, InResponseTo, tampered, wrapping, reserved id), `TestSAMLIdPInitiated` (off, on, replay), `TestSAMLDeactivatedSCIMUser`, `TestSAMLGroupsOverageDenied`, `TestSAMLMetadataAndMethods`, `TestSAMLConfigValidation` | Done |
| Flags, files, metadata fetch | `cmd/halo-server/saml.go` | `TestSAMLFlags`, `TestSAMLConfigFiles` | Done |
| OpenAPI, Helm, console login page, docs | `internal/server/openapi_ops.go`, `deploy/helm/halos`, `web/src/App.tsx`, `docs/src/content/docs/guides/sso-saml.md` | `TestOpenAPI*` | Done |
| Real Okta, Entra ID, ADFS, Ping tenants | | | UNVERIFIED |
