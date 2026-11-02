---
title: "ADR-0039: SAML 2.0 login"
description: halo-server is a SAML 2.0 service provider next to its OIDC login, for IdPs that mandate SAML. crewjam/saml verifies signatures; Halos requires a signed assertion or response, a named audience, a bearer confirmation, a tight validity window, single-use request and assertion ids, and sends the result through the same directory, grants, revocation, session and audit path as OIDC.
status: accepted
date: 2026-11-01
---

# ADR-0039: SAML 2.0 login

> **Amended 2026-11-01 after security review.** SAML logins now enforce `identity.requireAcr`/`requireAmr` (fail closed); a pre-parse screen refuses namespace-prefix rebinding, more than one assertion, rsa-1_5 and unauthenticated AES-CBC; attributes match by `Name` only; the request cookie is `__Host-halo_saml` and is spent only after the response verifies.

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

- `GET /auth/saml/login`: builds an AuthnRequest, signs it (RSA-SHA256 or ECDSA-SHA256 with the SP key, HTTP-Redirect binding), stores its id in a sealed `__Host-halo_saml` cookie (HMAC with the session key, 10 minutes, `Path=/`, no Domain, `HttpOnly`, `SameSite=None; Secure` over https because the IdP posts back cross-site; the `__Host-` prefix keeps a sibling subdomain from planting or overwriting it; plain-http loopback dev uses `halo_saml`, `Path=/auth`). When policy has exactly one `identity.requireAcr`, it is sent as `RequestedAuthnContext` (`Comparison="exact"`). The OIDC state cookie is `__Host-halo_oidc` the same way, and redirects to the IdP's HTTP-Redirect SSO endpoint. The IdP must offer that binding: the console CSP (`form-action 'self'`) forbids posting a form to the IdP.
- `POST /auth/saml/acs`: the assertion consumer service, HTTP-POST binding only. The artifact binding is refused (crewjam would make a back-channel call to the IdP; we do not need it). Body at most 256 KiB.
- `GET /auth/saml/metadata`: SP metadata (entity id, the POST ACS, the SP certificate for signing and encryption) to register at the IdP.
- `GET /auth/methods`: `{"oidc": bool, "saml": bool}` for the login page. Public; it reveals only which methods are on.

All three SAML routes answer 404 when SAML is not configured.

### Validation of a response

Halos screens the decoded document first (`screenResponse`), before any signature or decryption work: it must be well-formed XML; no namespace prefix may be bound to more than one URI (the default namespace may switch per element, as SAML documents do); the Response may hold at most one `Assertion` or `EncryptedAssertion` child (each encrypted one costs an RSA decryption before anything is authenticated); every `EncryptionMethod` must be RSA-OAEP or AES-GCM, or AES-CBC only in a Response that carries a signature (crewjam verifies that signature before decrypting); rsa-1_5 key transport is always refused.

crewjam/saml (`ServiceProvider.ParseXMLResponse`) then runs:

1. The XML must round-trip (`xml-roundtrip-validator`), defeating parser-differential tricks.
2. If the Response carries a signature it must verify against a signing certificate from the IdP metadata; if it does not, every Assertion must carry one that verifies. A signature is accepted only over the element whose `ID` its `Reference` names. The bytes crewjam unmarshals are that element re-serialized with namespace declarations copied in from the whole document, so they are not byte-identical to the verified canonical form; the only way they could mean something different is a prefix bound to two URIs, which the screen refuses.
3. Response `Destination`, when present (always, when the Response is signed), must equal the ACS URL. Response `Issuer` and assertion `Issuer` must equal the IdP entity id.
4. `InResponseTo` on the Response and on each SubjectConfirmation must equal the request id from the request cookie.
5. Each SubjectConfirmation's `Recipient` must equal the ACS URL; its `NotOnOrAfter` must not have passed.
6. Response and assertion `IssueInstant` no older than 90 seconds; `Conditions` `NotBefore`/`NotOnOrAfter` with crewjam's 180-second skew.
7. EncryptedAssertions are decrypted with the SP key, then held to the same rules.

Halos then adds (`internal/server/saml.go`):

- **Audience required.** crewjam accepts an assertion with no `AudienceRestriction`; Halos requires one naming the SP entity id (`--saml-entity-id`, default `<baseURL>/auth/saml/metadata`).
- **Bearer confirmation required.** At least one SubjectConfirmation with method `bearer`, so the Recipient check above always runs.
- **Tighter skew.** `Conditions` must hold within 60 seconds of halo-server's clock, and `NotOnOrAfter` must be present.
- **Single-use request id.** Only once the response has verified is the cookie cleared and its request id consumed in the shared store; reusing it is refused. A forged cross-site POST that fails verification neither clears the cookie nor spends the id, so it cannot cancel a pending login.
- **Single-use assertion id.** SHA-256 of issuer and assertion `ID` is added to the store until the assertion could no longer be accepted (the later of `IssueInstant` + 90s and `NotOnOrAfter`, plus 180s). A second use is refused.
- **Panics are rejections.** crewjam dereferences `Subject` and `Conditions` of a verified assertion unchecked; the parse is wrapped so a malformed but signed assertion is a 401, not a dropped connection.

### Identity

- User id: the NameID, or the attribute whose `Name` is `--saml-user-attribute`. It must be an identifier the user cannot change at the IdP (UPN, object id, a persistent NameID), never a mail attribute the user or a delegated admin can edit: whoever controls the value controls the Halos identity. Groups: every value of each attribute whose `Name` is in `--saml-groups-attribute`, default `groups`, `Group`, `memberOf`, `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`, `http://schemas.xmlsoap.org/claims/Group`. `FriendlyName` is never matched: it is informational, not unique, and an IdP admin can give any attribute the friendly name `groups`.
- Entra ID groups overage (`http://schemas.microsoft.com/claims/groups.link` instead of groups) is refused with an actionable message and audited as `login.denied` (`reason: groups_overage`, `method: saml`), unless SCIM is authoritative. Graph resolution is OIDC-only: a SAML login has no Graph access token.
- Reserved ids (`service-account:`, `breakglass:`, canonicalized) are refused as for OIDC.
- From there the OIDC callback and the ACS share `issueSession`: SCIM `directoryGroups` (deactivated or unprovisioned users refused; authoritative groups win), `grants` from current policy, `revoked.issueAt` (the session starts past any revocation epoch), the policy-group filter and server-side session for large group sets, the session TTL and idle timeout (ADR-0036), and a `login` audit event, now with `method: oidc|saml`.
- Failed ACS posts are charged to the per-address failed-login budget shared with OIDC; metrics use flow `saml`.
- **Authentication context (fail closed).** `identity.requireAcr`: some AuthnStatement's `AuthnContextClassRef` must be one of the listed values (use SAML class URIs, e.g. `urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor`, or what your IdP emits). `identity.requireAmr`: the `http://schemas.microsoft.com/claims/authnmethodsreferences` attribute (Entra ID, ADFS) must contain one of the listed values; its `http://schemas.microsoft.com/claims/multipleauthn` value also counts as `mfa`, so `requireAmr: [mfa]` works for both protocols. An assertion that does not carry the evidence is denied (403, `login.denied`, `reason: authn_context`, `method: saml`), never let through. With policy requirements and SAML both configured, halo-server logs a warning at start so operators check their IdP sends them. With no policy loaded a SAML login is refused (503), as an OIDC login is.

### Configuration

halo-server flags: `--saml-idp-metadata-file` or `--saml-idp-metadata-url` (https only, http to loopback for tests; fetched once at start, 10-second timeout, no redirects, 1 MiB cap), `--saml-sp-key-file` and `--saml-sp-cert-file` (PEM; RSA or ECDSA; the certificate must match the key), `--saml-entity-id`, `--saml-user-attribute`, `--saml-groups-attribute`, `--saml-allow-idp-initiated` (default off, warned at start). The IdP metadata must contain an entity id, an IDPSSODescriptor with a signing certificate and an HTTP-Redirect SingleSignOnService, or halo-server refuses to start. Helm: `server.saml.{existingSecret,keyKey,certKey,idpMetadataKey,idpMetadataURL,entityID,userAttribute,groupsAttribute,allowIdPInitiated}`.

## Security considerations

| Threat | Handling | Residual |
|---|---|---|
| XML signature wrapping (signed element moved, unsigned look-alike read) | The signature must reference the element being verified by `ID`; crewjam unmarshals that same element (re-serialized with the document's namespace declarations; prefix rebinding is refused beforehand, so they cannot change meaning); only direct children of the Response are considered; XML that does not round-trip is refused. Tested: a copy with the genuine signature and an altered subject, the genuine assertion nested inside it, is rejected | A future crewjam/goxmldsig bug. goxmldsig is pinned at v1.6.1: v1.4.0, which crewjam v0.5.1 requires, has a signature bypass (GO-2026-4753) |
| Unsigned assertion | Without a valid Response signature every assertion must be signed; an unsigned one is rejected. Tested | |
| Comment / canonicalization injection in NameID | Exclusive c14n without comments; Go's `encoding/xml` reads the full text of the element, which is what was signed | |
| Response for another SP | Audience must name our entity id (required, not optional); Recipient and Destination must be our ACS. Tested (wrong audience, no audience) | |
| Replay of a captured response | Request id single-use (spent after verification, in the store); assertion id single-use until it would expire anyway; IssueInstant at most 90s old. Tested | Single-use is per store: in memory on one replica, shared across replicas when Postgres is configured (`storage.KV` on the shared Backend, as OIDC login state). Without Postgres, replicas do not share it, and running several without Postgres is already unsupported (ADR-0021) |
| Clock skew | NotBefore/NotOnOrAfter within 60s (Halos) and 180s (crewjam, applied first); IssueInstant within 90s | Hosts must run NTP |
| Login CSRF / session fixation (attacker's assertion posted into a victim's browser) | SP-initiated only by default: InResponseTo must match a request id sealed in this browser's cookie | With `--saml-allow-idp-initiated`, an attacker can sign a victim into the attacker's account. That is why it is off and warned |
| IdP-initiated SSO | Off by default; when on, a response with no request is accepted (InResponseTo cannot be checked) but still needs signature, audience, recipient, window and a fresh assertion id; a response arriving with a tracking cookie is still held to InResponseTo | See above |
| Encrypted assertions | RSA-OAEP key transport and AES-GCM content; AES-CBC only inside a Response that carries a signature, which crewjam verifies before decrypting; rsa-1_5 refused. Decrypted with the SP key, then the assertion must still verify unless the outer Response was signed. Tested | An IdP that encrypts with AES-CBC must also sign the Response |
| Artifact binding SSRF / back channel | Refused: only `SAMLResponse` is read, never `SAMLart`; metadata advertises the POST ACS only | |
| Metadata tampering | Metadata is server configuration (file, or an https URL fetched once at start) | Metadata fetched over https trusts the web PKI; pin a file for stronger assurance. A rotated IdP certificate needs a restart |
| Oversized or hostile XML | 256 KiB form limit; at most one assertion, screened before any RSA work; round-trip validation; panics in the library are caught | |
| MFA requirement bypassed by choosing SAML | `requireAcr`/`requireAmr` enforced on the assertion, fail closed. Tested | The IdP decides what its class or method values mean |
| Namespace-prefix confusion between verified and parsed bytes | A prefix bound to more than one URI anywhere in the document is refused before parsing. Tested | |
| Mutable user id (mail attribute) | Guide and ADR require an immutable identifier; attributes match by `Name` only. Tested (FriendlyName ignored) | Configuration, not code: Halos cannot tell which attributes a user can edit |
| Cookie tossing from a sibling subdomain | `__Host-` request cookie (Secure, Path=/, no Domain) | Plain-http dev has no prefix |
| Forged POST cancelling a pending login | Request id spent and cookie cleared only after verification. Tested | |
| Logging secrets | The private error is logged, never the response XML | |
| Reserved / spoofed ids | Service-account and break-glass prefixes refused | |

## Consequences

- **Good.** Enterprises on SAML-only IdPs can sign in without a broker; the security overview's "No SAML" gap closes.
- **Good.** One identity path after verification: directory, grants, revocation, sessions and audit cannot drift between protocols.
- **Bad.** Five new modules (`crewjam/saml`, `beevik/etree`, `russellhaering/goxmldsig`, `mattermost/xml-roundtrip-validator`, `jonboulle/clockwork`) and `golang.org/x/crypto` (crewjam's xmlenc imports `ripemd160`) in the server binary. x/crypto is held at v0.55.0, the newest release that keeps `go 1.25.0` (v0.56.0 and later require Go 1.26).
- **Bad.** No SAML single logout: `POST /auth/logout` ends Halos sessions; the IdP session is the IdP's.
- **Neutral.** FIPS builds: the SAML path uses only standard-library crypto, but an IdP signing with RSA-SHA1 or encrypting with RSA-OAEP-SHA1 may be refused in `fips140=only` mode. Use SHA-256.

## Implementation status (2026-11-01)

| Commitment | Code | Test | Status |
|---|---|---|---|
| SP login, ACS, metadata, methods; checks above; shared `issueSession` | `internal/server/saml.go`, `auth.go`, `server.go` | `internal/server/saml_test.go` `TestSAMLLogin` (valid, encrypted, unsigned, wrong/no audience, expired, skew, InResponseTo, tampered, wrapping, reserved id), `TestSAMLIdPInitiated` (off, on, replay), `TestSAMLDeactivatedSCIMUser`, `TestSAMLGroupsOverageDenied`, `TestSAMLMetadataAndMethods`, `TestSAMLConfigValidation` | Done |
| Security review (2026-11-01): acr/amr fail closed and RequestedAuthnContext, startup warning, pre-parse screen (prefix rebinding, one assertion, encryption algorithms), Name-only attributes, `__Host-` state cookies, request id spent after verification, Helm arg quoting | `internal/server/saml.go`, `auth.go`, `server.go`, `deploy/helm/halos` | `internal/server/saml_review_test.go` `TestSAMLAuthnContext`, `TestSAMLRequestedAuthnContextAndWarning`, `TestSAMLScreenResponse`, `TestSAMLAttributesByNameOnly`, `TestStateCookieName`, `TestSAMLForgedPostKeepsPendingLogin` | Done |
| Flags, files, metadata fetch | `cmd/halo-server/saml.go` | `TestSAMLFlags`, `TestSAMLConfigFiles` | Done |
| OpenAPI, Helm, console login page, docs | `internal/server/openapi_ops.go`, `deploy/helm/halos`, `web/src/App.tsx`, `docs/src/content/docs/guides/sso-saml.md` | `TestOpenAPI*` | Done |
| Real Okta, Entra ID, ADFS, Ping tenants | | | UNVERIFIED |
