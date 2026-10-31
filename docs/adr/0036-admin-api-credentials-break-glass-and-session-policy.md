---
title: "ADR-0036: Admin API credentials, break-glass and session policy"
description: Service-account API tokens bound to one role for automation, a sealed break-glass local admin for IdP outages, a configurable absolute and sliding idle session lifetime, and OIDC login that never silently grants no roles (Entra ID groups overage) and can require MFA (acr/amr).
status: accepted
date: 2026-10-30
---

# ADR-0036: Admin API credentials, break-glass and session policy

- Status: accepted
- Date: 2026-10-30

## Context and problem statement

halo-server has one way in for people and automation alike: an OIDC login that yields a `halo_session` cookie with a fixed 12-hour lifetime and no idle timeout. Automation (the `halo` CLI's server-backed commands, `halo mcp serve --server`, scripts, CI) runs as `HALO_SESSION=<admin halo_session cookie>` copied out of a browser. That copied cookie:

- is a human's whole session, with all of that human's roles, sitting in a pipeline secret or a shell history;
- shows in the audit log as the human, so nobody can tell automation from the person;
- dies after at most 12 hours, so people copy it again, often;
- cannot be revoked without ending the human's own sessions.

Three more gaps sit on the same trust boundary:

- **No way in when the IdP is down.** An IdP outage, or a broken `identity.issuer` in policy, locks every admin out of the kill switch and the incident freeze, the moment they matter most.
- **Entra ID groups overage.** Past 200 groups Entra drops the `groups` claim from the ID token and puts `_claim_names`/`_claim_sources` (or `hasgroups: true`) in its place. halo-server read that as "no groups": the user logged in with no roles, silently.
- **No step-up.** Policy could not require that a console login used MFA.

## Decision drivers

- Automation gets its own credential: least privilege, attributable, revocable alone, expiring, scannable when leaked.
- No credential stronger than the person who made it; no credential that renews itself.
- Break-glass exists, is off until someone deliberately turns it on, and is loud: every use reaches the SIEM.
- Sessions end when a user walks away, not only after 12 hours; defaults stay compatible.
- A login never succeeds with fewer roles than the user holds, without saying so.
- No new dependency (no bcrypt/argon2 module; `golang.org/x/crypto` is not in `go.mod`), the existing storage seam and RBAC table, the existing audit chain and SIEM export.

## Considered options

### Automation credentials

1. **Keep copying cookies.** Status quo; every problem above.
2. **OAuth client credentials at the IdP**, verified by halo-server as JWTs. Ties automation to the IdP (down in exactly the incident where the kill switch is needed), needs per-IdP setup, and the IdP's tokens carry no Halos role.
3. **Long-lived random tokens issued by halo-server, bound to one role, stored hashed.** Chosen. The same shape as GitHub and GitLab personal access tokens.
4. **Signed (JWT) service tokens.** Offline verification is not needed (halo-server is the only verifier), and revocation would need a list anyway; an opaque token with a row lookup revokes at once and leaks nothing when decoded.

### Break-glass

1. **None; fix the IdP.** Leaves the kill switch unreachable during an IdP incident.
2. **`--dev-insecure-user`.** Disables authentication for everyone. Never in production.
3. **A sealed local account: a password hash in server configuration, refused unless explicitly enabled, short fixed session, every use audited at high severity.** Chosen.

### Idle timeout

1. **Server-side session store with a last-seen row per session.** A write on every request, on every replica.
2. **Last-seen time in the signed cookie, re-issued as the session is used.** Chosen: stateless, every replica agrees.

### Groups overage

1. **Ignore it (status quo).** Silently strips roles.
2. **Always deny.** Safe and clear, but leaves large tenants without a way in other than restricting the app's group claims.
3. **Deny by default; resolve from Microsoft Graph when policy says so.** Chosen.

## Decision outcome

### Service-account API tokens

- **Format.** `halo_sat_` + 16 hex digits of public id + 64 hex digits of secret (256 random bits from `crypto/rand`), 89 characters, regex `halo_sat_[0-9a-f]{80}` for secret scanners (`internal/server/servicetokens.go`).
- **Storage.** Only the SHA-256 of the whole token is stored, next to the id and metadata (name, role, description, owner, creator, creation, expiry, revocation). The id finds the row; the stored hash is compared with `crypto/subtle.ConstantTimeCompare`. SHA-256 rather than HMAC under a server key: the input has 256 bits of entropy, so a stolen table cannot be brute-forced either way, and keying it to the session key would end every token when that key rotates. Postgres: table `halo_service_tokens` (`internal/pgstore/migrations/0004_service_tokens.sql`, `min-binary-schema: 1`, additive); single replica: `service-tokens.jsonl` under `--data-dir`, replayed on start; `halo-server import` copies it. A revocation is never undone by a replay or an import.
- **Lifetime.** Every token expires. `ttl` defaults to, and may not exceed, `--service-token-max-ttl` (default 90 days, at most 365 days, at least 1 hour). Expired and revoked rows stay listed; Postgres prunes rows 30 days past expiry.
- **Role.** Exactly one role from the existing set (ADR-0015). A token's role may not grant any permission its creator lacks (`roleWithin`). The principal is `service-account:<name>:<id>`, with that role only, no groups, outside SCIM.
- **Who manages them.** `POST /api/v1/service-tokens`, `GET /api/v1/service-tokens`, `POST /api/v1/service-tokens/{id}/revoke` (reason required), all `admin` in `routePerms`. Creating needs an interactive human session: a token cannot mint its successor, and break-glass cannot leave credentials behind. Any admin principal, a token or break-glass included, may list and revoke. The token is returned once (201) and never again. It is stored before `service-token.create` is audited (`AuditStrict`); if the audit append fails, the token is revoked again and not returned. At most 1,000 active tokens, counted and enforced atomically with the insert (an advisory-locked transaction on Postgres, the store mutex on one replica).
- **Separation of duties (amended after security review).** A token acts on behalf of its creator: its Principal carries `OnBehalfOf`, and every separation-of-duties comparison (self-approval, duplicate approval) matches either id. Beyond that, filing, approving and denying access requests and approving rollout steps need a human: a token or break-glass caller gets 403 ("this decision needs a person"), audited as `authz.deny` with `need: human`. Without this a person refused as their own approver could mint an `approver` token and approve through it, or count twice toward a quorum.
- **Use.** `Authorization: Bearer halo_sat_...` on any console/API route. A bearer value without the prefix is not ours (a fronting proxy's, say) and falls through to the cookie. Failed attempts (malformed, unknown, wrong secret, revoked) are charged to the client address on their own failed-auth budget (10 per minute, shared across replicas, as the other limiters); an expired token is a 401 without a charge; a store error is a 503, never a pass. The row is read on every request, so a revocation on any replica holds on every replica at the token's next use.
- **Attribution.** Every action a token takes is audited with its principal as the actor. Its use is also audited as `service-token.use` (method, path, role), at most once an hour per token per replica.
- **Clients.** `halo service-token create|list|revoke`. The `halo` CLI's server-backed commands and `halo mcp serve --server` read `HALO_TOKEN`, which wins over `HALO_SESSION`; a `halo_sat_` value is sent as a bearer token, anything else as the cookie. `halo mcp token` still takes only a session or workload credential as a delegation parent (ADR-0024): service accounts do not delegate.

### Break-glass

- **Configuration.** `--breakglass-hash-file` holds `pbkdf2-sha256$600000$<salt>$<key>` from `halo-server breakglass-hash` (Go's standard `crypto/pbkdf2`, PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte salt; fewer iterations are refused; passwords of at least 16 characters). `--breakglass-user` (default `breakglass`). Helm: `server.breakGlass.{existingSecret,key,user,enabled}`.
- **Sealed.** Without `--breakglass-enabled`, `POST /auth/breakglass` answers 404. Enabling it is a deploy, and the server logs a warning at start.
- **Where from.** `--breakglass-allowed-cidrs` (Helm `server.breakGlass.allowedCIDRs`) is required whenever break-glass is enabled: halo-server refuses to start, and the chart to render, without it. Login from any other client address answers 404 as if sealed, before the password is read, so outsiders can neither guess nor move the global failure count; a break-glass session used from elsewhere is refused. Use the VPN or bastion range. A range broader than /8 (IPv4) or /32 (IPv6), `0.0.0.0/0` and `::/0` included, would re-open the lockout denial of service, so it is refused (the flag, `server.New` whether sealed or enabled, and the Helm template); IPv4 /8 to /15 and IPv6 /32 to /47 are accepted with a startup warning.
- **Login.** `POST /auth/breakglass {"user","password"}`, same-origin check, the OIDC callback's per-address failed-login budget, a global budget (20 failures in 15 minutes from allowed addresses, shared across replicas) that locks every break-glass login for 15 minutes, at most two concurrent verifications (the KDF costs CPU). The lock is one entry in the shared store: every replica locks at once, and only the replica whose write created it audits `breakglass.lockout` (high severity). `POST /api/v1/breakglass/unlock` (admin, a person, from a normal SSO session) lifts it on every replica and resets the count, audited as `breakglass.unlock` at high severity, so the locked path is never needed to unlock. The KDF runs whatever the user name, and the comparison is constant time. Success sets a session cookie for `breakglass:<user>`, admin role, valid 30 minutes and never extended.
- **Loud.** `breakglass.login` is written with `AuditStrict` and `severity: high` before the cookie is issued: if the audit log is unavailable the login is refused. Failed attempts (`breakglass.login.failed`) and every request the session makes (`breakglass.request`) are audited at high severity too; a state-changing request (anything but GET) is audited with `AuditStrict` before it acts and refused with 503 if the entry cannot be written. SIEM export marks high-severity entries: OCSF `severity_id` 4 (High), syslog severity 2 (critical) instead of 6.
- **Contained.** The session carries a fingerprint of the configured hash: disabling break-glass or rotating the password ends it on the next request. It cannot create service tokens, act as a delegation parent, or file or decide access requests and rollout approvals. It is outside policy and SCIM (that is the point), so a broken policy or directory does not lock it out. Runbook: [Admin access](/halos/guides/admin-access/#break-glass).

### Session policy

- `--session-ttl` (default 12h, 5m to 168h): absolute lifetime from login, never extended.
- `--session-idle-timeout` (default 1h, at least 1m and at most the TTL; 0 turns it off): the session ends after this long without a request. The cookie carries its last-seen time, sealed with the session key; once it is older than a tenth of the idle timeout the next request re-issues the cookie with the same absolute expiry. A cookie issued before this change falls back to its issue time.
- Helm: `server.session.{ttl,idleTimeout}`, `server.serviceTokens.maxTTL`. Delegation from a session (ADR-0024) applies the same checks, and the delegated credential expires no later than the session's idle deadline (last seen plus the idle timeout); every credential exchanged from it is bounded by its parent's expiry, so the whole chain dies with the idle session.
- **Compatibility.** The 1-hour idle default ends a copied `HALO_SESSION` an hour after the browser last used it. That is intended: automation moves to `HALO_TOKEN`. Set `--session-idle-timeout=0` for the previous behaviour.

### OIDC login

- **Groups overage.** When the groups claim is absent and `_claim_names` names it, or `hasgroups` is true (Entra ID), the login is refused with an error naming the fix and audited as `login.denied` (`reason: groups_overage`), unless policy sets `identity.groupsOverage: graph`. Then the login also requests `User.Read` and `GroupMember.Read.All` (admin consent), and halo-server calls `POST <graph>/me/getMemberObjects` with the login's access token (`net/http`, 10-second timeout, no redirects, at most 4 MiB, paging refused rather than truncated). A Graph failure refuses the login (503, `login.denied`, `reason: groups_graph`). `_claim_sources` is never followed. `--entra-graph-url` selects national clouds. With SCIM authoritative (ADR-0022) the directory decides groups and overage does not matter.
- **Authentication context.** `identity.requireAcr`: the ID token's `acr` must be one of them, and they are sent as `acr_values`. `identity.requireAmr`: its `amr` must contain at least one of them (e.g. `[mfa]`). A failure is a 403 telling the user to sign in again with MFA, audited as `login.denied` (`reason: authn_context`). These policy denials are not charged to the address's failed-login budget. They apply to the halo-server console login only; gateways do not check them.
- **Reserved ids.** An IdP login whose user id starts with `service-account:` or `breakglass:` is refused, so audit attribution cannot be spoofed.
- `identity` joins the policy security paths: a policy with an invalid `groupsOverage` or `requireAcr`/`requireAmr` entry is refused at load, and halo-server keeps serving the last good one.

## Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Token leaked in a log, repo or ticket | Prefix for secret scanners; expiry (90 days by default); one-role scope; `halo service-token revoke` holds at once on every replica; `service-token.use` shows the address it was used from | Valid until noticed or expired. Not bound to a network or client certificate |
| Token store stolen (database dump, backup, data dir) | Only SHA-256 of 256-bit secrets is stored: not reversible, not guessable | The metadata (names, owners) is readable |
| Guessing a token | 2^256 secret; failed attempts rate limited per address across replicas | None practical |
| Timing side channel on lookup | The id is public and only finds the row; the secret is compared as whole-token hashes in constant time | Whether an id exists may leak; it grants nothing |
| Privilege escalation by minting | Admin-only routes; role ceiling; tokens and break-glass cannot mint; creation audited strictly | An admin can mint an admin token: by design, audited, revocable |
| Self-perpetuating automation | A token cannot create tokens; every token expires | A human must rotate before expiry |
| Automation indistinguishable from people | Distinct `service-account:` principal in every audit entry; reserved ids refused at IdP login | |
| Break-glass password guessed | Sealed (404) unless enabled; required allowed CIDRs (404 elsewhere, before the password is read); PBKDF2 at 600k iterations; per-address limit; global lockout after 20 failures in 15 minutes from allowed addresses, one shared lock, audited once at high severity, lifted by an SSO admin (`POST /api/v1/breakglass/unlock`); at most two concurrent attempts; high-severity audit of every failure | Someone inside the allowed range can trip the lockout; an SSO admin unlocks it, and a range of /8 to /15 (accepted, warned at startup) widens who can; broader is refused |
| Self-approval or double counting through a minted token or break-glass | Tokens act on behalf of their creator in every separation-of-duties check; request and rollout-approval decisions refuse non-human principals (audited 403) | |
| A case variant of a reserved id (`BreakGlass:x`) taken at IdP login | Reserved prefixes are checked on the canonical (lowercased) id | |
| Break-glass used quietly | Login refused unless the audit append succeeds; every request audited; SIEM severity high | An attacker with the SIEM pipeline as well is out of scope |
| Break-glass session outliving the incident | 30-minute fixed lifetime; disabling or rotating ends it; `revoke-sessions` on `breakglass:<user>` ends it | |
| Stolen session cookie | Idle timeout (1h) and absolute lifetime; logout and revocation as before. Agent credentials delegated from a session are bounded by its idle deadline, so a chain cannot refresh past it | A cookie in active use by the attacker keeps sliding until the absolute TTL |
| Entra overage silently removes roles | Denied with a clear error, or resolved from Graph; a Graph error denies | Graph needs admin-consented `GroupMember.Read.All` |
| Access token sent to the wrong host | Graph URL is server configuration (https only, http to loopback for tests), never policy or the token's `_claim_sources` | |
| Phishing-resistant MFA not enforced at the IdP | `requireAcr`/`requireAmr` check the signed ID token | The IdP decides what `amr: mfa` means; gateways do not check it |

## Consequences

- **Good.** Automation has a scoped, attributable, revocable, expiring credential; nobody needs to copy a cookie.
- **Good.** An IdP outage no longer locks admins out of the kill switch and the freeze, and using that way in is impossible to miss.
- **Good.** Idle sessions end; large Entra tenants either work or fail with an actionable message.
- **Bad.** Existing `HALO_SESSION` automation stops after an hour of browser inactivity until it moves to `HALO_TOKEN` (or the operator sets the idle timeout to 0).
- **Bad.** One more table and one more secret (the break-glass hash) to operate; a binary at schema 3 ignores the table and accepts no tokens during a mixed-version rollout.
- **Neutral.** The single-replica token log is never compacted; it holds at most one line per token change.

## Implementation status (2026-10-30)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Token format, hashing, constant-time check, expiry, revocation, role ceiling, limiter, attribution | `internal/server/servicetokens.go`, `auth.go` | `internal/server/admin_access_test.go` `TestServiceTokenFormat`, `TestServiceTokenLifecycle`, `TestServiceTokenCreateValidation`, `TestRoleCeiling`, `TestServiceTokenFailedAuthLimit` | Done |
| Storage: Postgres table, file log, replicas, import | `internal/pgstore/servicetokens.go`, `migrations/0004_service_tokens.sql`, `internal/server/import.go` | `internal/pgstore/servicetokens_test.go` `TestServiceTokensSQL`; `TestServiceTokensPersistAndReplicate`, `TestServiceTokensPostgres` | Done |
| CLI and MCP: `HALO_TOKEN`, `halo service-token` | `cmd/halo/credential.go`, `cmd_servicetoken.go`, `internal/mcpserver/tools_autopilot.go` | `TestServiceTokenCLI`, `TestHaloTokenTransport`, `TestFleetToolsServiceToken` | Done |
| Break-glass: sealed, PBKDF2, audit-or-refuse, fixed session, rotation ends sessions, SIEM severity | `internal/server/breakglass.go`, `audit_export.go`, `cmd/halo-server/main.go` | `TestBreakGlassHash`, `TestBreakGlass`, `TestBreakGlassHashCommand` | Done |
| Security review (2026-10-30): human-only decisions and OnBehalfOf; canonical reserved ids; idle-bounded delegation; break-glass CIDRs, global lockout and strict audit of changes; atomic token cap | `internal/server/rbac.go` (`requireHuman`), `auth.go`, `session.go` (`sessionDeadline`), `breakglass.go`, `servicetokens.go`, `internal/pgstore/servicetokens.go` | `internal/server/admin_access_review_test.go`; `TestServiceTokensSQL` | Done |
| Session TTL and sliding idle timeout, flags, Helm | `internal/server/session.go`, `cmd/halo-server/main.go`, `deploy/helm/halos` | `TestSessionPolicyNormalize`, `TestSessionIdleAndAbsoluteTimeout`, `TestSessionIdleOff`, `TestAdminAccessFlags` | Done |
| Entra overage (deny, Graph), acr/amr, reserved ids, policy validation | `internal/server/entra.go`, `auth.go`, `internal/policy/identity.go` | `TestEntraGroupsOverage`, `TestGraphScopesRequested`, `TestRequireAcrAmr`, `TestReservedSubjectRefused`, `TestIdentityPolicyValidation` | Done; real Entra and Okta tenants UNVERIFIED |
