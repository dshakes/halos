---
title: "ADR-0022: SCIM 2.0 provisioning"
description: halo-server is a SCIM 2.0 service provider, so deprovisioning a user in the IdP revokes their sessions and devices at once, and the SCIM directory can be the authoritative source of group membership for rings, cohorts and roles.
status: accepted
date: 2026-10-21
---

# ADR-0022: SCIM 2.0 provisioning

- Status: accepted (extends ADR-0011)
- Date: 2026-10-21

> **Amended 2026-10-21 (third security review).** Fail open is for an outage only. A gateway fails open on a transport error or a 5xx; any other non-200 answer refuses the caller as not provisioned, and a cached inactive entry stays refused however old it is while `halo-server` is down. `halo-server` answers a subject over 256 characters as inactive (200) instead of 400, which a gateway had read as an outage (tests: `TestDirectoryClientNeverFailsOpenOnInactiveOrRefusal`, `TestGatewayDirectoryEndpoint`). Gateway tokens must have 32 characters and 128 bits of estimated entropy (ADR-0009).

> **Amended 2026-10-22 (final security review).** A full gateway directory cache (100k subjects) cleared every entry, forgetting inactive answers, so fail open re-admitted a deactivated user during a later outage. A full cache now evicts active entries only (those past Grace first); an inactive answer is never forgotten to make room, and when every entry is inactive a new answer is not cached (test: `TestDirectoryCacheEvictionKeepsInactive`).

## Context and problem statement

Halos learns who a user is from OIDC: the console reads the `groups` claim at login, enrolled devices keep the groups they had at enrollment, and the gateways read groups from the caller's JWT or a trusted header. Nothing tells Halos that a user left. A console session lives until it expires (12h), a device token until its TTL (90d), and a removed group only disappears at the next login. Enterprises expect the IdP's deprovisioning to take effect immediately, and expect group membership to be managed in one place.

## Decision drivers

- Deprovisioning in the IdP must end the user's access to halo-server immediately, without an admin running `revoke-sessions` and `devices/{id}/revoke` by hand.
- Okta and Microsoft Entra ID must work as they ship, including their quirks.
- Invariant 4 holds: cohort comes only from the authenticated identity, never from a client header.
- The provisioning credential is separate from every human and gateway credential and is never stored in plaintext.
- Persistence follows the server's existing pattern and sits behind an interface the HA backend can implement.

## Considered options

1. **Shorter session and device lifetimes.** Cheap, but a 15-minute session still leaves a window, short device tokens make laptops re-enroll constantly, and group changes still wait for a login.
2. **Poll the IdP's admin API.** Each IdP has a different API and credential model, and the polling interval is the deprovisioning delay.
3. **SCIM 2.0 service provider (chosen).** Okta and Entra ID push users and groups to a standard endpoint as soon as they change.

## Decision outcome

Chosen: **option 3**. `halo-server` serves RFC 7643/7644 at `/scim/v2`.

**Surface.** `Users` and `Groups` (GET, POST, PUT, PATCH, DELETE), `ServiceProviderConfig`, `ResourceTypes`, `Schemas`. Filters: `userName eq`, `externalId eq`, `id eq` on users and `displayName eq`, `externalId eq`, `id eq` on groups; any other filter is `400 invalidFilter`. Pagination uses `startIndex` (1-based) and `count` (default 100, max 1000). PATCH supports `add`, `replace` and `remove`, path-less object values, `members[value eq "..."]` and `emails[type eq "..."].value`. Weak ETags are returned in `meta.version` and honoured in `If-Match`. Bulk, sorting, `/Me` and password changes are not supported and are advertised as such.

**IdP quirks handled.** Entra ID capitalises op names (`"Replace"`), sends booleans as strings (`"value": "False"`), qualifies paths with schema URNs, and removes members with a value list. Okta updates users with PUT, changes membership with PATCH, and sends path-less `replace` operations that echo the group id. Attributes Halos does not keep (title, the enterprise extension, passwords) are accepted, not stored, and listed in the audit entry's `ignoredAttributes`.

**Identity.** A SCIM user's `userName` is the Halos identity: it must equal the OIDC `userClaim` value (email by default) and is matched case-insensitively. A group's `displayName` is what policy refers to (ring membership, `adminGroups`, toggle rules). Group members must be provisioned users; nested groups are refused.

**Authentication.** A dedicated bearer token. halo-server is configured with the hex SHA-256 of each accepted token (`--scim-token-sha256-file`, one per line), compares in constant time against every configured hash, and shares the per-IP failed-auth budget with device and gateway tokens. Two lines allow a rotation without downtime: add the new hash, switch the IdP, remove the old hash. Session cookies are never read on `/scim/v2`, so an admin session cannot provision.

**Deprovisioning.** Deactivating a user (`active: false` by PATCH or PUT), deleting them, or renaming their `userName` (the old identity) immediately: bumps the user's session epoch so every console session dies, revokes every device token bound to the user, and drops their unconsumed enrollment tokens. These effects run before the directory change is persisted, so a failure leaves the old state for the IdP to retry. A deactivated user who still holds a valid IdP login is refused at the console and on device endpoints whether or not the directory is authoritative.

**Authoritative mode.** `--scim-authoritative` makes the directory the source of truth on halo-server: users the directory does not list as active are refused at login, on every console request and on device-token endpoints, and their groups (for admin rights, ring resolution and toggle targeting) are the directory's, not the session's or the enrollment's. Group changes apply to live sessions on the next request.

**Gateways.** `halo-server` serves `GET /api/v1/gateway/directory?subject=<id>` behind the existing gateway token. `halo-proxy` (`directory.url`, `directory.tokenFile`) and `halo-kong` (`directory_url`, `directory_token`) look up the verified subject after identity verification: an active user's groups are replaced by the directory's, and anyone else is treated as an unknown caller (ring unknown, default routing, no experiments). Entries are cached per subject (`cacheTTL`, default 1m). An unreachable halo-server is tolerated for `grace` (default 5m), after which callers are unknown. Groups never come from a client header; the subject id still comes only from the verified token or trusted header.

**Audit.** Every mutation appends to the hash-chained audit log with actor `scim` (`scim.user.create|replace|patch|delete`, `scim.group.create|replace|patch|delete`), including membership deltas and whether sessions and devices were revoked. A failed audit append answers 500.

**Persistence.** `SCIMStore` is a small interface (users, groups, lookups, puts, deletes). The default implementation is an append-only JSONL log in `--data-dir` (`scim.jsonl`), replayed on start like the device and revocation logs. SCIM requires `--data-dir` or the Postgres backend. On Postgres ([ADR-0021](/halos/adr/0021-ha-control-plane-on-postgres/)) the same store runs over the shared `scim` log: every read (and every `Lookup` behind sessions, devices and the gateway directory) first applies the other replicas' writes, and fails closed (user treated as inactive) if the log cannot be read; mutations are serialised across replicas by a cluster lock, so the `userName` and `displayName` uniqueness checks hold; deprovisioning revokes sessions (case-insensitive epoch), devices and pending enrollment tokens in shared state, so it holds on every replica at once.

### Consequences

- Good: deprovisioning in the IdP ends console sessions, device tokens and pending enrollments in one request, and is audited.
- Good: with authoritative mode, group membership is managed in one place and applies to rings, cohorts and admin rights without a re-login.
- Good: invariant 4 holds; the directory is keyed by the verified subject.
- Bad: the gateway cache means a deprovisioned user can keep their cohort at a gateway for up to `cacheTTL` (or `grace` during a halo-server outage). Gateway access itself is decided by the IdP token, which deprovisioning does not revoke; that remains the IdP's job.
- Bad: `userName` must match the OIDC user claim exactly in meaning. A mismatch (for example UPN versus mail in Entra ID) leaves users unknown in authoritative mode. The guide shows the attribute mapping.
- Neutral: groups are capped at 20,000 members (one JSONL line must stay under the replay limit), and the log is not compacted. Both are revisited with the HA backend.
- Neutral: the gateway directory is authoritative whenever it is configured at the gateway, independent of `--scim-authoritative` on halo-server.

## Amended 2026-10-21 (security review)

- **Case.** Session revocations are keyed by the lowercased user id (live, and on replay of older mixed-case log lines), matching devices, enrollments and directory lookups. An IdP that provisions `Alice@Corp.com` now ends the session of `alice@corp.com`; before, it revoked a different key and the cookie survived.
- **Gateways refuse, not demote.** A verified caller the directory does not list as active gets 403 in the caller's protocol (`gateway.RejectNotProvisioned`) instead of becoming an unknown caller, which skipped the posture gate and per-user budgets. "Unknown" is kept only for callers with no credential and for an unreachable halo-server past `grace`.
- **Workloads.** Workload credentials (ADR-0023) are not in SCIM: the gateways skip the lookup for `Kind == workload` and keep the kind. A `userName` starting with `workload:` (any case) is refused, so no SCIM entry can stand for a workload.
- **Scale.** The store indexes memberships by user, so `Lookup`, user deletion and PATCH member deltas are linear; benchmarked at 20,000 users and 30,000 memberships.
- **Credentials.** `/api/v1/gateway/directory` accepts `--gateway-directory-token-file` alone when set (see the operations guide); the shared gateway token remains the fallback.

## Amended 2026-10-21 (second security review)

- **An outage never demotes to anonymous.** Past `grace` with the directory unreachable (or with an invalid directory config at `halo-kong`), the gateways no longer make a verified caller unknown, which passed the posture gate as "unknown" and skipped per-user budgets. `directory.failMode` (`directory_fail_mode` on `halo-kong`): `open` (default) keeps the verified subject with no groups (default routing, no experiments, posture and budgets still applied); `closed` answers 503 in the caller's protocol (`gateway.RejectDirectoryUnavailable`). Tests: `TestDirectoryClientResolve`, `TestDirectoryOutageKeepsIdentity`, `TestAccessDirectoryIsAuthoritative`.
- **The outage cannot be provoked through public endpoints.** halo-server's failed-auth limiter was one bucket per IP shared by token exchange, SCIM, gateway tokens and devices, so garbage sent to `/api/v1/token/exchange` from a gateway's egress IP locked the gateway out of the directory. Each endpoint class now has its own bucket, and a valid gateway token is accepted even from a blocked IP. Tests: `TestAuthLockoutIsPerEndpointClass`, `TestGatewayKillswitchRateLimited`.
- **One canonical user id.** `canonicalUser` (lowercase, trim) is the only comparison and key for user ids in halo-server: sessions, devices, enrollments, posture, SCIM `userName`, access-request self-approval (which compared exactly, so a case variant could approve its own request) and the whoami self check. Not `strings.EqualFold`: map keys need one canonical string, and EqualFold's Unicode folding differs from ToLower. Test: `TestUserIDsCompareCanonically`.
