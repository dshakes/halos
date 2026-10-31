---
title: halo-server API
description: Every halo-server HTTP endpoint with its auth requirement, derived from the route registrations in internal/server.
---

Routes are registered in `internal/server/server.go` (`Handler`). This page lists all of them. Errors are JSON `{"error": "..."}`; every response carries `X-Request-Id`, and `/api/` responses carry `Cache-Control: no-store`. Any other `/api/...` path is 404.

## Auth levels

| Level | Credential | Failure |
|---|---|---|
| **Public** | None. `POST /api/v1/enroll` takes a one-time enrollment token in the body | |
| **Session** | Signed-in developer: the session cookie from OIDC login (ends after `--session-idle-timeout` without a request and at `--session-ttl`), or a service-account token, `Authorization: Bearer halo_sat_...`, holding one role ([ADR-0036](/halos/adr/0036-admin-api-credentials-break-glass-and-session-policy/)) | 401 `login required`; a token: 401 `invalid service token` or `service token expired`, 429 after repeated failures, 503 if the store is unavailable |
| **Admin** | Session whose groups intersect `identity.adminGroups` in policy (recomputed from current policy on every request) | 403 `admin role required` |
| **Fleet or device token** | `Authorization: Bearer` with the shared fleet token (`--token-file`) or a per-device token | 401, or 429 after repeated failures |
| **Device token** | Per-device bearer token from enrollment | 401, or 429 |
| **Gateway token** | `Authorization: Bearer` with `--gateway-token-file`, or the endpoint's own `--gateway-{killswitch,posture,budget,directory}-token-file` token when set (then the only one accepted there) | 401, or 429 after repeated failures; 404 if the kill switch is not configured |
| **SCIM token** | `Authorization: Bearer` with a token whose SHA-256 is in `--scim-token-sha256-file`. A session cookie is never accepted | SCIM error 401, or 429 after repeated failures (a valid token is accepted even then); 404 when SCIM is off |

Failed-authentication budgets (the 429s) are per endpoint class and per client address, an IPv6 address counted by its /64: 10 failures, then one per 6 seconds. With the Postgres backend every failure is also counted in the database, so all replicas share one budget per address ([ADR-0021](/halos/adr/0021-ha-control-plane-on-postgres/)).

### Scoped grants

A role may be held over a scope of rings and units (`identity.roleBindings`, [ADR-0037](/halos/adr/0037-scoped-role-bindings/)). A global grant (`identity.roles`, `adminGroups`, an unscoped binding, a token without a scope, break-glass) behaves exactly as described on this page. With only scoped grants for the permission a route needs:

| Route kind | Routes | Behaviour |
|---|---|---|
| One resource | `GET /api/v1/devices/{id}`, `GET /api/v1/experiments/{name}`, `GET /api/v1/toggles/{name}`, `GET /api/v1/rollouts/{name}`, `GET /api/v1/rollouts/{name}/approvals`, `POST /api/v1/experiments/{name}/{status,kill,unkill}`, `POST /api/v1/toggles/{name}/{kill,unkill}`, `POST /api/v1/requests/{id}/{approve,deny}`, `POST /api/v1/rollouts/{name}/approve`, `POST /api/v1/devices/{id}/revoke`, `POST /api/v1/service-tokens/{id}/revoke` | Allowed when a grant's scope covers the resource. 403 otherwise, and 403 (not 404) for a resource that does not exist, so names outside the scope cannot be probed |
| Lists | `GET /api/v1/fleet`, `/devices`, `/releases`, `/experiments`, `/rollouts`, `/toggles`, `/killswitch`, `/freeze`, `/requests`, `/service-tokens` | Only in-scope items; `total`, per-ring stats and counts are computed from them. Fleet reports sent with the shared fleet token have no owner the server can place and are shown to global readers only |
| Global only | `GET /api/v1/policy`, `/budgets`, `/cloud-agents`, `/audit`, `/sessions`, `/sessions/{id}`, `/revocations`; `POST /api/v1/cloud-agents/kill`, `/users/{id}/revoke-sessions`, `/toggles/{name}/propose`, `/sessions`, `/freeze`, `/revocations`, `/breakglass/unlock`; `GET /api/v1/whoami` for another user | 403 `... with a global role binding` |

Every scoped 403 is audited as `authz.deny` with `scope` (`global`, `unknown` or `out of scope`), `resource` and the caller's `bindings`. An action a scoped grant authorized carries `authzRole`, `authzScope` and `authzBinding` in its audit entry. `GET /api/v1/me` and `GET /api/v1/capabilities` return `bindings`: `[{"role", "scope": {"rings", "units"}, "source"}]`.

State-changing Session and Admin requests (anything but `GET`) are rejected with 403 when an `Origin` header does not match the host. `--dev-insecure-user` replaces the session check with a fixed user; demos only.

## Endpoints

### Health and login

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | Public | Liveness: `ok` |
| `GET /auth/login` | Public | Start the OIDC authorization-code flow (PKCE) |
| `GET /auth/callback` | Public | OIDC redirect target; sets the session cookie |
| `POST /auth/logout` | Public | End the session |
| `POST /auth/breakglass` | Public (password in the body) | Break-glass local admin login `{"user","password"}`: a 30-minute admin session for `breakglass:<user>`. 404 unless `--breakglass-enabled`, or from a client outside `--breakglass-allowed-cidrs` (required when enabled); 401 bad credentials; 429 after repeated failures, during the 15-minute global lockout (20 failures from allowed addresses on any replica; audited once as `breakglass.lockout`; lifted by `POST /api/v1/breakglass/unlock`) or while two attempts are running; 500 if the audit append fails (no session). Audited at high severity: `breakglass.login`, `breakglass.login.failed`, and `breakglass.request` for every request the session makes |

### Fleet and devices

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /api/v1/fleet/report` | Fleet or device token | `halod` status report (max 64 KB). Reports carry `experiment` and `variant` (client-axis variant applied; empty otherwise) and `errorCode` (for example `no_subject_for_experiment`). With a device token, user and device come from the binding, not the payload |
| `GET /api/v1/fleet/ring` | Device token | Ring this device should follow, resolved live from policy: `{"ring": "ring1-ga", "subject": "dev1@acme.com"}`. `subject` is the device's bound user id, the id the gateway hashes, which `halod` uses to pick its client-axis experiment variant |
| `GET /api/v1/fleet` | Admin | Hosts, per-ring stats and drift counts |
| `GET /api/v1/devices` | Admin | Enrolled devices |
| `GET /api/v1/devices/{id}` | Admin | One device: binding, last report, and up to 50 recent reports (newest first; history resets on server restart). Token hashes are never returned |
| `POST /api/v1/devices/{id}/revoke` | Admin | Revoke a device token. Audited |
| `POST /api/v1/users/{id}/revoke-sessions` | Admin | Invalidate a user's console sessions everywhere. Audited |
| `POST /api/v1/revocations` | Admin | Revoke a halo-server credential ([ADR-0026](/halos/adr/0026-per-credential-revocation/)). Body: exactly one of `jti` (1-128 of `A-Z a-z 0-9 - _`; kills the credential and every credential exchanged from it) and `subject` (`agent:<name>`, `workload:<subject>` or a human id; kills every credential issued at or before the revocation, anywhere in a chain; a human id also revokes their sessions), plus `reason` (required, at most 1000 characters). Returns the revocation with `revokedBefore` (subjects) and `expires`. 400 for an invalid body, 409 at 10,000 active revocations for a new key, 503 if the store is unavailable (nothing revoked), 500 if the audit append fails (the revocation holds). Audited as `credential.revoke`. `halo agents revoke` |
| `GET /api/v1/revocations` | Admin | Active revocations with who, why and when. `halo agents revocations` |
| `POST /api/v1/service-tokens` | Admin, interactive session only | Create a service-account token `{"name","role","scope","ttl","description","owner"}`: 201 with `token` (shown once) and `serviceToken`. The role may not exceed the caller's; `scope` (`{"rings": [...], "units": [...]}`, absent = global, [ADR-0037](/halos/adr/0037-scoped-role-bindings/)) must be within one of the caller's admin grants, and each of the role's permissions must be the caller's over it (403 otherwise). `scope` is decoded strictly: an unknown key, ring or unit is a 400; `ttl` 1h to `--service-token-max-ttl` (default and maximum, 90 days). 403 for a token or break-glass caller, 409 at 1,000 active tokens, 500 if the audit append fails (the token is revoked and not returned). Audited as `service-token.create`. `halo service-token create` |
| `GET /api/v1/service-tokens` | Admin | Every token's id, principal, name, role, scope, owner, creator, expiry and revocation; never the secret. A scoped admin sees the tokens whose scope is within their admin grants. `halo service-token list` |
| `POST /api/v1/service-tokens/{id}/revoke` | Admin | Revoke `{"reason"}`; holds on every replica at the token's next request. Audited as `service-token.revoke`. `halo service-token revoke` |
| `POST /api/v1/breakglass/unlock` | Admin, interactive session only | Lift the break-glass global lockout on every replica and reset its failure count; `{"wasLocked"}`. 403 for a token or break-glass caller, 404 when break-glass is not configured, 500 if the audit append fails (nothing changed). Audited as `breakglass.unlock` at high severity |

### Releases and audit

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /api/v1/releases` | Admin | Per ring: the signature-verified pointer read from the registry (digest, `seq`, issued and expiry times, `expired`, `expiringSoon` under 48 hours), convergence of reporting devices on that digest, and drift. Cached 30 seconds; if the registry is unreachable the last verified state is returned flagged `stale`. Needs `registry` and `pubKeyFile` in the portal config |
| `GET /api/v1/audit` | Admin | Hash-chained audit log. Query: `limit` (1 to 500, default 100), `since` (sequence number or RFC3339 time; returns entries after it, oldest first, else the newest `limit`), exact-match `actor` and `action`. Response: `entries`, `next` (pass as `since` to page), `total`, `verified` (the whole chain, across rotated segments), `verifyError`, `head`. Reads stream, so memory is bounded by `limit` whatever the log size |
| `GET /api/v1/sessions` | Audit role | Agent session ledger ([ADR-0031](/halos/adr/0031-agent-session-ledger/)): the newest stored version of each session, newest start first. Query: `user` (Halos identity, or the vendor identity of an unresolved session), `harness`, `ring`, `tool` (a tool or MCP server), `since`/`until` (RFC3339, on the session start), `limit` (1 to 5000, default 100). Response: `sessions` (each record with `auditSeq` and `auditHash`, the audit entry holding it), `total`, `verified`, `verifyError`, `head` |
| `GET /api/v1/sessions/{id}` | Audit role | One session by ledger id or harness session id; 404 when unknown |
| `POST /api/v1/sessions` | Admin | Store normalized session records (`halo sessions import`): `{"records": [...]}`, up to 1000. Every record is validated first and one invalid record (prose in any field, an unhashed path, a forged id, an unknown field) refuses the whole batch with 400. `who.user` is set from the SCIM directory, never from the body. Each record is appended to the audit log as action `session.record`. Answers the stored records |
| `GET /api/v1/cloud-agents` | Read | Cloud agent tasks ([ADR-0034](/halos/adr/0034-cloud-agent-governance/)) updated in the last 7 days, each attributed to a Halos user from `cloudAgents.identities`, with policy alerts (`disabled`, `ungoverned`, `unmanaged`, `repo`, `model`, `unattributed`, `concurrency`, `budget`) and `configured` (webhook, GitHub and Cursor clients). `?active=true` keeps queued and running tasks |
| `POST /api/v1/cloud-agents/kill` | Operate | `{"scope": "user\|ring\|experiment", "name", "reason", "dryRun"}`: cancel the active cloud tasks of a user, or of every user a ring or experiment resolves. Reason required; `dryRun` defaults to `true` (plan only). A real run is audited (`cloudagent.kill`) before any vendor call and each result after; answers `actions` (task, vendor call, manual step, result), `unattributed` and `next_steps` |
| `POST /api/v1/cloud-agents/webhooks/github` | `X-Hub-Signature-256` HMAC | GitHub `workflow_run` deliveries (404 without `--cloud-webhook-secret-file`; body at most 1 MiB). Governed runs are stored as `cloudagent.task`, finished ones also as `session.record`; an older delivery than the stored task answers 202 `stale`. Alerts are audited (`cloudagent.alert`); with `onOverLimit: pause` the tasks are paused (`cloudagent.pause`) |

### Policy, experiments and the kill switch

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /api/v1/policy` | Admin | The loaded policy |
| `GET /api/v1/experiments` | Admin | Experiments with status and latest verdict |
| `GET /api/v1/experiments/{name}` | Admin | One experiment |
| `POST /api/v1/experiments/{name}/status` | Admin | Body `{"status": "running\|paused\|concluded"}`. **Opens a policy-repo PR**; nothing changes until a human merges. Returns `{"prURL"}`. 409 if already in that status, 501 if no policy writer is configured. Audited as `experiment.status` |
| `POST /api/v1/experiments/{name}/kill` | Admin | Kill switch on. Body `{"reason": "..."}` (required, at most 500 characters; 422 otherwise). 404 for a name not in policy. 501 when the server has no kill-list signing key (nothing would be enforced). Audited as `experiment.kill` |
| `POST /api/v1/experiments/{name}/unkill` | Admin | Kill switch off. Also works for names no longer in policy, so stale kills can be cleared. Optional `{"reason"}`. 501 without a signing key. Audited as `experiment.unkill` |
| `GET /api/v1/toggles` | Admin | Every toggle with owner, expiry and `stale`, axis, default, ordered rules, a payload summary (names only) and the live kill state (`by`, `reason`, `at`). `killEnabled` says whether the server can kill |
| `GET /api/v1/toggles/{name}` | Admin | One toggle plus its kill and proposal history from the audit log. With `?user=U[&ring=R][&groups=a,b]` it adds `preview`: on or off, why, and the rule trace (the ring is resolved from the user when omitted; 422 for an unknown ring) |
| `POST /api/v1/toggles/{name}/propose` | Admin | Open a policy PR editing the toggle. Body: `reason` (required) plus any of `default`, `expires`, and `rule` (name or index) with `percent`, `addRings`/`removeRings`, `addGroups`/`removeGroups`, `addUsers`/`removeUsers`. Validated against the guardrails first: 422 for an invalid or no-op change, nothing opened. 501 with no policy writer. Audited as `toggle.propose` |
| `POST /api/v1/toggles/{name}/kill` | Admin | Kill a feature toggle (fleet-wide off). Body `{"reason": "..."}` (required; 422 otherwise). Same signed kill list as experiments. Audited as `toggle.kill` |
| `POST /api/v1/toggles/{name}/unkill` | Admin | Kill switch off for the toggle. Optional `{"reason"}`. Audited as `toggle.unkill` |
| `GET /api/v1/rollouts` | Admin | Rollouts from policy, with saved controller state when the server runs with `--controller` and a data dir |
| `GET /api/v1/rollouts/{name}` | Admin | One rollout, same shape |
| `GET /api/v1/killswitch` | Admin | Active kills with who, when and why, and the list `version` |
| `GET /api/v1/gateway/killswitch` | Gateway token | The signed kill list for `halo-proxy` and `halo-kong` |
| `GET /api/v1/gateway/directory` | Gateway token | SCIM directory entry for `?subject=<id>`: `{"active": true, "groups": [...]}` for an active provisioned user, `{"active": false}` otherwise. 404 without SCIM or a gateway token ([SCIM provisioning](/halos/guides/scim-provisioning/)). With `?revocations=1` instead: the credential revocation list, `{"jtis": {jti: expiry}, "subjects": {subject: epoch}}` (unix seconds), which gateways fetch every 30 seconds (served without SCIM too; 404 only without a gateway token); 503 if the store is unavailable |
| `GET /api/v1/gateway/posture` | Gateway token | Device-posture verdict for `?subject=<id>` (at most 256 characters), read by `halo-proxy` posture gates. 404 when no gateway token is configured |
| `POST /api/v1/gateway/budget/check` | Gateway token | Budget verdict for `{"subject","groups","ring"}`: every counter the caller is charged to, with spend, limits, action, `alertAt` and `resetAt` ([cost budgets](/halos/guides/cost-budgets/)). 404 when no gateway token is configured |
| `POST /api/v1/gateway/budget/usage` | Gateway token | A proxy replica's usage: `{"batch","records":[{"subject","groups","ring","usd","tokens","at"}]}`, at most 5000 records and 8 MiB. A batch id seen in the last hour returns `"duplicate": true` and is not counted again |
| `POST /api/v1/gateway/dlp/events` | Gateway token | DLP findings from a gateway: `{"batch","events":[{"at","gateway","subject","ring","unit","protocol","harness","direction","action","kind","detector","hash","location","score","signals"}]}`, at most 500 events and 1 MiB. Each event is appended to the audit log as `dlp.secret` or `dlp.injection` (actor `gateway:<name>`). `hash` must be 8 hex characters; never a secret. A batch id seen in the last hour returns `"duplicate": true`; 503 when the audit log cannot be written (the gateway resends) ([data-loss prevention](/halos/guides/dlp/)) |
| `GET /api/v1/budgets` | Admin | Every budget counter with spend in its current window, plus org and group counters at zero. Exact-match filters `?budget=` and `?key=` (for example `user:alice@acme.com`). `halo budget status` reads it |
| `GET /api/v1/fleet/killswitch` | Device token | The same signed list for `halod` (client-axis devices; configured via `killSwitch` in `halod.yaml`; portal enrollment sets it when the server has a kill key). 404 when the server has no kill key |
| `GET /api/v1/capabilities` | Session | Optional features this server is configured for. `killSwitch` is true only when a kill-list signing key (`--killswitch-key-file`) is set and the kill route is registered, so the console never probes with a real POST |

### Developer self-service

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /api/v1/me`, `/catalog`, `/harnesses` | Session | Identity and ring, requestable catalog, harness matrix |
| `GET /api/v1/whoami` | Session | Ring and variants for a user. Developers: self only; admins: any user |
| `POST /api/v1/launch/{launcher}` | Session | Launcher output (`devcontainer`, `codespaces`, `coder`, `laptop`) |
| `POST /api/v1/requests`, `GET /api/v1/requests` | Session | Submit and list access requests (submitting needs a person: a service token or break-glass gets 403). Rollout step approvals (`POST /api/v1/rollouts/{name}/approve`) are person-only too |
| `POST /api/v1/requests/{id}/approve`, `/deny` | Admin | Decide a request (a person only: a service token or break-glass gets 403, audited as `authz.deny` with `need: human`); approval opens a PR. 500 if the decision cannot be stored (the request stays pending; the message names a PR already opened) or audited (the decision stands) |

### Enrollment (public)

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /enroll/killswitch.pub` | Public | The kill-list verification public key (PEM) that the enroll scripts install. 404 when the kill switch is not configured |
| `GET /enroll.sh`, `GET /enroll.ps1` | Public | Enrollment scripts. They pin the `halod` checksum from server config |
| `GET /enroll/release.pub` | Public | Release public key |
| `POST /api/v1/enroll` | Public (enrollment token in the body) | Exchange a single-use token for a device token and `halod.yaml`. A bad, expired or used token is 401 |

### SCIM 2.0 provisioning

RFC 7644 endpoints for the IdP, all with the **SCIM token**. Bodies and errors are `application/scim+json`; errors use the `urn:ietf:params:scim:api:messages:2.0:Error` schema with `scimType`. Setup and semantics: [SCIM provisioning](/halos/guides/scim-provisioning/), [ADR-0022](/halos/adr/0022-scim-provisioning/).

| Method and path | Purpose |
|---|---|
| `GET /scim/v2/ServiceProviderConfig`, `/ResourceTypes[/{id}]`, `/Schemas[/{id}]` | Discovery |
| `GET /scim/v2/Users`, `GET /scim/v2/Groups` | List. `filter` (`userName`, `externalId`, `id` on users; `displayName`, `externalId`, `id` on groups; `eq` only), `startIndex`, `count` (max 1000), `excludedAttributes=members` |
| `POST /scim/v2/Users`, `POST /scim/v2/Groups` | Create (409 `uniqueness` for a taken `userName` or `displayName`) |
| `GET`, `PUT`, `PATCH`, `DELETE /scim/v2/Users/{id}` and `/scim/v2/Groups/{id}` | Read, replace, patch, delete. `If-Match` is honoured (412). Deactivating, deleting or renaming a user revokes their sessions, devices and pending enrollments |

The console itself is served from `/` (any path that is not `/api/` or `/scim/v2/`).

## Kill switch

### Gateway endpoint

`GET /api/v1/gateway/killswitch` with `Authorization: Bearer <gateway token>` returns:

```json
{
  "payload":   "<base64 of the JSON below>",
  "signature": "<base64 ed25519 signature>"
}
```

```json
{"version": 7, "experiments": ["opus-5-5-canary"], "issuedAt": "2026-09-30T17:21:04.512Z"}
```

The signature is ed25519 over the bytes `halo-killswitch-v1\n` followed by the raw payload. `version` grows with every kill or unkill (informational); `issuedAt` is the server clock at response time. Gateways accept a list only if the signature verifies, `issuedAt` is at most 10 minutes old and at most 1 minute in the future, and `issuedAt` is strictly newer than the list they hold. The endpoint is enabled only when both `--killswitch-key-file` and `--gateway-token-file` are set.

### Admin actions

```bash
# as a signed-in admin (session cookie) or through the console's Kill switch button
curl -X POST https://halo.acme.example/api/v1/experiments/opus-5-5-canary/kill \
  -b cookies.txt -H 'content-type: application/json' -d '{"reason":"p95 latency regression"}'
# -> {"experiment":"opus-5-5-canary","killed":true,"changed":true}
```

`changed` is `false` when the experiment was already in that state. A kill takes effect on gateways at their next poll (default 10 seconds), does not expire, and is not lifted by pausing or concluding the experiment in policy. Concepts and failure policy: [experiments](/halos/concepts/experiments/#kill-switch). Design: [ADR-0009](/halos/adr/0009-signed-kill-switch/).

### Audit actions

`login`, `logout`, `request.create`, `request.approve`, `request.deny`, `device.enroll`, `device.revoke`, `session.revoke`, `credential.revoke`, `experiment.status`, `experiment.kill`, `experiment.unkill`, `toggle.propose`, `toggle.kill`, `toggle.unkill`. The controller's kills are recorded with actor `halo-controller`. SCIM mutations are recorded with actor `scim`: `scim.user.create`, `scim.user.replace`, `scim.user.patch`, `scim.user.delete`, `scim.group.create`, `scim.group.replace`, `scim.group.patch`, `scim.group.delete`.
