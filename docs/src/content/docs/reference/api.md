---
title: halo-server API
description: Every halo-server HTTP endpoint with its auth requirement, derived from the route registrations in internal/server.
---

Routes are registered in `internal/server/server.go` (`Handler`). This page lists all of them. Errors are JSON `{"error": "..."}`; every response carries `X-Request-Id`, and `/api/` responses carry `Cache-Control: no-store`. Any other `/api/...` path is 404.

## Auth levels

| Level | Credential | Failure |
|---|---|---|
| **Public** | None. `POST /api/v1/enroll` takes a one-time enrollment token in the body | |
| **Session** | Signed-in developer: the session cookie from OIDC login | 401 `login required` |
| **Admin** | Session whose groups intersect `identity.adminGroups` in policy (recomputed from current policy on every request) | 403 `admin role required` |
| **Fleet or device token** | `Authorization: Bearer` with the shared fleet token (`--token-file`) or a per-device token | 401, or 429 after repeated failures |
| **Device token** | Per-device bearer token from enrollment | 401, or 429 |
| **Gateway token** | `Authorization: Bearer` with `--gateway-token-file` | 401, or 429 after repeated failures; 404 if the kill switch is not configured |

State-changing Session and Admin requests (anything but `GET`) are rejected with 403 when an `Origin` header does not match the host. `--dev-insecure-user` replaces the session check with a fixed user; demos only.

## Endpoints

### Health and login

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | Public | Liveness: `ok` |
| `GET /auth/login` | Public | Start the OIDC authorization-code flow (PKCE) |
| `GET /auth/callback` | Public | OIDC redirect target; sets the session cookie |
| `POST /auth/logout` | Public | End the session |

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

### Releases and audit

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /api/v1/releases` | Admin | Per ring: the signature-verified pointer read from the registry (digest, `seq`, issued and expiry times, `expired`, `expiringSoon` under 48 hours), convergence of reporting devices on that digest, and drift. Cached 30 seconds; if the registry is unreachable the last verified state is returned flagged `stale`. Needs `registry` and `pubKeyFile` in the portal config |
| `GET /api/v1/audit` | Admin | Hash-chained audit log. Query: `limit` (1 to 500, default 100), `since` (sequence number or RFC3339 time; returns entries after it, oldest first, else the newest `limit`), exact-match `actor` and `action`. Response: `entries`, `next` (pass as `since` to page), `total`, `verified`, `verifyError`, `head` |

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
| `GET /api/v1/gateway/posture` | Gateway token | Device-posture verdict for `?subject=<id>` (at most 256 characters), read by `halo-proxy` posture gates. 404 when no gateway token is configured |
| `GET /api/v1/fleet/killswitch` | Device token | The same signed list for `halod` (client-axis devices; configured via `killSwitch` in `halod.yaml`; portal enrollment sets it when the server has a kill key). 404 when the server has no kill key |
| `GET /api/v1/capabilities` | Session | Optional features this server is configured for. `killSwitch` is true only when a kill-list signing key (`--killswitch-key-file`) is set and the kill route is registered, so the console never probes with a real POST |

### Developer self-service

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /api/v1/me`, `/catalog`, `/harnesses` | Session | Identity and ring, requestable catalog, harness matrix |
| `GET /api/v1/whoami` | Session | Ring and variants for a user. Developers: self only; admins: any user |
| `POST /api/v1/launch/{launcher}` | Session | Launcher output (`devcontainer`, `codespaces`, `coder`, `laptop`) |
| `POST /api/v1/requests`, `GET /api/v1/requests` | Session | Submit and list access requests |
| `POST /api/v1/requests/{id}/approve`, `/deny` | Admin | Decide a request; approval opens a PR |

### Enrollment (public)

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /enroll/killswitch.pub` | Public | The kill-list verification public key (PEM) that the enroll scripts install. 404 when the kill switch is not configured |
| `GET /enroll.sh`, `GET /enroll.ps1` | Public | Enrollment scripts. They pin the `halod` checksum from server config |
| `GET /enroll/release.pub` | Public | Release public key |
| `POST /api/v1/enroll` | Public (enrollment token in the body) | Exchange a single-use token for a device token and `halod.yaml`. A bad, expired or used token is 401 |

The console itself is served from `/` (any path that is not `/api/`).

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

`login`, `logout`, `request.create`, `request.approve`, `request.deny`, `device.enroll`, `device.revoke`, `session.revoke`, `experiment.status`, `experiment.kill`, `experiment.unkill`, `toggle.propose`, `toggle.kill`, `toggle.unkill`. The controller's kills are recorded with actor `halo-controller`.
