---
title: Self-service portal
description: The developer kiosk and operator console in halo-server. Launchers, laptop enrollment, device tokens, access requests and experiment actions that become pull requests, releases, device and audit views.
---

`halo-server` serves a developer portal ("kiosk") next to the operator API. Developers sign in with the org's OIDC provider, see which ring and profile they are on, get a launcher for the environment they want, and ask for access. Nothing they do changes production directly: enrollment issues a scoped device credential, and access requests end as **pull requests a human merges**.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/enrollment-light.svg" alt="A developer logs in to the halo-server portal through OIDC, requests a laptop launch and gets a one-time token, enrolls the laptop to receive halod.yaml with a device token, and halod then resolves its ring live. Access requests are approved by an admin and become a policy PR, never a merge." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/enrollment-dark.svg" alt="A developer logs in to the halo-server portal through OIDC, requests a laptop launch and gets a one-time token, enrolls the laptop to receive halod.yaml with a device token, and halod then resolves its ring live. Access requests are approved by an admin and become a policy PR, never a merge." width="760" />

## Turn it on

Two pieces of configuration. The policy side lives in the root file `halos.yaml` (see [policy model](/halos/concepts/policy-model/#root-halosyaml)); the server side is a JSON file passed as `--portal-config`.

```yaml
# halos.yaml (excerpt)
identity: {issuer: https://acme.okta.com/oauth2/default, clientID: halos-portal, adminGroups: [ai-platform]}
selfService:
  enabled: true
  launchers: [devcontainer, codespaces, laptop]
  requestable: [mcp-server, ring-opt-in]
  catalog: [{name: linear, url: https://mcp.linear.app/sse}]
  enrollmentTTLSeconds: 900
```

```json
{
  "baseURL": "https://halo.acme.example",
  "registry": "ghcr.io/acme/halos",
  "pubKeyFile": "/etc/halos/release.pub",
  "devcontainerFeature": "ghcr.io/acme/features/halos:1",
  "codespacesURL": "https://github.com/codespaces/new?ring={ring}",
  "halodURL": "https://dl.acme.example/halod-{os}-{arch}",
  "halodSHA256": {"linux-amd64": "<64 hex>", "linux-arm64": "<64 hex>", "darwin-arm64": "<64 hex>"},
  "policyRepoDir": "/policy-writer/current",
  "policyBase": "main",
  "sessionKeyFile": "/run/secrets/session-key",
  "oidcClientSecretFile": "/run/secrets/oidc-client-secret"
}
```

Other fields: `devcontainerImage`, `coderURL`, `policySubdir`. Unknown fields are rejected. `baseURL` and `halodURL` must be shell-safe because they are baked into generated scripts. `halodSHA256` keys are `<os>-<arch>` and values 64 lowercase hex digits.

```bash
halo-server -policy-dir policy-repo -token-file fleet.token -listen 127.0.0.1:8080 \
  -portal-config portal.json -data-dir /var/lib/halos
```

Flags: `-policy-dir` and `-token-file` are required; `-data-dir` persists the request log, device store, audit log and kill list (empty means in-memory only); `-verdicts` points at the file `halo exp analyze --verdicts-file` writes; `-device-ttl` sets how long a device token lives after enrollment (default 2160h, 90 days; an expired device must re-enroll); `-trusted-proxy-cidrs` lists reverse proxies whose `X-Forwarded-For` is believed for rate limiting. The controller and kill-switch flags are covered in the [CLI reference](/halos/reference/binaries/#halo-server). Without `-dev-insecure-user`, the session key must be at least 32 bytes. `-dev-insecure-user`, `-dev-insecure-groups` and `-dev-insecure-admin` disable login for local demos only and log a warning.

## Launchers

`POST /api/v1/launch/{launcher}` returns what the developer needs for their ring. A launcher works only if it is in `selfService.launchers` and its server config is present; otherwise the API answers 409 naming what is missing.

| Launcher | Returns | Needs in `--portal-config` |
|---|---|---|
| `devcontainer` | A `.devcontainer/devcontainer.json` snippet: the Feature with `registry`, `ring`, `firewall: true`, key URL, `halodUrl`, `gatewayHost`, plus `NET_ADMIN`/`NET_RAW` | `devcontainerFeature`, `registry` |
| `codespaces` | A URL from `codespacesURL` with `{ring}` and `{user}` query-escaped | `codespacesURL` |
| `coder` | A URL from `coderURL` | `coderURL` |
| `laptop` | A one-time enrollment token, its expiry, and bash and PowerShell commands | `baseURL`, `registry`, `pubKeyFile`, `halodURL`, `halodSHA256` |

A developer with no ring gets 409 `you are not assigned to any ring`.

## Laptop enrollment

The token is 32 random bytes, stored server-side only as its SHA-256, **single-use**, and expires after `enrollmentTTLSeconds` (default 900). It is burned even if presented late.

```bash
# macOS / Linux, as printed by the portal
curl -fsSL https://halo.acme.example/enroll.sh | sh -s -- <token>
# Windows
& ([scriptblock]::Create((irm https://halo.acme.example/enroll.ps1))) -Token <token>
```

`enroll.sh` refuses to run without a pinned checksum for the machine's OS and architecture, downloads `halod`, verifies its sha256 against the value pinned in the server config, installs it into the root-owned per-OS location, fetches the release public key from `/enroll/release.pub`, exchanges the token at `POST /api/v1/enroll`, and writes `halod.yaml` (mode 0600, root-owned; the server builds the file by marshaling a config struct, not by string templating, so values cannot inject YAML). The script is served over your TLS; the binary it installs is hash-pinned. **UNVERIFIED:** the shell and PowerShell scripts have not been run on real machines here (PowerShell not at all).

## Device tokens

Enrollment returns a `halod.yaml` containing a per-device bearer token, shown exactly once. The server stores only its SHA-256 (plus user, groups at enrollment, timestamps and a revoked flag) in an append-only `devices.jsonl` under `--data-dir` (mode 0600).

- `halod` uses it to ask `GET /api/v1/fleet/ring` which ring to follow (resolved live from the policy and the user recorded at enrollment, so moving a person between rings needs no re-enrollment) and to `POST /api/v1/fleet/report`.
- Device tokens expire `--device-ttl` after enrollment (default 90 days). Re-enroll to renew.
- Failed authentications are rate-limited per client IP (429 with `Retry-After`).
- Admins list devices at `GET /api/v1/devices` and revoke one at `POST /api/v1/devices/{id}/revoke`. A revoked device's next call gets 401. To log a person out of the web console everywhere, an admin calls `POST /api/v1/users/{id}/revoke-sessions`; it invalidates that user's existing sessions (the revocation is persisted).
- Fleets that cannot enroll individually (dev containers, MDM) can report with the shared fleet token from `--token-file`.

Back up `devices.jsonl` and the request log; see [production deployment](/halos/guides/production-deployment/).

## Access requests become PRs

A developer submits `POST /api/v1/requests` with a `kind`, an `item` and a justification (1 to 1000 characters). `kind` must be in `selfService.requestable`; a duplicate pending request from the same user for the same item is refused. Admins (members of `identity.adminGroups`) approve or deny.

| Kind | On approval |
|---|---|
| `ring-opt-in` | PR adding the requester to the ring's `membership.users`. Only for rings with `membership.optIn: true` |
| `mcp-server` | PR appending the catalog server to the requester's ring profile. **This applies to everyone on that profile, not only the requester**, and the PR says so |
| `model`, `harness` | Approval is recorded; no automatic patch exists, so a human makes the change |

The PR is opened on a branch `halos/request-<id>` from a **dedicated clone** of the policy repo (`policyRepoDir`), never the directory the server is serving, and it is never merged. Requires `git` and `gh` on the server. If no writer is configured, approvals are recorded and need a manual policy change.

## Operator console

Admins (members of `identity.adminGroups`) get more of the same web app. Developers see only the kiosk and their own assignment. The pages that matter for operations:

| Page | Shows | Source |
|---|---|---|
| **Releases** | Each ring's signature-verified pointer read from the registry: digest, `seq`, issue and expiry times with an expiry badge (amber under 48 hours, red once expired), how many reporting devices are on the ring's current digest versus others, and drift counts. Shows **cached** state, flagged, when the registry is unreachable; only verified state is ever stored. Needs `registry` and `pubKeyFile` in the portal config | `GET /api/v1/releases` |
| **Device** (from Fleet) | One machine: user, groups, enrollment and token expiry, last report (ring, release, per-harness want versus installed, drift, error code), and up to 50 recent reports, newest first. History is in memory and resets when the server restarts. Device token hashes are never shown | `GET /api/v1/devices/{id}` |
| **Audit** | Privileged actions, newest first, filterable by exact actor and by action. A badge shows whether the whole hash chain verifies and the head hash | `GET /api/v1/audit` |
| **Experiments** | Each experiment with its latest verdict, plus actions (below) | `GET /api/v1/experiments` |

The Audit page proves edits and removals in the middle of the log, not truncation of the newest entries: record the head hash elsewhere if that matters ([security model](/halos/concepts/security-model/#audit-log)).

### Experiment actions

Two kinds of action, with different consequences:

- **Start, pause and conclude** open a **pull request** against the policy repo (`POST /api/v1/experiments/{name}/status`). Nothing changes until a human merges it. The PR is opened from the dedicated `policyRepoDir` clone, like access-request PRs. With no writer configured the API answers 501.
- **Kill switch** takes effect at the gateways at their next poll (about 10 seconds) with no PR. The button appears only when the server exposes the kill switch (`GET /api/v1/capabilities`), asks for a reason, and confirms before acting. See [experiments](/halos/concepts/experiments/#kill-switch).

Every action above is recorded in the audit log with the admin's identity.

## API summary

The complete list with auth levels is the [API reference](/halos/reference/api/).

| Route | Who |
|---|---|
| `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout` | Anyone |
| `GET /api/v1/me`, `/catalog`, `/harnesses`, `/whoami` | Signed-in developer (whoami: self only, admins any user) |
| `POST /api/v1/launch/{launcher}` | Signed-in developer |
| `POST`/`GET /api/v1/requests` | Signed-in developer |
| `POST /api/v1/requests/{id}/approve`, `/deny` | Admin |
| `POST /api/v1/users/{id}/revoke-sessions`, `POST /api/v1/devices/{id}/revoke` | Admin |
| `GET /api/v1/fleet`, `/policy`, `/experiments`, `/experiments/{name}`, `/devices`, `/devices/{id}`, `/releases`, `/audit`, `/killswitch` | Admin |
| `POST /api/v1/experiments/{name}/status`, `/kill`, `/unkill` | Admin |
| `GET /api/v1/capabilities` | Signed-in developer |
| `GET /api/v1/gateway/killswitch` | Gateway token |
| `POST /api/v1/fleet/report` | Fleet token or device token |
| `GET /api/v1/fleet/ring` | Device token |
| `GET /enroll.sh`, `/enroll.ps1`, `/enroll/release.pub`, `POST /api/v1/enroll` | Public; the token is the credential |

Responses carry a strict Content-Security-Policy, `X-Frame-Options: DENY` and `Cache-Control: no-store` on API paths.
