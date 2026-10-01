# halo-server

Serves the Halos API and console. Optionally runs the automated experiment
loop (`--controller`) and the gateway kill switch.

## Core flags

| Flag | Default | Purpose |
|---|---|---|
| `--policy-dir` | (required) | Served policy repo checkout. SIGHUP reloads. |
| `--token-file` | (required) | Bearer token halod uses for `POST /api/v1/fleet/report`. |
| `--listen` | `127.0.0.1:8080` | API/console listen address. |
| `--data-dir` | in-memory | JSONL logs: fleet, requests, devices, audit, `killswitch.jsonl`, `controller-state.jsonl`. |
| `--verdicts-file` | | Verdicts JSON array shown in the console; the controller (and `halo exp analyze --verdicts-file`) upserts it. `--verdicts` is a deprecated alias. |
| `--portal-config` | | Portal/self-service JSON config. |
| `--trusted-proxy-cidrs` | | Reverse proxies whose `X-Forwarded-For` is trusted for rate limiting. |
| `--device-ttl` | 90d | Device token lifetime. |

## Kill switch

Instant rollback on the traffic plane, with no PR merge needed. Killed
experiments are treated as not running by halo-proxy and halo-kong: control
routing and no shadow mirroring.

| Flag | Purpose |
|---|---|
| `--killswitch-key-file` | ed25519 PKCS#8 PEM private key (`halo keys generate --name killswitch`). It signs the kill list. Use a dedicated key, not the release key. **Requires `--data-dir`** (kills must survive a restart). |
| `--gateway-token-file` | Bearer token (16+ chars) that gateways present to `GET /api/v1/gateway/killswitch`. |

Set both flags or neither; startup fails otherwise, and fails if the key is set without `--data-dir`. Without a key the server is honest about it: no kill list is served, kill and unkill return 501, `GET /api/v1/capabilities` reports `killSwitch: false`, and the in-process controller reports rollbacks as **not enforced** ("merge the pause PR urgently") instead of recording a kill nobody reads. The gateway endpoint returns
`{"payload": base64(JSON {version, experiments, issuedAt}), "signature": base64(ed25519("halo-killswitch-v1\n" + payload))}`.

Gateways reject a list if:

- the signature is bad,
- it is older than 10 minutes or more than 1 minute in the future, or
- it is not strictly newer than the list they already hold.

On a fetch failure a gateway keeps its last-known list. A gateway that has never fetched a list kills nothing.

Admin endpoints (session plus admin role, same-origin, audit-logged as `experiment.kill` or `experiment.unkill`):

- `POST /api/v1/experiments/{name}/kill` with body `{"reason": "..."}` (**required**, 500 characters max; HTTP 422 without one)
- `POST /api/v1/experiments/{name}/unkill` with body `{"reason": "..."}` (optional)
- `GET /api/v1/killswitch` lists active kills with who, when and why.

A kill does not expire. Pausing or concluding the experiment in policy does not
lift it. Unkill it explicitly before you restart the experiment.

## Audit

Privileged actions append to the hash-chained `audit.jsonl` in `--data-dir`, fsynced before the action is acknowledged. They fail closed: kill, unkill, device enrollment, session and device revocation and experiment-status PRs return HTTP 500 if the append fails. A kill whose audit append fails stays applied (fail safe), a failed unkill is reverted, and a revocation stays in force. `audit.jsonl` has a single writer: do not point `halo controller run` at a data dir this server is using.

## Controller (`--controller`)

On every tick the controller evaluates each `status: running` experiment
against ClickHouse evidence and then:

- **rollback**: kills the experiment at once **if** the deciding evidence is gateway-sourced and a kill key is configured, opens a PR that sets `status: paused` with the evidence in the body, and notifies. Rollbacks decided on CLI telemetry are not auto-killed (`killOutcome: not_gateway_evidence`); without a kill key the notification says to merge urgently.
- **promote**: opens a PR that concludes the experiment and notifies. Before merging, a human adds the rollout change (ring release or model route).
- **expired**: opens a PR that concludes the experiment and notifies.

The controller never merges a PR. It takes each action at most once per
experiment run; the record lives in `controller-state.jsonl`. When the
experiment is next seen not running, that record resets. Errors are retried
at 15s, 30s and so on, up to the tick interval. A running experiment that is
already killed is held, not evaluated; notifications tell humans to unkill
before resuming. Notifications are tracked per channel and a failed channel is
retried on later ticks without re-posting to the others.

| Flag | Default | Purpose |
|---|---|---|
| `--controller` | off | Enable the loop. Requires `--clickhouse-url` and `--data-dir`. |
| `--interval` | `5m` | Tick interval (minimum 1m). Each tick is bounded to 2m. `--controller-interval` is a deprecated alias. |
| `--clickhouse-url`, `--clickhouse-database`, `--clickhouse-user`, `--clickhouse-password-file` | | Evidence source (`halo_metrics` table). |
| `--policy-repo-dir` | | **Dedicated** clone used to open PRs. It is hard-reset to `origin/<base>` before each PR, so it must be separate from `--policy-dir` and the portal `policyRepoDir`. Without it, no PRs are opened. Needs `git` and an authenticated `gh`. |
| `--policy-repo-subdir` | | Policy root inside the clone. |
| `--policy-repo-base` | `main` | PR base branch. |
| `--notify-slack-url-file` | | Slack incoming-webhook URL. Posts `{text, blocks}`. |
| `--notify-webhook-url-file` | | Generic webhook URL. Posts the JSON event. |
| `--notify-webhook-secret-file` | | HMAC-SHA256 secret. Adds `X-Halo-Timestamp: <unix s>` and `X-Halo-Signature: sha256=<hex HMAC(secret, timestamp + "." + body)>`. Receivers must verify it and reject timestamps more than 5 minutes off (Go and Python snippets: docs site, CLI reference, "Verifying the webhook signature"). |
| `--metrics-listen` | off | Serves `/metrics` with `halo_controller_ticks_total`, `halo_controller_verdicts_total{verdict}` and `halo_controller_errors_total`. Unauthenticated, so keep it internal. |

Webhook URLs are secrets. They are read from files and never logged.

For CI or cron, `halo controller run --once --policy-dir . --clickhouse URL --data-dir DIR`
runs the same loop once. Its PRs come from the CI checkout. Its kills reach the
gateways only when `DIR` is halo-server's `--data-dir` (a shared volume).
Run only one controller per data dir. `halo controller run` also appends its
kills to `audit.jsonl`, so it must not run against a data dir a live
halo-server is writing; use `--controller` there. Pass `--killswitch-served` to
`halo controller run` only when this server (with `--killswitch-key-file`)
serves that data dir; otherwise its messages say the kill is only recorded.
