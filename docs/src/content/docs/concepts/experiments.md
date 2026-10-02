---
title: Experiments
description: A/B, canary and shadow experiments on the client or traffic axis, with sticky assignment and stopping rules.
---

An `Experiment` compares **variants** for a set of rings, under a primary metric and guardrails, with a stopping rule.

## Type and axis

| | `client` axis | `traffic` axis |
|---|---|---|
| Variants differ by | profile / release on the machine | model route at the gateway |
| Change takes effect | on rebuild / next `halod` pull ([channels](#client-axis-delivery)) | immediately at the gateway (policy hot-reload) |
| Types | `ab`, `canary` | `ab`, `canary`, `shadow` |
| Example | CLI 2.1.280 vs 2.1.290 | `opus` alias to a newer model |

Types: `ab` splits by weight and compares; `canary` sends a small share to the candidate and aborts on guardrail breach; `shadow` mirrors and does not affect responses ([shadow traffic](/halos/concepts/shadow-traffic/)).

Traffic first: [ADR-0003](/halos/adr/0003-experiments-on-traffic-plane-first/).

## Assignment

- Deterministic: `hash(user, salt) % 10000` mapped over normalized variant weights. `salt` defaults to the experiment name so experiments are independent.
- **Sticky per user.** Because the variant is a function of the user, an agent session never switches model mid-task. Shadow sampling is keyed on the session id the harness sends (for example Claude Code's `x-claude-code-session-id`), so a whole session is either mirrored or not.
- The cohort comes from the identity the gateway verified (OIDC JWT), never from a client header. A request with no verified identity gets default routing and no experiments.
- At most one A/B or canary applies to a request (the first matching running experiment); any number of running shadow experiments can sample it.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/variant-assignment-light.svg" alt="The verified identity is hashed with the experiment salt into 10,000 buckets; the weight bucket picks control (current route) or candidate (routes override), and the gateway stamps x-halo-variant." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/variant-assignment-dark.svg" alt="The verified identity is hashed with the experiment salt into 10,000 buckets; the weight bucket picks control (current route) or candidate (routes override), and the gateway stamps x-halo-variant." width="760" />

## Client-axis delivery

A client-axis variant is a **release**, not a route, so it has to reach the machine through the same signed path as any release. `halo release publish --ring R` builds the ring release plus one release per variant of the running client-axis experiment that enrolls `R`, and serves each on its own **channel**.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/client-axis-channels-light.svg" alt="halo release publish writes the ring release (with the experiment salt, weights and channels) and one channel per variant. halod verifies the ring pointer, computes the same hash as the gateway to pick a variant, then verifies and applies that variant's channel." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/client-axis-channels-dark.svg" alt="halo release publish writes the ring release (with the experiment salt, weights and channels) and one channel per variant. halod verifies the ring pointer, computes the same hash as the gateway to pick a variant, then verifies and applies that variant's channel." width="760" />

- **Channel name:** `<ring>.x-<experiment>.<variant>`. If that exceeds 100 characters, the experiment/variant part becomes the first 20 hex characters of `sha256(experiment NUL variant)` (`<ring>.x-<hash>`). A channel is published like a ring: a signed pointer at `ring-<channel>.pointer`.
- **The ring manifest lists the experiment.** Its `experiments` section (name, salt, per-variant weight and channel) is part of the release the signature covers. `halod` recomputes each channel name and refuses a manifest that names a different one.
- **Same function as the gateway.** `halod` computes the variant with `policy.Experiment.ResolveVariant`, the function `halo-proxy` uses, from the signed salt and weights. The device and the gateway agree on the variant without talking to each other.
- **One running client-axis experiment per ring.** A device applies one release, so two overlapping experiments cannot both deliver. Validation rejects the overlap.
- **An older `halod` ignores the `experiments` section** and applies the ring release, which is control.

### Subject

`halod` needs the user id the gateway hashes. It takes the first that is available:

1. `subject` in the ring endpoint response (`GET /api/v1/fleet/ring` returns `{"ring", "subject"}`, the enrolled user).
2. `subject:` in `halod.yaml` (for MDM: template the user id into the file). 1 to 256 characters, no control characters.
3. The last subject `halod` saved.

With no subject, `halod` applies the ring release, reports `errorCode: no_subject_for_experiment` and exits non-zero from `halod once`. It never guesses a variant.

### Failure behaviour

- **A channel that fails verification keeps last-good.** Bad signature, wrong org, replayed `seq`, expired pointer, or a release for a different experiment/variant fails the whole cycle: `keeping last-good <digest>`. `halod` does not fall back to the ring release, because that would silently move treatment devices to control.
- **Each channel has its own anti-rollback mark** in the `halod` state file, like a ring.
- **Pause and republish to revert.** When the experiment is no longer `running`, the next `halo release publish` writes a ring release with no `experiments` and no channels. Devices converge to it on their next pull.

### Variant guardrails

A variant profile is held to the ring's profile more strictly than a child is to its parent. These are **errors** (`halo validate` exit 2), not warnings:

| Rule | Error when |
|---|---|
| Exact version pins | a harness `version` is not exact semver (no ranges, no `latest`), or no harness is enabled |
| Telemetry | `telemetry.enabled` is false |
| `permissions.disableBypass` | not true |
| No widening | the variant adds `permissions.allow`, `permissions.ask` or `egress.allowedDomains` entries the ring profile lacks, or drops a ring `permissions.deny` or `mcp.denied` entry |
| No MCP changes | `mcp.servers` adds or changes a server the ring does not have |
| No weakening | `sandboxRequired`, `mcp.managedOnly`, `hooks.managedOnly` or `models.enforce` is true on the ring and not on the variant; `permissions.sandbox` is relaxed (`read-only` to `workspace-write`, or any sandbox to none/`off`) |
| Mode ordering | `permissions.mode` is more permissive than the ring's, ranked `plan` < `default` < `acceptEdits` < `auto` (empty means `default`; an unknown mode ranks above `auto`) |
| Hooks are a subset | the variant has a hook (command and event) the ring profile lacks |
| Telemetry unchanged | `telemetry.otlpEndpoint` or `telemetry.logPrompts` differs from the ring's, so a variant cannot redirect or start exporting evidence or prompts |
| Models are a subset | when the ring restricts `models.allowed`: the variant's list is empty, adds a model, or its `models.default` is outside the ring's list |
| Instructions and env equal | `instructions` or `env` differs from the ring profile's |
| Unique channels | a channel name collides with a ring or another channel |

### Attribution

The variant release carries the experiment and variant in its harness config. Claude Code gets `halo.experiment` and `halo.variant` in `OTEL_RESOURCE_ATTRIBUTES` (next to `halo.ring` and `halo.release`). Codex, Gemini CLI and Copilot CLI have no resource-attribute setting: `halo release publish` and `halo render` warn that CLI metrics are not attributed to the experiment.

The gateway attributes a request (`x-halo-experiment`, `x-halo-variant`) to a client-axis experiment **only when no traffic-axis experiment applies** to it, so a client-axis experiment never displaces a traffic experiment's routing. Client-axis experiments never route. `halod status` and fleet reports carry `experiment` and `variant`.

Walkthrough: [A/B a CLI upgrade](/halos/guides/cli-upgrade-ab/). Design: [ADR-0010](/halos/adr/0010-release-channels-for-client-experiments/).

## Metrics and stopping

```yaml
metrics:
  primary: {metric: halo.task.success, direction: increase}
  guardrails:
    - {metric: halo.cost.usd_per_session, direction: decrease, maxRegression: 0.10}
stopping: {method: msprt, alpha: 0.05, minSamples: 300, maxDays: 14, maxSpendUSD: 500}
```

- `msprt`: mixture sequential probability ratio test, valid under continuous monitoring (no peeking penalty). `fixed`: fixed horizon.
- Guardrail `maxRegression` is relative worsening that aborts the experiment (0.10 = 10%). When the control's value is 0 (an error rate with no control errors), relative worsening is unbounded: any significant increase fails the guardrail, and two arms that are both exactly 0 pass it.
- `maxDays` and `maxSpendUSD` are hard ceilings so a non-converging experiment stops spending.
- Analysis: mSPRT for sequential decisions and bootstrap confidence intervals (`internal/stats`), with CUPED variance reduction available in the stats package.

## Lifecycle

`halo exp start|pause|conclude <name>` edit the `status` field of the experiment YAML in place (use `--policy-dir` for the policy repo). Only `running` experiments affect traffic.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/experiment-lifecycle-light.svg" alt="An experiment starts as draft, runs after halo exp start, can be paused and restarted, and ends concluded from running or paused." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/experiment-lifecycle-dark.svg" alt="An experiment starts as draft, runs after halo exp start, can be paused and restarted, and ends concluded from running or paused." width="760" />

`halo exp list` and `halo exp show <name>` read them. The status change is a git change like any other: commit it, review it, merge it. The gateway reloads the compiled policy (`halo gateway compile`) on its next snapshot.

## Verdicts

```bash
halo exp analyze opus-5-5-canary --policy-dir policy --clickhouse http://clickhouse:8123 \
  --verdicts-file verdicts.json
```

The verdict is one of `promote`, `rollback`, `continue` or `expired` (a `maxDays` or `maxSpendUSD` ceiling was hit without a decision). `--verdicts-file` upserts the result into a JSON file that `halo-server` serves (`--verdicts-file`). ClickHouse credentials come from `--user` and the `HALO_CLICKHOUSE_PASSWORD` environment variable.

A `promote` or `rollback` report carries `source`: `gateway` or `cli`, the evidence plane the deciding metric came through (`halo exp analyze --output json` shows it, and so does each metric). `gateway` is exact cohort attribution measured by `halo-proxy` and delivered over the authenticated gateway receiver; `cli` is telemetry from developer machines, which anyone who can reach the collector can forge. Only `gateway` evidence can trip the kill switch ([evidence trust](/halos/concepts/evidence-plane/#evidence-trust)). Sources are never mixed within one analysis: a metric uses gateway rows when any exist, and falls back to CLI events otherwise.

`halo exp promote <name> --ring <ring> --release <digest>` requires a `promote` verdict and opens a PR that points the ring at the release (`--dry-run` prints the patch). It never merges.

## The controller loop

`halo exp analyze` is one evaluation you run by hand. The **controller** runs it for every `status: running` experiment on a timer and acts on the result. It is built into `halo-server` (`--controller`) and also available as a one-shot for CI or cron (`halo controller run --once`).

<img class="diagram dark:sl-hidden" src="/halos/diagrams/controller-loop-light.svg" alt="Every five minutes the controller evaluates each running experiment from ClickHouse evidence: continue, roll back (kill switch, pause PR, notify), promote (conclude PR, notify) or expire (conclude PR, notify)." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/controller-loop-dark.svg" alt="Every five minutes the controller evaluates each running experiment from ClickHouse evidence: continue, roll back (kill switch, pause PR, notify), promote (conclude PR, notify) or expire (conclude PR, notify)." width="760" />

| Verdict | Controller action | Notes |
|---|---|---|
| `rollback` | If the deciding evidence is **gateway-sourced** and a kill list is served, trips the [kill switch](#kill-switch) at once; always opens a PR setting `status: paused` with the evidence in the body and notifies | The PR is never merged. On CLI-sourced evidence nothing is auto-killed (`killOutcome: not_gateway_evidence`): a human decides |
| `promote` | Opens a PR that sets `status: concluded`, notifies | It does not roll the treatment out: before merging, a human adds the ring release (client axis) or model route (traffic axis). Concluding returns everyone to control |
| `expired` | Opens a PR that sets `status: concluded`, notifies | The PR is never merged |
| `continue` | Nothing | |

Rules that matter in operation:

- **Each action happens once per experiment run.** The record is `controller-state.jsonl` in the data dir. When the experiment is next seen not running (someone merged the pause or conclusion), the record resets, so a restarted experiment starts clean. Ticks never duplicate PRs or notifications.
- **Kill first, but only on trusted evidence and only if something enforces it.** On rollback the kill happens before the PR, and the notification goes out even if the kill or the PR failed, because people must know. The webhook event's `killOutcome` says what happened: `enforced`, `recorded_only` (written, enforcement not guaranteed), `not_configured`, `not_gateway_evidence`, or `failed`. The in-process controller kills only when `halo-server` has a kill key (`-killswitch-key-file`); without it nothing reads the list, so it does not pretend: the PR and notification say **merge urgently**. `halo controller run` always writes the kill to `<data-dir>/killswitch.jsonl`, and says it is enforced only with `--killswitch-served`.
- **No evaluation after a rollback, or while killed.** Once a run rolled back, the controller only finishes that rollback's pending PR/notifications; a later `promote` verdict cannot conclude it. A running experiment found killed (admin kill, or a kill left from an earlier run) is not evaluated (its evidence is all-control); humans are told once per run to unkill before resuming (webhook verdict `killed`).
- **Notifications are tracked per channel** (`notify:slack`, `notify:webhook`): a failing channel is retried on later ticks alone, the others are not re-posted. Each delivery has a 10-second timeout and does not follow redirects.
- **The controller never merges.** Promotion and rollback PRs wait for a human. Automatic rollback (the kill switch) is the only automatic action that changes live traffic.
- **Errors retry sooner than the interval**: 15s, 30s, and so on, capped at the tick interval. Each tick is bounded to 2 minutes. The interval is at least 1 minute (default 5).
- **Run one controller per data dir.** Two controllers would race on the action log.
- **Notifications** go to a Slack incoming webhook and/or a generic webhook. Generic webhook bodies are signed and timestamped: `X-Halo-Timestamp: <unix seconds>` and `X-Halo-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>`, with the secret from `--notify-webhook-secret-file`. Receivers must verify the signature and reject timestamps more than 5 minutes off; [verification snippets](/halos/reference/binaries/#verifying-the-webhook-signature). Webhook URLs are secrets: read from files, never logged.
- **Audit is fail-closed for privileged actions.** A controller kill is appended to the hash-chained `audit.jsonl` (actor `halo-controller`) with fsync. If the append fails the kill stays applied (fail safe) and the tick reports the audit gap as an error. `halo controller run` appends through the same chain, so it is a **single writer**: do not point it at a data dir a live `halo-server` is appending to; use the server's in-process controller there.

### Running it

Inside `halo-server` (the usual way; kills reach gateways through the same data dir):

```bash
halo-server -policy-dir /srv/policy -token-file fleet.token -data-dir /var/lib/halos \
  -controller -clickhouse-url http://clickhouse:8123 -clickhouse-user halo -clickhouse-password-file ch.pass \
  -policy-repo-dir /srv/policy-writer -policy-repo-base main \
  -killswitch-key-file killswitch.key -gateway-token-file gateway.token \
  -notify-slack-url-file slack.url -metrics-listen 127.0.0.1:9100
```

`--controller` requires `-clickhouse-url` and `-data-dir`. `-policy-repo-dir` must be a clone separate from `-policy-dir`; it may be the portal's `policyRepoDir` (one clone and lock for console proposals and controller PRs). It is hard-reset to `origin/<base>` before each PR. Without it, the controller still evaluates, kills and notifies but opens no PRs. PRs need `git` and an authenticated `gh`.

As a one-shot (CI, cron):

```bash
HALO_CLICKHOUSE_PASSWORD=... halo controller run --once --policy-dir . \
  --clickhouse http://clickhouse:8123 --user halo --data-dir /var/lib/halos
```

**Check:** exit code is non-zero if any experiment failed. PRs are opened from the git checkout that contains `--policy-dir`. Kills reach gateways only when `--data-dir` is the same directory `halo-server` uses as `-data-dir` (a shared volume); otherwise the kill is recorded but nothing serves it. Pass `--killswitch-served` only when that is true: without it, rollback PRs and notifications say the kill is merely recorded. Use `--no-pr` for verdicts, kills and notifications only. Flags: [CLI reference](/halos/reference/cli/controller-run/).

## Kill switch

Merging a pause PR takes a review cycle plus a policy snapshot roll-out. The kill switch is the fast path for a bad treatment: a signed list of killed experiment names that gateways poll from `halo-server`. A killed experiment is treated as **not running**: its users get control routing and its shadow mirroring stops, at the gateway's next poll (default every 10 seconds), with no PR and no merge.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/kill-switch-light.svg" alt="The controller or an admin kills an experiment at halo-server, which appends to killswitch.jsonl with an audit entry. Every 10 seconds each gateway fetches the signed list with its gateway token and verifies signature, freshness and that issuedAt is strictly newer; killed experiments get control routing and no shadow." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/kill-switch-dark.svg" alt="The controller or an admin kills an experiment at halo-server, which appends to killswitch.jsonl with an audit entry. Every 10 seconds each gateway fetches the signed list with its gateway token and verifies signature, freshness and that issuedAt is strictly newer; killed experiments get control routing and no shadow." width="760" />

An admin can kill or unkill by hand (`POST /api/v1/experiments/{name}/kill` and `/unkill`; the console shows a Kill switch button when the server has one). Setup and the wire format: [API reference](/halos/reference/api/#kill-switch), [security model](/halos/concepts/security-model/#kill-switch), [ADR-0009](/halos/adr/0009-signed-kill-switch/).

### Failure policy

| Situation | What gateways do |
|---|---|
| `halo-server` unreachable, or the list fails verification | Keep the **last accepted** list. A kill never lapses because the control plane is down |
| The gateway has **never** fetched a valid list | Kill nothing. The policy snapshot's `status` fields alone decide |
| A list is older than 10 minutes or more than 1 minute in the future | Rejected (last list stays) |
| A list is not strictly newer (`issuedAt`) than the current one | Rejected as a replay, so an old envelope cannot undo a kill |

Kills **do not expire**. Pausing or concluding the experiment in policy does not lift a kill. Unkill it explicitly before you restart the experiment, or it stays on control:

```bash
curl -X POST https://halo.acme.example/api/v1/experiments/opus-5-5-canary/unkill \
  -H 'content-type: application/json' -d '{"reason":"fixed; restarting"}'   # admin session required
```

### Limits: the client axis

The kill switch lives at the **gateway**, so it fully undoes a `traffic`-axis experiment (model routes). A `client`-axis experiment changes the release **on the machine**. Killing it always stops gateway-side effects (routing, mirroring and attribution). Whether it reaches machines depends on `halod`:

- **`killSwitch` configured in `halod.yaml`:** `halod` polls the same signed list (`GET /api/v1/fleet/killswitch`, device token, default every 60 seconds) and treats a killed experiment as not running. The device applies the ring release (control) within one poll, without a republish, and reports `killed: true`. Unkill returns it to its variant. The list is verified, persisted and replay-protected like the gateway's; a failed fetch keeps the last list. Config: [`halod.yaml`](/halos/reference/binaries/#halodyaml).
- **Not configured (the default; enrollment does not add it):** devices keep their variant until the experiment is paused or concluded in policy and `halo release publish --ring <R>` republishes, or `halo rollback` points the ring and its channels at an earlier release. See [client-axis delivery](#client-axis-delivery).

The controller's notification text ("gateway traffic only; client-axis variants stay until the pause PR merges") describes the second case.

Killed experiments also get no `x-halo-experiment` or `x-halo-variant` stamp ([gateway headers](/halos/reference/gateway-headers/)).
