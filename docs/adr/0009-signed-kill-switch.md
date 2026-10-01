---
title: "ADR-0009: Signed, instant kill switch for experiments"
description: Gateways poll a signed kill list from halo-server so a bad experiment can be switched off in seconds without a PR merge.
status: accepted
date: 2026-09-30
---

# ADR-0009: Signed, instant kill switch for experiments

- Status: accepted (extends ADR-0003 and the guardrail rollback in the experiments design)
- Date: 2026-09-30

## Context and problem statement

Experiments on the traffic plane (ADR-0003) change what model real developers get. A guardrail breach (cost, error rate, latency) means the treatment should stop *now*. The only path that existed was a policy PR setting `status: paused`: review, merge, `halo gateway compile`, snapshot roll-out. That takes minutes to hours, which is too slow for a regression that burns money or breaks every request, and it is the wrong shape for an automated controller that detects the breach at 3am.

At the same time, anything that can switch routing without a merge is a new control channel to the gateways. It must not become a way to attack them, and it must not weaken the rule that a human owns every irreversible step.

## Decision drivers

- Rollback of a bad experiment in seconds, without a merge.
- The new channel can only move traffic *back to control*; it cannot roll anything out.
- A compromised network path, a stolen release key or a replayed response must not be able to forge or undo a kill.
- The control plane being down must never silently re-enable a killed experiment.
- Reuse what exists: `halo-server` already holds admin sessions, an audit log and a data dir; gateways already poll policy snapshots.
- Small enough to reason about: one signed document, one key, one token.

## Considered options

1. **Policy PR only.** Keep `status: paused` in git as the sole mechanism; make the controller open the PR faster.
2. **Unsigned kill endpoint.** Gateways poll `halo-server` over TLS for a plain JSON list.
3. **mTLS only.** Authenticate the gateway-to-server channel with client certificates and trust the body.
4. **Signed kill list with a dedicated key (chosen).** `halo-server` serves an ed25519-signed list; gateways verify it and apply it on top of their policy snapshot.

## Decision outcome

Chosen: **option 4.**

- `halo-server` keeps an append-only `killswitch.jsonl` (who, when, why, per experiment; last record wins). An admin (`POST /api/v1/experiments/{name}/kill`) or the controller on a `rollback` verdict writes it, and each change is audit-logged.
- `GET /api/v1/gateway/killswitch` returns `{payload, signature}`. The payload is `{version, experiments, issuedAt}`; the signature is ed25519 over `"halo-killswitch-v1\n" + payload`. It is enabled only when both `--killswitch-key-file` and `--gateway-token-file` are set.
- **A dedicated key**, generated with `halo keys generate --name killswitch`, separate from the release key. The gateway holds only the public half.
- **A bearer gateway token** (16+ characters) controls who may read the list; the signature controls what a gateway believes.
- `halo-proxy` and `halo-kong` poll every 10 seconds. A killed experiment is applied as `status: paused` on the gateway's in-memory policy: control routing, no shadow mirroring, no experiment headers.
- **Verification rules:** signature valid; `issuedAt` no more than 10 minutes old and no more than 1 minute in the future; `issuedAt` strictly newer than the list already held.
- **Failure policy:** a failed fetch or verification keeps the last accepted list. A gateway that has never accepted a list kills nothing and the policy snapshot decides. Kills never expire and are lifted only by an explicit unkill (pausing or concluding in policy does not lift them).
- The controller still opens the pause PR on rollback. The kill is the fast, reversible stopgap; the merged PR is the durable state.

## Consequences

- Good: a rollback verdict takes effect on gateways within one poll interval, with no merge.
- Good: the channel is one-directional in effect. It can only return users to control; it has no way to add a route or start an experiment.
- Good: a stolen release key cannot forge kills, and a stolen kill key cannot sign a release or ring pointer. Replayed or stale envelopes are rejected, so an attacker cannot un-kill by replaying an old list.
- Good: a control-plane outage does not re-enable a killed experiment.
- Bad: a second key and a second secret (the gateway token) to generate, store and rotate. There is no rotation protocol; rotating means updating every gateway's public key and `halo-server` together.
- Bad: a gateway that has never fetched a valid list kills nothing, so a kill issued while `halo-server` is unreachable takes effect only after the gateway can fetch. A fresh gateway starts unprotected until its first successful poll.
- Bad: whoever holds the kill key and controls a gateway's path can kill experiments (a denial of the experiment, not of service: users keep working on control). Anyone who can write `killswitch.jsonl` on the server can un-kill.
- Bad: kills do not expire, so a forgotten kill keeps an experiment off after the policy is fixed; operators must unkill before restarting.
- Limit: it acts on gateways only. A `client`-axis experiment changes profiles on machines, which a kill cannot reach; those variants stay until the pause PR merges and `halod` pulls the release. (Later: `halod` can poll the same signed list on an opt-in basis; see [client-axis delivery](/halos/concepts/experiments/#limits-the-client-axis).)
- Neutral: `halo gateway deck` does not yet generate the `killswitch_*` plugin fields; Kong users add them by hand.

## Pros and cons of the options

### 1. Policy PR only

- Good: one mechanism, git is the source of truth, nothing new to secure.
- Bad: minutes to hours to take effect, and it needs a human in the loop at the moment speed matters. Rejected as too slow; kept as the durable path.

### 2. Unsigned kill endpoint

- Good: trivial to build.
- Bad: TLS protects the transport, not the content. A compromised proxy, a misconfigured ingress cache or an on-path attacker can serve an empty list (hiding a kill) or a full one (switching off every experiment), and a replayed old response silently un-kills. Rejected.

### 3. mTLS only

- Good: strong channel authentication with existing tooling.
- Bad: authenticates the pipe, not the message; replay and a compromised server-side TLS terminator are not covered, and it requires a client-certificate PKI on every gateway, which heterogeneous stacks (Kong, Envoy, nginx, API Gateway) do not share. It is not a substitute for signing, but remains a compatible hardening on top, and `halo-proxy` does not provide mTLS today. Rejected as the sole control.

## More information

- Concepts and failure policy: [experiments](/halos/concepts/experiments/#kill-switch)
- Wire format and endpoints: [API reference](/halos/reference/api/#kill-switch)
- Threat rows T22 to T26: [threat model](/halos/reference/threat-model/)
- Code: `internal/gateway/killswitch.go`, `internal/server/killswitch.go`, `internal/controller/killstore.go`

## Addendum 2026-09-30: who may trip it, and what happens without it

A security review tightened how the controller reaches the switch. The wire format and trust chain above are unchanged.

- **Only trusted evidence kills.** The controller trips the switch on a `rollback` verdict only when the deciding evidence is gateway-sourced (the collector's authenticated receiver stamped `halo.source=gateway`). CLI telemetry is client-controlled, so a CLI-sourced rollback opens the pause PR and notifies (`killOutcome: not_gateway_evidence`) and a human decides. See [evidence plane](/halos/concepts/evidence-plane/#evidence-trust).
- **No key, no pretence.** `halo-server` serves a kill list and accepts kill and unkill only with `--killswitch-key-file` (which requires `--data-dir` and `--gateway-token-file`). Without it, the in-process controller does not record a kill nobody reads: it reports the rollback as not enforced and asks humans to merge the pause PR urgently, and `GET /api/v1/capabilities` reports `killSwitch: false`. `halo controller run` writes the kill to the data dir and says it is enforced only with `--killswitch-served`.
- **Killed means held.** The controller does not evaluate a running experiment that is already killed; it tells humans once to unkill before resuming.
- **A kill needs a reason** (HTTP 422 without one) and is audited fail-closed: the kill stays applied if the audit append fails (fail safe), a failed unkill is reverted, and the request returns 500.
- **No cleartext token.** Gateways refuse a plain `http://` kill URL to a non-loopback host unless `killSwitch.allowInsecureInCluster` (`halo-kong`: `killswitch_allow_insecure_in_cluster`) is set. A misconfigured `halo-kong` keeps serving, logs ERROR once a minute and sets `x-halo-killswitch: misconfigured` on the upstream request.
- **Webhooks are replay-resistant.** The generic webhook carries `X-Halo-Timestamp` and an HMAC over `timestamp + "." + body`; receivers reject timestamps more than 5 minutes off.
