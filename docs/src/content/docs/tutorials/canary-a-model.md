---
title: Canary a new model
description: Route 5% of a ring to a new model at the gateway, check who gets what, simulate the rollout, and roll back without touching a client.
---

This is the **traffic axis**: clients keep asking for the alias (`opus`), and the gateway decides which model answers. You will read the canary that ships in `examples/acme-corp`, check which user hits which route, simulate the rollout, and pause it. Commands were run against that example; the gateway itself is not started (the [playground](/halos/getting-started/playground/) does that).

**Prerequisites:** a built `halo` ([Your first 10 minutes](/halos/tutorials/first-10-minutes/)) and the repo checkout. Work in a copy: `cp -r examples/acme-corp policy && cd policy`.

## 1. Read the pieces

The experiment `experiments/opus-5-5-canary.yaml` sends 5% of `ring1-canary` to a new `opus` route:

```yaml
type: canary
axis: traffic
status: running
rings: [ring1-canary]
variants:
  - {name: control, weight: 95, control: true}
  - name: opus-5-5
    weight: 5
    routes:
      opus: {upstream: orchestrator, model: arn:aws:bedrock:…/z9w5opus55dd}
```

The rollout `rollouts/opus-5-5-upgrade.yaml` drives it: dark-launch, canary 1/5/25/50%, then a 5% holdout. It is `active` at step `canary-5`.

## 2. See who gets which model

Assignment is sticky per user and comes from the verified identity. `halo whoami` finds a user in the treatment arm, and `gateway routes` shows the effective routes for them and for a control user:

```console
$ halo whoami --user dev59@acme.com
user     dev59@acme.com
ring     ring1-canary
profile  engineering
variant  claude-cli-2.1.3xx-ab = control
variant  opus-5-5-canary = opus-5-5
$ halo gateway routes --user dev59@acme.com --session s1 | grep -E '^(ALIAS|opus)'
ALIAS   ORDER  UPSTREAM       KIND          MODEL               WEIGHT  PRIORITY  …
opus    1      orchestrator   orchestrator  arn:…/z9w5opus55dd  -       0         …  <- hit when healthy; experiment opus-5-5-canary/opus-5-5
$ halo gateway routes --user dev26@acme.com --session s1 | grep -E '^(ALIAS|opus)'
ALIAS   ORDER  UPSTREAM          KIND     MODEL                     WEIGHT  PRIORITY  …
opus    1      bedrock-use1      bedrock  arn:…/p7q2opus41bb        -       0         30s  <- hit when healthy; experiment opus-5-5-canary/control
opus    2      anthropic-direct  anthropic  claude-opus-4-1-20250805  -       1         …
```

(Columns trimmed.) `dev59` lands on the new route, `dev26` stays on Bedrock with its Anthropic failover. The cohort comes from the authenticated identity, never a request header.

A **toggle** is the other way to change a route. `toggles/sonnet-next-route.yaml` sends `sonnet` for ring0 to `claude-sonnet-5-5`:

```console
$ halo gateway routes --user alice@acme.com --group ai-platform | grep -E '^(ALIAS|sonnet)'
ALIAS   ORDER  UPSTREAM          KIND       MODEL              …
sonnet  1      anthropic-direct  anthropic  claude-sonnet-5-5  …
$ halo toggle eval --user alice@acme.com --groups ai-platform | grep -A1 sonnet-next
on  sonnet-next-route            rule harness-team matched (on)
      rule harness-team: ring ok ("ring0-harness-team" in [ring0-harness-team])
```

An experiment's variant route wins over a toggle's.

## 3. Plan and simulate the rollout

```console
$ halo rollout plan opus-5-5-upgrade
Rollout opus-5-5-upgrade  (traffic axis, active)
Change:     gateway alias opus -> treatment route of experiment opus-5-5-canary
…
  1  T+0      dark-launch  dark-launch  [#.........]  10%  10% of ring1-canary requests mirrored, none served  2d   500   …   pause
> 3  T+2d6h   canary-5     canary       [#.........]   5%  5% of ring1-canary on treatment                     12h  500   …   rollback
…
Earliest completion: T+18d18h (sum of bakes; samples and approvals add time). Every step is a PR a human merges.
On completion: gateway.models.opus has failover targets: re-point it to orchestrator/arn:…/z9w5opus55dd by hand in this PR
$ halo rollout simulate opus-5-5-upgrade --scenario regression
…
T+2d20h  canary-1     rollback  guardrail:halo.latency.p50_ms failed: +21.3% [+14.8%, +27.9%] (threshold regression <= 10.0%)

Outcome: rollback after 2d20h
$ halo rollout status opus-5-5-upgrade
Rollout opus-5-5-upgrade  (traffic axis, active)
Step:       3/6 canary-5: 5% of ring1-canary on treatment
…
(metric gates need --clickhouse)
```

`status` shows gate values as `unknown` here because there is no telemetry; point it at ClickHouse (`--clickhouse`) for live evidence. Gates here are latency and error rate, because task success is judged offline by [`halo eval`](/halos/tutorials/gate-upgrades-on-evals/).

## 4. Roll back without touching a client

```console
$ halo exp pause opus-5-5-canary
ok opus-5-5-canary: "running" -> "paused" (experiments/opus-5-5-canary.yaml)
$ halo gateway compile -o policy.json
wrote policy.json (12799 bytes)
$ halo gateway routes --user dev59@acme.com --session s1 | grep -E '^opus'
opus   1   bedrock-use1      bedrock    arn:…/p7q2opus41bb        …
opus   2   anthropic-direct  anthropic  claude-opus-4-1-20250805  …
```

After the pause and recompile, `dev59` is back on the control route. `halo-proxy` and `halo-kong` hot-reload the compiled policy. For a stop with no PR (effective at the next poll, about 10 s at gateways and 60 s on devices), use the signed kill list: [Kill a bad change in 10 seconds](/halos/tutorials/kill-a-bad-change/).

## What just happened

- The experiment assigns users by hashing their identity, so the same user always sees the same model, and the variant never comes from a client header.
- `gateway routes` ran the same resolver the gateway uses, so it predicts the route before any traffic flows.
- Every rollout step is a PR a human merges. Completion re-points the alias by hand, because `opus` has failover targets.
- Pausing the experiment and recompiling restored the control route. No client or release changed.

## Next

- [Canary a model upgrade](/halos/guides/model-upgrade-canary/): shadow first, then canary and promote
- [Shadow traffic](/halos/concepts/shadow-traffic/) and [rollouts](/halos/concepts/rollouts/)
- [Add a feature toggle](/halos/tutorials/add-a-toggle/)
