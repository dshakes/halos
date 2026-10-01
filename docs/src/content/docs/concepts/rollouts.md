---
title: Rollouts
description: Phase one change through ordered steps (progressive, canary, blue-green, dark launch, holdout), each with a bake, a sample floor and gates. Breaches roll back automatically; every advance is a PR.
---

A **Rollout** takes one change (a release on the client axis, a model route on the traffic axis) through ordered **steps**. Each step has a strategy, an exposure, a minimum bake, a sample floor and gates. The controller judges the live step on every tick: a breached gate acts at once, and a passed step only ever opens a PR.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/rollout-strategies-light.svg" alt="The five rollout strategies: progressive ring moves, canary percentages, blue-green switching, dark launch through mirrored traffic, and a long-term holdout." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/rollout-strategies-dark.svg" alt="The five rollout strategies: progressive ring moves, canary percentages, blue-green switching, dark launch through mirrored traffic, and a long-term holdout." width="880" />

## Strategies

| Strategy | Axis | `percent` means | Moves |
|---|---|---|---|
| `progressive` | client | whole ring (unset or 100) | `Ring.release` to `change.release` |
| `blue-green` | client | whole ring | Ring switches to the pre-staged release; rollback switches back to `baseline.release` |
| `canary` | both | treatment share; may never go down between steps | Backing experiment's weights |
| `dark-launch` | traffic | share of requests mirrored by `halo-shadow`; nobody is served it | Shadow sample rate |
| `holdout` | both | share kept on **control** for the bake | Experiment weights |

Percent steps carry their exposure on the backing **experiment** (two arms, one control), so assignment stays in `internal/assign` and the experiment's kill switch is the fast rollback. Ring-wide steps have no control arm, so they cannot carry metric guardrails or `minSamples`. A client-axis rollout needs at least one ring-wide step; a traffic-axis rollout re-points `change.alias` when it completes.

## Steps and gates

```yaml
# examples/acme-corp/rollouts/opus-5-5-upgrade.yaml (excerpt)
kind: Rollout
name: opus-5-5-upgrade
axis: traffic
status: active                # draft | active | paused | aborted | completed
step: canary-5                # live step, set by merged advance PRs
experiment: opus-5-5-canary   # two arms: exposure, evidence, kill switch
change: {alias: opus}
steps:
  - name: dark-launch
    strategy: dark-launch
    percent: 10
    bake: 2d                  # Go duration or Nd
    minSamples: 500           # per arm
    gates:
      guardrails: [{metric: halo.latency.p95_ms, direction: decrease, maxRegression: 0.15}]
      scorecard: {file: evals/opus-5-5.scorecard.json, variant: opus-5-5, minPass1: 0.75, maxRegression: 0.01}
    onFailure: pause          # rollback (default) | pause
  - name: canary-50
    strategy: canary
    percent: 50
    bake: 1d
    minSamples: 4000
    gates:
      guardrails:
        - {metric: halo.api.error_rate, direction: decrease, maxRegression: 0.05}
        - {metric: halo.latency.p95_ms, direction: decrease, maxRegression: 0.15}
      approval: true
```

All gates must pass before a step advances:

- **bake** and **samples**: time in the step, and per-arm samples, reach their minimums.
- **guardrails**: the experiment's arms compared with the `internal/stats` sequential test. A confident regression past `maxRegression` fails; an inconclusive one stays pending.
- **scorecard**: a `halo eval run --output json` scorecard. It fails when the variant's pass@1 is under `minPass1`, the comparison is significantly worse or drops more than `maxRegression`, or `comparisons[variant].gate.verdict` is **block**. **hold** keeps the gate pending; **ship** passes.
- **approval**: the step waits until a human runs `halo rollout advance`.

## The controller loop

`rollout.Evaluate` is pure and deterministic: rollout, state, evidence and time in, one decision out (`advance`, `hold`, `rollback`, `pause`, `complete`). The controller acts on that decision asymmetrically:

1. **A failed gate acts immediately**, before bake or samples finish. `rollback` on a traffic-axis rollout trips the experiment's signed kill switch, so gateways send everyone to control. It only does that when the breach comes from gateway-sourced evidence; CLI-reported metrics or a scorecard never auto-kill. `pause` stops further steps without changing exposure. Both open a PR that records the halt, and the rollout holds until the policy leaves `active`.
2. **Advance and complete only open a PR**, once per step. A merged PR moves `step:`; the controller never merges.

State lives in `<data-dir>/rollouts/<name>.json`. The step, entry time and halt are derived by replaying a **hash-chained history**: each entry is a sha256 over its fields and the previous hash. A partially edited file fails verification and is rejected. The chain is unkeyed, so it detects edits, not a complete rewrite of the file: protect the data dir. Actions carry idempotency keys per step, so a retried tick does not open a second PR or trip the kill twice.

## Plan it

```console
$ halo rollout plan opus-5-5-upgrade --policy-dir examples/acme-corp
Rollout opus-5-5-upgrade  (traffic axis, active)
Change:     gateway alias opus -> treatment route of experiment opus-5-5-canary
Experiment: opus-5-5-canary

  #  START    STEP         STRATEGY     TREATMENT          EXPOSURE                                            BAKE  MIN N  GATES                                                                   ON FAIL
  1  T+0      dark-launch  dark-launch  [#.........]  10%  10% of ring1-canary requests mirrored, none served  2d    500    latency.p50_ms<=10%, latency.p95_ms<=15%, eval:opus-5-5                 pause
  2  T+2d     canary-1     canary       [#.........]   1%  1% of ring1-canary on treatment                     6h    200    latency.p50_ms<=10%, latency.p95_ms<=15%, api.error_rate<=5%            rollback
> 3  T+2d6h   canary-5     canary       [#.........]   5%  5% of ring1-canary on treatment                     12h   500    latency.p50_ms<=10%, latency.p95_ms<=15%, api.error_rate<=5%            rollback
  4  T+2d18h  canary-25    canary       [###.......]  25%  25% of ring1-canary on treatment                    1d    2000   latency.p50_ms<=10%, latency.p95_ms<=15%, api.error_rate<=5%            rollback
  5  T+3d18h  canary-50    canary       [#####.....]  50%  50% of ring1-canary on treatment                    1d    4000   latency.p50_ms<=10%, latency.p95_ms<=15%, api.error_rate<=5%, approval  rollback
  6  T+4d18h  holdout      holdout      [##########]  95%  5% of ring1-canary held on control                  14d   1000   latency.p50_ms<=10%, latency.p95_ms<=15%, api.error_rate<=5%, approval  rollback

Earliest completion: T+18d18h (sum of bakes; samples and approvals add time). Every step is a PR a human merges.
On completion: gateway.models.opus has failover targets: re-point it to orchestrator/arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/z9w5opus55dd by hand in this PR
```

The GATES column is what each step is judged on: the backing experiment's guardrails (here `latency.p50_ms` and `latency.p95_ms`), each overridden by the step's own guardrail on the same metric, plus the step's other guardrails. An active rollout owns its experiment, so dropping the experiment's guardrails would silently disable their auto-rollback. Shadow-only metrics count only on a dark-launch step.

## Rehearse a regression

```console
$ halo rollout simulate opus-5-5-upgrade --scenario regression --policy-dir examples/acme-corp
Simulating opus-5-5-upgrade (scenario regression, tick 1h, 1000 users/h, seed 1; PRs assumed merged at once)

AT       STEP         DECISION  WHY
T+0      -            advance   not started: propose step dark-launch
T+1h     dark-launch  hold      bake: baking, 1d23h left; samples: 100/100 of 500 per arm; guardrail:halo.latency.p50_ms: inconclusive, upp...
T+5h     dark-launch  hold      bake: baking, 1d19h left
T+2d     dark-launch  advance   all gates passed: propose step canary-1
T+2d1h   canary-1     hold      bake: baking, 5h left; samples: 990/10 of 200 per arm; guardrail:halo.latency.p50_ms: inconclusive, upper b...
T+2d6h   canary-1     hold      samples: 5940/60 of 200 per arm; guardrail:halo.latency.p50_ms: inconclusive, upper bound +34.1% vs limit 1...
T+2d20h  canary-1     rollback  guardrail:halo.latency.p50_ms failed: +21.3% [+14.8%, +27.9%] (threshold regression <= 10.0%)

Outcome: rollback after 2d20h
```

`simulate` runs the same state machine on synthetic evidence (or recorded evidence) and writes nothing. In `regression`, the first guardrail is twice its limit worse from `--breach-step` on (default: the second guardrailed step).

## Commands

| Command | Does |
|---|---|
| `halo rollout list` / `plan` / `status` | Steps and timeline; live gate values vs thresholds and the next action |
| `halo rollout simulate --scenario healthy\|regression` | Rehearse the state machine; writes nothing |
| `halo rollout advance` | Open the PR for the next step, or completion. Counts as the approval gate |
| `halo rollout pause` / `rollback` | Open a PR pausing, or aborting (experiment paused, rings back on `baseline.release`) |

Related: [experiments](/halos/concepts/experiments/), [rings and releases](/halos/concepts/rings-and-releases/), [evals](/halos/concepts/evals/), [toggles](/halos/concepts/toggles/).
