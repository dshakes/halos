---
title: "Rollout"
description: "A phased rollout of one change: ordered steps with a ring, percent, bake, gates and a failure action. Advancing only opens a PR; rollback and pause are automatic."
---

A phased rollout of one change: ordered steps with a ring, percent, bake, gates and a failure action. Advancing only opens a PR; rollback and pause are automatic.

Generated from `schemas/rollout.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1alpha1 |  | Document version. |
| `axis` | string | yes |  | client, traffic |  | client: a release digest moves through rings; traffic: a gateway model route. |
| `baseline` | object |  |  |  |  | Known-good state a rollback returns to. |
| `baseline.release` | string |  |  |  |  | Client axis: switch-back release digest. |
| `change` | object | yes |  |  |  | What rolls out. |
| `change.alias` | string |  |  |  |  | Traffic axis: gateway model alias re-routed to the treatment's route on completion. |
| `change.release` | string |  |  |  |  | Client axis: release digest the ring pointers move to. |
| `change.version` | string |  |  |  |  | Client axis: human label of the release. |
| `experiment` | string |  |  |  |  | Backing two-arm experiment (exposure, evidence, kill switch). Optional when every step is progressive or blue-green. |
| `kind` | string | yes |  | const Rollout |  | Document kind. |
| `labels` | object |  |  |  |  | Free-form labels. |
| `labels.*` | string |  |  |  |  |  |
| `name` | string | yes |  |  | pattern ^[a-z0-9][a-z0-9._-]&#123;0,62}$ | Unique name within its kind. |
| `status` | string |  |  | draft, active, paused, aborted, completed |  | Only active rollouts are driven by the controller. |
| `step` | string |  |  |  |  | The live step, set by merged advance PRs; empty = not started. |
| `steps` | array of object | yes |  |  | minItems 1 | Ordered steps. |
| `steps[]` | object |  |  |  |  | One phase of the rollout. |
| `steps[].bake` | string |  |  |  | pattern ^([0-9]+d\|([0-9]+(\.[0-9]+)?(ns\|us\|µs\|ms\|s\|m\|h))+)$ | Minimum time at this step: a Go duration (30m, 24h) or whole days (14d). |
| `steps[].gates` | object |  |  |  |  | All must pass before the step advances. |
| `steps[].gates.approval` | boolean |  |  |  |  | Hold until a human advances the step. |
| `steps[].gates.guardrails` | array of object |  |  |  |  | Metric guardrails; a breach triggers onFailure at any time. |
| `steps[].gates.guardrails[]` | object |  |  |  |  | A metric guardrail on the backing experiment's arms. |
| `steps[].gates.guardrails[].direction` | string | yes |  | increase, decrease |  | Which direction is better. |
| `steps[].gates.guardrails[].maxRegression` | number |  |  |  | minimum 0 | Relative worsening that fails the gate, e.g. 0.05 = 5%. |
| `steps[].gates.guardrails[].metric` | string | yes |  |  | pattern ^halo\.[a-z0-9_.]+$ | Normalised halo.* metric name (see internal/policy MetricRegistry). |
| `steps[].gates.scorecard` | object |  |  |  |  | Eval scorecard gate (halo eval run --output json). |
| `steps[].gates.scorecard.file` | string | yes |  |  |  | Scorecard JSON, relative to the policy repo. |
| `steps[].gates.scorecard.maxRegression` | number |  |  |  | minimum 0; maximum 1 | Largest allowed pass-rate drop vs the scorecard control (0.02 = 2pp). |
| `steps[].gates.scorecard.minPass1` | number |  |  |  | minimum 0; maximum 1 | Absolute pass@1 floor. |
| `steps[].gates.scorecard.variant` | string | yes |  |  |  | Scorecard variant to judge. |
| `steps[].minSamples` | integer |  |  |  | minimum 0 | Minimum users per arm before the step may advance. |
| `steps[].name` | string | yes |  |  | pattern ^[a-z0-9][a-z0-9._-]&#123;0,62}$ | Step name, unique within the rollout. |
| `steps[].onFailure` | string |  |  | rollback, pause |  | What a gate breach does (default rollback). |
| `steps[].percent` | number |  |  |  | maximum 100 | canary: treatment share; holdout: share kept on control; dark-launch: share of requests mirrored; progressive/blue-green: 100 (default). |
| `steps[].ring` | string |  |  |  |  | Target ring. Required for progressive/blue-green; percent steps expose the backing experiment's rings. |
| `steps[].strategy` | string | yes |  | progressive, canary, blue-green, dark-launch, holdout |  | progressive / blue-green move the ring's release pointer (client axis); canary / holdout set the backing experiment's weights; dark-launch mirrors traffic via halo-shadow (traffic axis). |
