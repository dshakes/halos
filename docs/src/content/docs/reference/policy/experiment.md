---
title: "Experiment"
description: "An A/B, canary or shadow experiment with sticky per-user assignment."
---

An A/B, canary or shadow experiment with sticky per-user assignment.

Generated from `schemas/experiment.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1 |  | Document version. |
| `axis` | string | yes |  | client, traffic |  | Where variants differ: client (profiles) or traffic (model routes). Shadow must be traffic. |
| `kind` | string | yes |  | const Experiment |  | Document kind. |
| `labels` | object |  |  |  |  | Free-form labels. |
| `labels.*` | string |  |  |  |  |  |
| `metrics` | object | yes |  |  |  | Metrics. |
| `metrics.guardrails` | array of object |  |  |  |  | Metrics that abort the experiment on regression. |
| `metrics.guardrails[]` | object |  |  |  |  | A metric objective. |
| `metrics.guardrails[].direction` | string | yes |  | increase, decrease |  | Which direction is better. |
| `metrics.guardrails[].maxRegression` | number |  |  |  | minimum 0 | Guardrails: relative worsening that aborts, e.g. 0.05 = 5%. |
| `metrics.guardrails[].metric` | string | yes |  |  | pattern ^halo\.[a-z0-9_.]+$ | Normalised halo.* metric name (see internal/policy MetricRegistry). |
| `metrics.primary` | object | yes |  |  |  | A metric objective. |
| `metrics.primary.direction` | string | yes |  | increase, decrease |  | Which direction is better. |
| `metrics.primary.maxRegression` | number |  |  |  | minimum 0 | Guardrails: relative worsening that aborts, e.g. 0.05 = 5%. |
| `metrics.primary.metric` | string | yes |  |  | pattern ^halo\.[a-z0-9_.]+$ | Normalised halo.* metric name (see internal/policy MetricRegistry). |
| `name` | string | yes |  |  | pattern ^[a-z0-9][a-zA-Z0-9._-]*$ | Unique name within its kind. |
| `rings` | array of string | yes |  |  | minItems 1 | Rings the experiment draws users from. |
| `rings[]` | string |  |  |  |  |  |
| `salt` | string |  |  |  |  | Keeps assignment independent across experiments; defaults to name. |
| `sampleRate` | number |  |  |  | maximum 1 | Shadow only: fraction of eligible requests mirrored, in (0,1]. |
| `status` | string |  |  | draft, running, paused, concluded |  | Lifecycle state; only running experiments assign users. |
| `stopping` | object | yes |  |  |  | Stopping rule. |
| `stopping.alpha` | number |  |  |  |  | Significance level in (0,1). |
| `stopping.maxDays` | integer |  |  |  | minimum 0 | Maximum duration. |
| `stopping.maxSpendUSD` | number |  |  |  | minimum 0 | Maximum spend. |
| `stopping.method` | string | yes |  | msprt, fixed |  | Stopping rule. |
| `stopping.minSamples` | integer |  |  |  | minimum 0 | Minimum samples before a decision. |
| `type` | string | yes |  | ab, canary, shadow |  | How users are exposed. |
| `variants` | array of object | yes |  |  | minItems 1 | Experiment arms. |
| `variants[]` | object |  |  |  |  | An experiment arm. |
| `variants[].control` | boolean |  |  |  |  | Marks the control variant (exactly one for ab/canary). |
| `variants[].name` | string | yes |  |  |  | Variant name, unique within the experiment. |
| `variants[].profile` | string |  |  |  |  | Client axis: profile to apply. |
| `variants[].routes` | object |  |  |  |  | Traffic axis: model alias -> route override. |
| `variants[].routes.*` | object |  |  |  |  | Upstream target for a model alias. |
| `variants[].routes.*.model` | string | yes |  |  |  | Provider model id or Bedrock inference profile ARN. |
| `variants[].routes.*.upstream` | string | yes |  |  |  | Name of an entry in gateway.upstreams. |
| `variants[].weight` | number | yes |  |  |  | Share of users (normalised); must be > 0. |
