---
title: "halo model switch"
description: "Point an alias at a model: in place, or with --canary as a guardrailed traffic rollout"
---

Point an alias at a model: in place, or with --canary as a guardrailed traffic rollout

&lt;model> is a provider model id, optionally prefixed &lt;provider>/ (e.g. bedrock/anthropic.claude-opus-4-1).
Without --canary the route is edited in place (halos.yaml models.&lt;alias> in simple mode).
With --canary it writes a traffic-axis Rollout from the rollout preset plus its experiment.

## Usage

```console
halo model switch <alias> <model> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--canary` |  | bool | false | roll out as a guardrailed canary instead of switching at once |
| `--dry-run` |  | bool | false | print the diff instead of writing |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo model`](/halos/reference/cli/model/)
