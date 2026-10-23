---
title: "halo eval steps run"
description: "Replay each harvested step against a model route and score the next action (deterministic matcher, session-clustered CIs)"
---

Replay each harvested step against a model route and score the next action (deterministic matcher, session-clustered CIs)

## Usage

```console
halo eval steps run [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--judge-key-env` |  | string |  | env var holding the judge's gateway credential |
| `--judge-model` |  | string |  | pinned judge model id (with --rubric) |
| `--judge-url` |  | string |  | gateway base URL for the judge (with --rubric) |
| `--judge-wire` |  | string | anthropic-messages | judge wire: anthropic-messages \| openai-responses |
| `--key-env` |  | string |  | env var holding the credential (x-api-key, x-goog-api-key or Bearer, by wire) |
| `--model` |  | string |  | model route: a gateway model alias, or an upstream model id (required) |
| `--parallel` |  | int | 4 | concurrent model calls |
| `--rubric` |  | string |  | optional rubric YAML: a secondary judge score per step (never changes pass) |
| `--scorecard` |  | string |  | also write the scorecard JSON to this file |
| `--seed` |  | uint64 | 1 | bootstrap seed (reproducible CIs) |
| `--suite` |  | string |  | directory of harvested step cases (required) |
| `--url` |  | string |  | gateway (or upstream) base URL; https, or http to loopback (required) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo eval steps`](/halos/reference/cli/eval-steps/)
