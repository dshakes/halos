---
title: "halo copilot experiment"
description: "Design an experiment: arms and metrics proposed, sample size and duration computed by internal/stats"
---

Design an experiment: arms and metrics proposed, sample size and duration computed by internal/stats

## Usage

```console
halo copilot experiment <hypothesis> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--alpha` |  | float64 | 0.05 | significance level |
| `--api-key-env` |  | string | ANTHROPIC_API_KEY | env var holding the provider credential (never printed) |
| `--apply` |  | bool | false | commit the experiment (status draft) to a new local halos/copilot-* branch (never pushes) |
| `--axis` |  | string | client | offline: client \| traffic |
| `--baseline` |  | float64 | 0 | current mean of the primary metric (required) |
| `--control` |  | string |  | offline: control profile |
| `--daily-units` |  | float64 | 0 | users entering the experiment per day (for the duration) |
| `--debug` |  | bool | false | log prompts and replies to stderr (default: token counts only) |
| `--direction` |  | string | increase | offline: increase \| decrease |
| `--llm-url` |  | string |  | provider or gateway base URL (default: the policy's gateway baseURL, e.g. a halo-proxy, else https://api.anthropic.com) |
| `--max-cost-usd` |  | float64 | 2 | estimated spend per run in USD (hard ceiling) |
| `--max-iterations` |  | int | 3 | model calls per run (hard ceiling) |
| `--max-tokens` |  | int | 60000 | input+output tokens per run (hard ceiling) |
| `--mde` |  | float64 | 0.05 | relative minimum detectable effect (0.05 = 5%) |
| `--metric` |  | string |  | offline: primary halo.* metric |
| `--model` |  | string | claude-opus-5-5 | pinned model id |
| `--name` |  | string |  | offline: experiment name |
| `--offline` |  | bool | false | deterministic templates, no model call (air-gapped, tests) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--power` |  | float64 | 0.8 | statistical power |
| `--price-in` |  | float64 | 5 | USD per million input tokens, for the cost estimate |
| `--price-out` |  | float64 | 25 | USD per million output tokens, for the cost estimate |
| `--ring` |  | string |  | offline: ring to draw users from |
| `--sd` |  | float64 | 0 | per-user standard deviation of the primary metric (default: sqrt(p(1-p)) for a rate) |
| `--treatment` |  | string |  | offline: treatment profile |
| `--wire` |  | string | anthropic-messages | provider wire: anthropic-messages \| openai-responses |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Examples

```console
halo copilot experiment "opus-5-5 raises accept rate without hurting latency" --baseline 0.31 --mde 0.05 --daily-units 400
  halo copilot experiment --offline "cli-next raises accept rate" --name cli-next-accept --ring ring1-canary \
    --control engineering --treatment engineering-next --metric halo.edit.accept_rate --baseline 0.31 --mde 0.05
```

## Parent

[`halo copilot`](/halos/reference/cli/copilot/)
