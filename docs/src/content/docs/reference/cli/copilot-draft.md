---
title: "halo copilot draft"
description: "Turn an intent into a verified policy diff (validate, plan, impact); --apply commits it to a local branch"
---

Turn an intent into a verified policy diff (validate, plan, impact); --apply commits it to a local branch

## Usage

```console
halo copilot draft <intent> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--api-key-env` |  | string | ANTHROPIC_API_KEY | env var holding the provider credential (never printed) |
| `--apply` |  | bool | false | commit the verified draft to a new local halos/copilot-* branch (never pushes) |
| `--debug` |  | bool | false | log prompts and replies to stderr (default: token counts only) |
| `--dry-run` |  | bool | false | show what would change without writing (the default without --apply) |
| `--llm-url` |  | string |  | provider or gateway base URL (default: the policy's gateway baseURL, e.g. a halo-proxy, else https://api.anthropic.com) |
| `--max-cost-usd` |  | float64 | 2 | estimated spend per run in USD (hard ceiling) |
| `--max-iterations` |  | int | 3 | model calls per run (hard ceiling) |
| `--max-tokens` |  | int | 60000 | input+output tokens per run (hard ceiling) |
| `--model` |  | string | claude-opus-5-5 | pinned model id |
| `--offline` |  | bool | false | deterministic templates, no model call (air-gapped, tests) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--price-in` |  | float64 | 5 | USD per million input tokens, for the cost estimate |
| `--price-out` |  | float64 | 25 | USD per million output tokens, for the cost estimate |
| `--wire` |  | string | anthropic-messages | provider wire: anthropic-messages \| openai-responses |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Examples

```console
halo copilot draft "move ring1-canary to Claude Code 2.1.300"
  halo copilot draft --offline "set claude-code version 2.1.300 in profile engineering" --apply
```

## Parent

[`halo copilot`](/halos/reference/cli/copilot/)
