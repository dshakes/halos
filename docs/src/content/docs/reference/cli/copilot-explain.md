---
title: "halo copilot explain"
description: "Explain a release, a policy diff or an experiment in plain language, citing only Halos outputs"
---

Explain a release, a policy diff or an experiment in plain language, citing only Halos outputs

## Usage

```console
halo copilot explain release <ring> | diff <git-ref> | experiment <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--api-key-env` |  | string | ANTHROPIC_API_KEY | env var holding the provider credential (never printed) |
| `--debug` |  | bool | false | log prompts and replies to stderr (default: token counts only) |
| `--diff` |  | string |  | release: git ref of the policy to compare with (default: an empty release) |
| `--llm-url` |  | string |  | provider or gateway base URL (default: the policy's gateway baseURL, e.g. a halo-proxy, else https://api.anthropic.com) |
| `--max-cost-usd` |  | float64 | 2 | estimated spend per run in USD (hard ceiling) |
| `--max-iterations` |  | int | 3 | model calls per run (hard ceiling) |
| `--max-tokens` |  | int | 60000 | input+output tokens per run (hard ceiling) |
| `--model` |  | string | claude-opus-5-5 | pinned model id |
| `--offline` |  | bool | false | deterministic templates, no model call (air-gapped, tests) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--price-in` |  | float64 | 5 | USD per million input tokens, for the cost estimate |
| `--price-out` |  | float64 | 25 | USD per million output tokens, for the cost estimate |
| `--roi` |  | string |  | experiment: ROI report JSON (halo roi report --output json) |
| `--scorecard` |  | string |  | experiment: eval scorecard JSON |
| `--verdicts-file` |  | string |  | experiment: verdicts JSON array (halo exp analyze --verdicts-file) |
| `--wire` |  | string | anthropic-messages | provider wire: anthropic-messages \| openai-responses |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Examples

```console
halo copilot explain diff main
  halo copilot explain release ring1-canary --diff main
  halo copilot explain experiment opus-5-5-canary --verdicts-file verdicts.json --offline
```

## Parent

[`halo copilot`](/halos/reference/cli/copilot/)
