---
title: "halo eval online"
description: "Grade sampled halo-shadow pairs with the judge rubric; emit halo.eval.* metrics and append history"
---

Grade sampled halo-shadow pairs with the judge rubric; emit halo.eval.* metrics and append history

## Usage

```console
halo eval online [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--experiment` |  | string |  | only this experiment |
| `--history` |  | string |  | scorecard history JSONL: skip already-graded pairs and append results |
| `--judge-cache` |  | string |  | directory caching judge verdicts |
| `--judge-key-env` |  | string |  | env var holding the gateway credential |
| `--judge-model` |  | string |  | pinned judge model id (required) |
| `--judge-url` |  | string |  | gateway base URL for the judge (required) |
| `--judge-wire` |  | string | anthropic-messages | judge wire: anthropic-messages \| openai-responses |
| `--otlp` |  | string |  | OTel collector OTLP/HTTP base URL for halo.eval.* metrics: the eval receiver (collector-config --eval-receiver, :4320) |
| `--otlp-token-file` |  | string |  | bearer token file for the collector's eval receiver (HALO_OTLP_EVAL_TOKEN); never the gateway token, which would let eval jobs write trusted gateway evidence |
| `--pair-key-file` |  | stringSlice | [] | base64 32-byte pair key (repeatable: current and retired) |
| `--pairs` |  | string |  | halo-shadow pair store (JSONL) (required) |
| `--policy-dir` |  | string |  | policy repo: labels each experiment's control arm with its control variant name, so `halo exp analyze` matches the arms (default label: control) |
| `--rubric` |  | string |  | rubric YAML (required) |
| `--sample` |  | int | 50 | max pairs graded per experiment (0 = all) |
| `--seed` |  | uint64 | 1 | sampling and bootstrap seed |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo eval`](/halos/reference/cli/eval/)
