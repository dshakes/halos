---
title: "halo eval run"
description: "Run an eval suite and print the scorecard"
---

Run an eval suite and print the scorecard

## Usage

```console
halo eval run <suite.yaml> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--cpus` |  | string | 2 | docker CPU limit per trial |
| `--fail-on` |  | string | none | exit 3 when the gate verdict is at least: block \| hold \| none |
| `--history` |  | string |  | append a summary line to this scorecard history (JSONL) |
| `--local` |  | bool | false | run on the host instead of Docker (no isolation; testing only) |
| `--matrix` |  | bool | false | run the suite's matrix (harness x model x provider) instead of its variants |
| `--memory` |  | string | 4g | docker memory limit per trial |
| `--network` |  | string | none | docker network for trials (default none: no egress) |
| `--parallel` |  | int | 2 | concurrent trials |
| `--pass-env` |  | stringSlice | [] | host env vars (UPPER_SNAKE) forwarded into the agent step only |
| `--report` |  | string |  | also write the Markdown report (PR-comment ready) to this file |
| `--scorecard` |  | string |  | also write the scorecard JSON to this file |
| `--seed` |  | uint64 | 1 | bootstrap seed (reproducible CIs) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo eval`](/halos/reference/cli/eval/)
