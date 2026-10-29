---
title: "halo copilot next"
description: "Suggest next steps from experiment verdicts, eval scorecards, ROI and budgets, each with evidence and the command"
---

Suggest next steps from experiment verdicts, eval scorecards, ROI and budgets, each with evidence and the command

Deterministic rules over existing data; no model is called. Commands marked [human gate] change state:
a human runs them.

## Usage

```console
halo copilot next [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--roi` |  | string |  | ROI report JSON (halo roi report --output json) |
| `--scorecard` |  | stringSlice | [] | eval scorecard JSON (repeatable) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) for budget counters; session from HALO_SESSION |
| `--verdicts-file` |  | string |  | verdicts JSON array (halo exp analyze --verdicts-file) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo copilot`](/halos/reference/cli/copilot/)
