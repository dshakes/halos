---
title: "halo roi report"
description: "Estimate delivery effects per experiment arm (randomized) or compare rings (observational)"
---

Estimate delivery effects per experiment arm (randomized) or compare rings (observational)

Maps PR authors to Halos subjects with --identities (CSV login,subject[,groups][,kind]), recovers each developer's arm with the fleet's own assignment, and estimates per arm: PR cycle time, merged PRs per developer-week, review rounds, change-failure rate and lines changed, with developer-clustered bootstrap CIs, an SRM check, time slices for novelty, and cost per merged PR when ClickHouse has AI spend. Only --experiment is randomized; --rings is labelled observational. Informational: nothing promotes on it.

## Usage

```console
halo roi report [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--clickhouse` |  | string |  | ClickHouse HTTP URL (table halo_delivery_prs; AI spend from halo_metrics) |
| `--database` |  | string |  | ClickHouse database |
| `--experiment` |  | string |  | experiment whose variants are the arms (randomized) |
| `--identities` |  | string |  | identity roster CSV: login,subject[,groups][,kind] (required) |
| `--mde` |  | float64 | 0.1 | relative effect a null result must have been powered to detect |
| `--min-developers` |  | int | 10 | developers with data per arm before a metric is estimated |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--rings` |  | stringSlice | [] | compare rings instead, the first as baseline (observational) |
| `--seed` |  | uint64 | 1 | bootstrap seed (reproducible CIs) |
| `--since` |  | string |  | window start (YYYY-MM-DD or RFC 3339); default: the experiment's first telemetry in ClickHouse |
| `--slices` |  | int | 3 | time slices for the novelty check (&lt; 2 = off) |
| `--store` |  | string |  | local JSONL store instead of ClickHouse (no AI spend data) |
| `--until` |  | string |  | window end (default now) |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo roi`](/halos/reference/cli/roi/)
