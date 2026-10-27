---
title: "halo roi ingest file"
description: "Import outcomes from a generic CSV/JSONL export (any SCM or tracker)"
---

Import outcomes from a generic CSV/JSONL export (any SCM or tracker)

Each record is one change: repo, number, author (SCM login) or subject (Halos user id), opened_at, merged_at (empty = not merged), review_rounds, additions, deletions, change_failure, bot, source. CSV needs a header row naming those columns; JSONL uses the same keys. Times are RFC 3339 or YYYY-MM-DD.

## Usage

```console
halo roi ingest file <path.csv|path.jsonl>... [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--clickhouse` |  | string |  | ClickHouse HTTP URL (table halo_delivery_prs; AI spend from halo_metrics) |
| `--database` |  | string |  | ClickHouse database |
| `--store` |  | string |  | local JSONL store instead of ClickHouse (no AI spend data) |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo roi ingest`](/halos/reference/cli/roi-ingest/)
