---
title: "halo exp analyze"
description: "Evaluate experiment evidence from ClickHouse (promote|rollback|continue|expired)"
---

Evaluate experiment evidence from ClickHouse (promote|rollback|continue|expired)

## Usage

```console
halo exp analyze <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--clickhouse` |  | string |  | ClickHouse HTTP URL, e.g. http://localhost:8123 (required) |
| `--database` |  | string |  | ClickHouse database |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |
| `--verdicts-file` |  | string |  | upsert this verdict into a JSON array file read by halo-server |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo exp`](/halos/reference/cli/exp/)
