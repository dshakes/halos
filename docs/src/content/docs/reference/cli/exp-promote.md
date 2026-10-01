---
title: "halo exp promote"
description: "Open a PR pointing --ring at --release (never merges); requires a promote verdict"
---

Open a PR pointing --ring at --release (never merges); requires a promote verdict

## Usage

```console
halo exp promote <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--base` |  | string |  | PR base branch |
| `--clickhouse` |  | string |  | ClickHouse HTTP URL, e.g. http://localhost:8123 (required) |
| `--database` |  | string |  | ClickHouse database |
| `--dry-run` |  | bool | false | print the patch instead of opening a PR |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--release` |  | string |  | release digest to pin (required) |
| `--ring` |  | string |  | ring to re-point (required) |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo exp`](/halos/reference/cli/exp/)
