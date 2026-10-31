---
title: "halo rollout status"
description: "Show the live step, gate values vs thresholds and the next action"
---

Show the live step, gate values vs thresholds and the next action

## Usage

```console
halo rollout status <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--clickhouse` |  | string |  | ClickHouse HTTP URL for metric gates (optional) |
| `--data-dir` |  | string |  | controller data dir: read &lt;data-dir>/rollouts/&lt;name>.json for step entry time and history |
| `--database` |  | string |  | ClickHouse database |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) for the incident freeze and step approvals (ADR-0030); credential from HALO_TOKEN or HALO_SESSION |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo rollout`](/halos/reference/cli/rollout/)
