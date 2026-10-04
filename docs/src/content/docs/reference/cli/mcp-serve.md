---
title: "halo mcp serve"
description: "Serve Halos tools, resources and prompts over stdio MCP"
---

Serve Halos tools, resources and prompts over stdio MCP

Serve Halos over stdio MCP. Read-only tools are always on. --allow-writes adds experiment and proposal tools (dry_run by default, reason required). --server (or HALO_SERVER) plus an admin HALO_SESSION enables the fleet tools (kill switch, audit, devices). No tool publishes releases, retags rings, merges or pushes.

## Usage

```console
halo mcp serve [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--allow-writes` |  | bool | false | expose write tools (experiment status, promotion/rollback proposals) |
| `--clickhouse` |  | string |  | ClickHouse HTTP URL; enables analyze_experiment |
| `--database` |  | string |  | ClickHouse database |
| `--policy-dir` |  | string | . | policy repo directory |
| `--schema-dir` |  | string |  | JSON Schema directory (default: auto-detect) |
| `--server` |  | string |  | halo-server base URL for the fleet tools (or HALO_SERVER); admin session from HALO_SESSION |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo mcp`](/halos/reference/cli/mcp/)
