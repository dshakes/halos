---
title: "halo mcp serve"
description: "Serve Halos tools, resources and prompts over stdio MCP"
---

Serve Halos tools, resources and prompts over stdio MCP

Serve Halos over stdio MCP. Read-only tools are always on. --allow-writes adds experiment and proposal tools (dry_run by default, reason required). --server (or HALO_SERVER) plus HALO_TOKEN (an admin service-account token) or an admin HALO_SESSION enables the fleet tools (kill switch, audit, devices). --admin-read lets admin_plan read the vendor consoles with HALO_MCP_ADMIN_&lt;VENDOR>_TOKEN; without it admin_plan renders from policy only. --roi-identities enables roi_report (delivery ROI, read-only). No tool publishes releases, retags rings, merges or pushes.

## Usage

```console
halo mcp serve [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--admin-read` |  | bool | false | let admin_plan read the live vendor consoles with HALO_MCP_ADMIN_&lt;VENDOR>_TOKEN (default: render from policy only) |
| `--allow-writes` |  | bool | false | expose write tools (experiment status, promotion/rollback proposals) |
| `--clickhouse` |  | string |  | ClickHouse HTTP URL; enables analyze_experiment |
| `--database` |  | string |  | ClickHouse database |
| `--policy-dir` |  | string | . | policy repo directory |
| `--roi-identities` |  | string |  | identity roster CSV (login,subject[,groups][,kind]); enables roi_report and the ROI section of promotion PRs |
| `--roi-store` |  | string |  | local JSONL store of PR outcomes (halo roi ingest --store); default: ClickHouse |
| `--schema-dir` |  | string |  | JSON Schema directory (default: auto-detect) |
| `--server` |  | string |  | halo-server base URL for the fleet tools (or HALO_SERVER); admin credential from HALO_TOKEN or HALO_SESSION |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo mcp`](/halos/reference/cli/mcp/)
