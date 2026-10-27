---
title: "halo sessions list"
description: "List ledger sessions, newest first (halo-server, audit role)"
---

List ledger sessions, newest first (halo-server, audit role)

## Usage

```console
halo sessions list [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--harness` |  | string |  | harness, e.g. claude-code, copilot-agent |
| `--limit` |  | int | 100 | at most this many sessions (1..5000) |
| `--ring` |  | string |  | ring |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER); the session cookie comes from HALO_SESSION (audit role) |
| `--since` |  | string |  | sessions started at or after: RFC 3339, a duration back (24h) or days (7d) |
| `--tool` |  | string |  | tool or MCP server used |
| `--until` |  | string |  | sessions started before |
| `--user` |  | string |  | Halos identity, or the vendor identity of an unresolved session |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo sessions`](/halos/reference/cli/sessions/)
