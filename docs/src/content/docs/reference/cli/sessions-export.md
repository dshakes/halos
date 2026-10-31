---
title: "halo sessions export"
description: "Export ledger sessions as JSONL, one stored record per line (halo-server, audit role)"
---

Export ledger sessions as JSONL, one stored record per line (halo-server, audit role)

Writes the matching sessions as JSONL (each line a record with its auditSeq and auditHash), newest first. For continuous delivery to a SIEM use the audit export (ADR-0016): every ledger record is an audit entry with action session.record. Exits 1 when the audit chain does not verify, after writing.

## Usage

```console
halo sessions export [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--harness` |  | string |  | harness, e.g. claude-code, copilot-agent |
| `--limit` |  | int | 5000 | at most this many sessions (1..5000) |
| `--out` |  | string |  | file to write (default stdout) |
| `--ring` |  | string |  | ring |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER); the credential comes from HALO_TOKEN or HALO_SESSION (audit role) |
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
