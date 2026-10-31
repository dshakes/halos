---
title: "halo sessions import"
description: "Read sessions from evidence sources, normalize and redact them, and store them in halo-server's ledger"
---

Read sessions from evidence sources, normalize and redact them, and store them in halo-server's ledger

Reads agent sessions from each --source, merges records of the same session, applies the redaction policy (no prompt text is ever read or stored; file paths and repositories are dropped by default, or HMAC-hashed with --paths hash), and posts them to halo-server, which joins each to a Halos identity through its SCIM directory and appends it to the hash-chained audit log (exported to SIEM like any audit entry). Sources: gateway (halo-proxy GenAI spans in ClickHouse), otel (Claude Code OTel events in ClickHouse), anthropic (Compliance API), github (enterprise audit log), jsonl (--file). Vendor credentials come from --&lt;vendor>-token-file or the variable --&lt;vendor>-token-env names (default HALO_SESSIONS_&lt;VENDOR>_TOKEN), never from a flag value, and are never printed. --dry-run prints the normalized records and stores nothing.

## Usage

```console
halo sessions import [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--anthropic-base-url` |  | string |  | anthropic API base URL: https, or http to a loopback host only (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--anthropic-token-env` |  | string | HALO_SESSIONS_ANTHROPIC_TOKEN | environment variable holding the anthropic API credential |
| `--anthropic-token-file` |  | string |  | file holding the anthropic API credential (read once, never logged) |
| `--clickhouse` |  | string |  | ClickHouse HTTP URL for --source gateway\|otel and --write-clickhouse (password from HALO_CLICKHOUSE_PASSWORD) |
| `--clickhouse-user` |  | string |  | ClickHouse user |
| `--database` |  | string | halo | ClickHouse database holding otel_logs, otel_traces and halo_session_ledger |
| `--dry-run` |  | bool | false | print the normalized, redacted records; store nothing |
| `--file` |  | string |  | JSONL file for --source jsonl (- for stdin) |
| `--github-base-url` |  | string |  | github API base URL: https, or http to a loopback host only (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--github-enterprise` |  | string |  | GitHub enterprise slug for --source github |
| `--github-phrase` |  | string |  | audit log search phrase for --source github (default "action:agent_session"; the window is added) |
| `--github-token-env` |  | string | HALO_SESSIONS_GITHUB_TOKEN | environment variable holding the github API credential |
| `--github-token-file` |  | string |  | file holding the github API credential (read once, never logged) |
| `--hash-salt-file` |  | string |  | file holding the HMAC salt for --paths hash (at least 16 bytes; keep it stable to compare across imports) |
| `--paths` |  | string | drop | file and repository redaction: drop (count only) or hash (HMAC-SHA256 with --hash-salt-file) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER); the credential comes from HALO_TOKEN or HALO_SESSION |
| `--since` |  | string | 24h | window start: RFC 3339, a duration back (24h) or days (7d) |
| `--source` |  | stringSlice | [] | evidence source, repeatable: gateway, otel, anthropic, github, jsonl |
| `--until` |  | string |  | window end (default now) |
| `--write-clickhouse` |  | bool | false | also copy the stored records into ClickHouse halo_session_ledger |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo sessions`](/halos/reference/cli/sessions/)
