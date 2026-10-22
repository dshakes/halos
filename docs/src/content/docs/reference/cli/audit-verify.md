---
title: "halo audit verify"
description: "Verify the audit hash chain across every segment (exit 2 if broken)"
---

Verify the audit hash chain across every segment (exit 2 if broken)

Reads &lt;data-dir>/audit-*.jsonl (rotated segments, oldest first) and then audit.jsonl, and checks
that sequence numbers run from 1 without gaps, every entry links to the one before it (across
segment boundaries too) and every hash matches. Read-only: safe against a live halo-server's data dir.
With --database-url-file it reads the Postgres backend's audit table instead (HA, ADR-0021), uncached.
Entries cut from the end leave a valid chain; compare the head with the newest hash your SIEM holds.

## Usage

```console
halo audit verify [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--data-dir` |  | string |  | halo-server --data-dir holding audit.jsonl |
| `--database-insecure-tls` |  | bool | false | accept a database URL that does not verify the server certificate and host name (sslmode below verify-full) to a non-loopback host |
| `--database-url-file` |  | string |  | file holding the Postgres URL of an HA halo-server (instead of --data-dir) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo audit`](/halos/reference/cli/audit/)
