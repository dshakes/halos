---
title: "halo audit verify"
description: "Verify the audit hash chain, its signed checkpoints and an external anchor (exit 2 if broken)"
---

Verify the audit hash chain, its signed checkpoints and an external anchor (exit 2 if broken)

Reads &lt;data-dir>/audit-*.jsonl (rotated segments, oldest first) and then audit.jsonl, and checks
that sequence numbers run without gaps, every entry links to the one before it (across
segment boundaries too) and every hash matches. Read-only: safe against a live halo-server's data dir.
With --database-url-file it reads the Postgres backend's audit table instead (HA, ADR-0021), uncached;
with --file it reads an export as your SIEM received it (native lines, or OCSF events).
Entries an erasure pseudonymised must each be vouched for by a later subject.erase entry, and a
chain that retention shortened must start where an audit.retention entry says (ADR-0040).
--public-key checks every signed checkpoint (ADR-0041): a chain recomputed after an edit fails at
the first checkpoint after it. With it, only a subject.erase or audit.retention entry signed by the
same key may vouch for a redaction or a cut, and a log with no signed checkpoint fails.
--anchor takes the newest checkpoint from a file your SIEM holds and requires the log to still
contain it unchanged, so entries cut from the end are caught; it compares that one entry only.
--compare-export compares content: every seq the log and the SIEM export both hold.

## Usage

```console
halo audit verify [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--allow-rotation-window` |  | bool | false | with several --public-key: accept a newest checkpoint signed by a previous key (while replicas are switching keys) |
| `--anchor` |  | string |  | file of exported entries (your SIEM's copy); its newest checkpoint must still be in the log, unchanged |
| `--compare-export` |  | string |  | file of exported entries (your SIEM's copy): every seq both hold must match in hash and content, unless the log's entry is a vouched-for redaction, and the log must reach the export's newest seq |
| `--data-dir` |  | string |  | halo-server --data-dir holding audit.jsonl |
| `--database-insecure-tls` |  | bool | false | accept a database URL that does not verify the server certificate and host name (sslmode below verify-full) to a non-loopback host |
| `--database-url-file` |  | string |  | file holding the Postgres URL of an HA halo-server (instead of --data-dir) |
| `--file` |  | string |  | an audit export as a SIEM received it, one entry (or OCSF event) per line (instead of --data-dir) |
| `--max-unsigned-tail` |  | int | -1 | with --public-key: fail when more entries than this follow the last signed checkpoint (-1: no limit) |
| `--public-key` |  | stringArray | [] | PEM public key of halo-server's --audit-signing-key-uri: check every checkpoint signature (ADR-0041); repeat it for keys the current one replaced, the current key first |
| `--strict` |  | bool | false | fail unless --public-key and an external anchor (--anchor or --compare-export) are given: the only combination that also catches deletion (recommended on a schedule) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo audit`](/halos/reference/cli/audit/)
