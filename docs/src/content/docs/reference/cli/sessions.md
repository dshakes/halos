---
title: "halo sessions"
description: "Agent session ledger: one identity-linked record per agent session (ADR-0031)"
---

Agent session ledger: one identity-linked record per agent session (ADR-0031)

## Usage

```console
halo sessions
```

## Flags

None.

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Commands

| Command | Description |
|---|---|
| [`halo sessions export`](/halos/reference/cli/sessions-export/) | Export ledger sessions as JSONL, one stored record per line (halo-server, audit role) |
| [`halo sessions import`](/halos/reference/cli/sessions-import/) | Read sessions from evidence sources, normalize and redact them, and store them in halo-server's ledger |
| [`halo sessions list`](/halos/reference/cli/sessions-list/) | List ledger sessions, newest first (halo-server, audit role) |
| [`halo sessions show`](/halos/reference/cli/sessions-show/) | Show one ledger session with its audit chain position (halo-server, audit role) |

## Parent

[`halo`](/halos/reference/cli/)
