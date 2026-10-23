---
title: "halo audit"
description: "Inspect halo-server's hash-chained audit log"
---

Inspect halo-server's hash-chained audit log

## Usage

```console
halo audit
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
| [`halo audit verify`](/halos/reference/cli/audit-verify/) | Verify the audit hash chain across every segment (exit 2 if broken) |

## Parent

[`halo`](/halos/reference/cli/)
