---
title: "halo toggle kill"
description: "Kill a toggle fleet-wide via halo-server (off everywhere at the next poll)"
---

Kill a toggle fleet-wide via halo-server (off everywhere at the next poll)

## Usage

```console
halo toggle kill <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--reason` |  | string |  | why; recorded in the audit log (required to kill) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) |
| `--unkill` |  | bool | false | clear the kill instead |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo toggle`](/halos/reference/cli/toggle/)
