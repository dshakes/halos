---
title: "halo freeze off"
description: "Lift the incident freeze on halo-server (admin)"
---

Lift the incident freeze on halo-server (admin)

## Usage

```console
halo freeze off [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--reason` |  | string |  | why (required; recorded in the audit log) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) ; session from HALO_SESSION |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo freeze`](/halos/reference/cli/freeze/)
