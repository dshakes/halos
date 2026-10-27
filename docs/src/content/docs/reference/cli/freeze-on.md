---
title: "halo freeze on"
description: "Set the incident freeze on halo-server: no rollout advances or promotions until lifted (admin)"
---

Set the incident freeze on halo-server: no rollout advances or promotions until lifted (admin)

## Usage

```console
halo freeze on [flags]
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
