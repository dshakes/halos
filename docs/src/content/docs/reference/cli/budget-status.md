---
title: "halo budget status"
description: "Show spend against each budget in its current window (halo-server, admin)"
---

Show spend against each budget in its current window (halo-server, admin)

## Usage

```console
halo budget status [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--budget` |  | string |  | only this budget |
| `--key` |  | string |  | only this counter, e.g. user:alice@example.com, group:platform, ring:ring1 or org |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo budget`](/halos/reference/cli/budget/)
