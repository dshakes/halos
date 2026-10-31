---
title: "halo service-token revoke"
description: "Revoke a service-account token at once, on every replica"
---

Revoke a service-account token at once, on every replica

## Usage

```console
halo service-token revoke <id> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--reason` |  | string |  | why; recorded in the audit log (required) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER); credential from HALO_TOKEN or HALO_SESSION (admin) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo service-token`](/halos/reference/cli/service-token/)
