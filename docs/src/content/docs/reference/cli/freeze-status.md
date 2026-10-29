---
title: "halo freeze status"
description: "Show which rings are frozen now (or --at), why, and when each opens"
---

Show which rings are frozen now (or --at), why, and when each opens

## Usage

```console
halo freeze status [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--at` |  | string |  | evaluate at this RFC 3339 time instead of now (planning; policy windows only) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--ring` |  | string |  | only this ring (default: every ring) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) to include the incident freeze; session from HALO_SESSION |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo freeze`](/halos/reference/cli/freeze/)
