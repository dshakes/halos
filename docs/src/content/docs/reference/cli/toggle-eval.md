---
title: "halo toggle eval"
description: "Show which toggles are on for a user, and why"
---

Show which toggles are on for a user, and why

## Usage

```console
halo toggle eval [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--groups` |  | string |  | comma-separated IdP groups |
| `--killed` |  | string |  | comma-separated toggle names to treat as killed |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--ring` |  | string |  | ring (default: resolved from the user and groups) |
| `--user` |  | string |  | user id (required) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo toggle`](/halos/reference/cli/toggle/)
