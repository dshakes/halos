---
title: "halo explain"
description: "Print the full low-level policy halos.yaml expands to, or with --user one user's effective config and which layer set each field"
---

Print the full low-level policy halos.yaml expands to, or with --user one user's effective config and which layer set each field

## Usage

```console
halo explain [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--groups` |  | string |  | comma-separated IdP groups of --user |
| `--kind` |  | string |  | only this kind (Gateway, Profile, Ring, Experiment, Toggle, Rollout, Unit) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--user` |  | string |  | explain this user's effective config (ring, variant, unit) with the layer that set each field |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
