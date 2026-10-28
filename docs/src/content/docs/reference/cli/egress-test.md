---
title: "halo egress test"
description: "Say whether a ring's policy allows a host, by which rule, and which harness enforces it"
---

Say whether a ring's policy allows a host, by which rule, and which harness enforces it

Resolves the ring's profile (and --unit's overlays), decides the host against egress
(deny rules win, then the allowlist and presets, then the default) and lists, per harness the
profile enables, the native mechanism that enforces the decision and what it cannot hold.
Exits 1 when the host is denied.

## Usage

```console
halo egress test <url|host> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--os` |  | string | host OS | target OS for the per-harness rendering: darwin\|linux\|windows |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--ring` |  | string |  | ring whose profile decides (required) |
| `--unit` |  | string |  | org unit whose overlays apply (ADR-0018) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo egress`](/halos/reference/cli/egress/)
