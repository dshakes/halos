---
title: "halo doctor"
description: "Check this machine and the policy repo; print the exact fix for each problem"
---

Check this machine and the policy repo; print the exact fix for each problem

Detects the AI CLIs on PATH and their versions, the tools onboarding uses, which credential
variables are set (never their values), whether the policy validates, whether the pinned CLI
versions match, and whether the gateway answers. Exits 1 when a check fails.

## Usage

```console
halo doctor [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
