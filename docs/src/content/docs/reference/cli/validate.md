---
title: "halo validate"
description: "Load and validate a policy repo (exit 2 on errors)"
---

Load and validate a policy repo (exit 2 on errors)

Also scans the supply-chain artifacts in the policy repo (ADR-0028). Artifacts from git or oci
are fetched, checked and scanned by `halo release build`; validate stays offline.

## Usage

```console
halo validate [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--strict` |  | bool | false | treat supply-chain scan findings as errors (same as supplyChain.scan: enforce) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
