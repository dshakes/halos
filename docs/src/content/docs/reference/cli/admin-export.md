---
title: "halo admin export"
description: "Write the console artifacts and manual steps for every vendorAdmin vendor"
---

Write the console artifacts and manual steps for every vendorAdmin vendor

Writes &lt;out>/&lt;vendor>/ with the artifacts an admin pastes into a console that has no write API (Claude managed settings JSON, Codex requirements and config TOML, the Cursor model list) and a STEPS.md with the manual steps, the read-only settings and every warning. Reads no console.

## Usage

```console
halo admin export [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--out` |  | string | vendor-admin | output directory |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo admin`](/halos/reference/cli/admin/)
