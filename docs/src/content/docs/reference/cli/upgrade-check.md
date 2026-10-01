---
title: "halo upgrade check"
description: "Check once for new CLI versions and models"
---

Check once for new CLI versions and models

## Usage

```console
halo upgrade check [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--config` |  | string |  | watcher config (default &lt;policy-dir>/.halos/upgrade.yaml) |
| `--dry-run` |  | bool | false | only report candidates: no eval, no branch, no PR |
| `--local` |  | bool | false | run evals on the host instead of Docker (no isolation; testing only) |
| `--npm-registry` |  | string |  | npm registry base URL (default https://registry.npmjs.org) |
| `--parallel` |  | int | 2 | concurrent eval trials |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo upgrade`](/halos/reference/cli/upgrade/)
