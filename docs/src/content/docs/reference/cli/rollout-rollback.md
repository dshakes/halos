---
title: "halo rollout rollback"
description: "Open a PR aborting the rollout: experiment paused, rings back on baseline.release"
---

Open a PR aborting the rollout: experiment paused, rings back on baseline.release

## Usage

```console
halo rollout rollback <name> [flags]
```

Aliases: `abort`

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--base` |  | string |  | PR base branch |
| `--dry-run` |  | bool | false | print the patch instead of opening a PR |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--reason` |  | string |  | why (required; recorded in the commit message and PR body) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo rollout`](/halos/reference/cli/rollout/)
