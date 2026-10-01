---
title: "halo rollout pause"
description: "Open a PR pausing the rollout (exposure stays; no further steps)"
---

Open a PR pausing the rollout (exposure stays; no further steps)

## Usage

```console
halo rollout pause <name> [flags]
```

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
