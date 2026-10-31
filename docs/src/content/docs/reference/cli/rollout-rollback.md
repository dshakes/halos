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
| `--forge` |  | string |  | where to open the change request: gh\|github\|gitlab (default: autodetect from the origin remote; gh unless the host names gitlab); github/gitlab use the REST API with GITHUB_TOKEN/GH_TOKEN or GITLAB_TOKEN |
| `--forge-base-url` |  | string |  | REST API root for GitHub Enterprise Server (https://ghe.example.com/api/v3) or self-managed GitLab (https://gitlab.example.com/api/v4); default derived from the origin remote |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--reason` |  | string |  | why (required; recorded in the commit message and PR body) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo rollout`](/halos/reference/cli/rollout/)
