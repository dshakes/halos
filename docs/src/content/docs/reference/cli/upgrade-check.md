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
| `--forge` |  | string |  | where to open the change request: gh\|github\|gitlab (default: autodetect from the origin remote; gh unless the host names gitlab); github/gitlab use the REST API with GITHUB_TOKEN/GH_TOKEN or GITLAB_TOKEN |
| `--forge-base-url` |  | string |  | REST API root for GitHub Enterprise Server (https://ghe.example.com/api/v3) or self-managed GitLab (https://gitlab.example.com/api/v4); default derived from the origin remote |
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
