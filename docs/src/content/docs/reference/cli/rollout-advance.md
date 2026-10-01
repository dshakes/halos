---
title: "halo rollout advance"
description: "Open a PR moving the rollout to its next step (or completing it); never merges"
---

Open a PR moving the rollout to its next step (or completing it); never merges

You are the approval: the PR is opened even with pending gates (listed in its body), but not when a
gate has failed unless --force. Without --data-dir/--clickhouse, bake and metric gates show as unknown.

## Usage

```console
halo rollout advance <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--base` |  | string |  | PR base branch |
| `--clickhouse` |  | string |  | ClickHouse HTTP URL for metric gates (optional) |
| `--data-dir` |  | string |  | controller data dir: read &lt;data-dir>/rollouts/&lt;name>.json for step entry time and history |
| `--database` |  | string |  | ClickHouse database |
| `--dry-run` |  | bool | false | print the patch instead of opening a PR |
| `--force` |  | bool | false | advance even though a gate failed |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--reason` |  | string |  | why (required; recorded in the commit message and PR body) |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo rollout`](/halos/reference/cli/rollout/)
