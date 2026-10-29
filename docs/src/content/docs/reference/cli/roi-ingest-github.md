---
title: "halo roi ingest github"
description: "Import pull requests from GitHub (GraphQL, read-only query)"
---

Import pull requests from GitHub (GraphQL, read-only query)

Import pull requests created since --since from each --repo: author, opened/merged times, review rounds (change requests + 1 once reviewed), lines changed, and the change-failure proxy (a merged revert "Reverts owner/repo#N" or a merged PR labelled --hotfix-label that references #N). Titles and bodies are read to find those references but never stored. The token comes only from the variable named by --token-env.

## Usage

```console
halo roi ingest github [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--clickhouse` |  | string |  | ClickHouse HTTP URL (table halo_delivery_prs; AI spend from halo_metrics) |
| `--database` |  | string |  | ClickHouse database |
| `--graphql-url` |  | string | https://api.github.com/graphql | GraphQL endpoint (GitHub Enterprise Server: https://HOST/api/graphql) |
| `--hotfix-label` |  | string | hotfix | label of a hotfix PR; it marks each PR it references (#N) as a change failure |
| `--repo` |  | stringSlice | [] | owner/name (repeatable, required) |
| `--since` |  | string |  | import PRs created at or after this date (YYYY-MM-DD or RFC 3339, required) |
| `--store` |  | string |  | local JSONL store instead of ClickHouse (no AI spend data) |
| `--token-env` |  | string | HALO_GITHUB_TOKEN | environment variable holding a read-only GitHub token |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo roi ingest`](/halos/reference/cli/roi-ingest/)
