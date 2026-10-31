---
title: "halo cloud-agents list"
description: "List active and recent cloud agent tasks with policy alerts"
---

List active and recent cloud agent tasks with policy alerts

With --server (or HALO_SERVER) and HALO_SESSION: halo-server's inventory (webhooks and vendor APIs; read permission).
Otherwise reads the vendor APIs directly: GitHub Actions runs of the explicit cloudAgents repos and the
Cursor key's agents, with credentials from --&lt;vendor>-token-file or HALO_CLOUD_&lt;VENDOR>_TOKEN. Exit 2 when
any alert is raised, 1 when a vendor could not be read. Changes nothing.

## Usage

```console
halo cloud-agents list [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--active` |  | bool | false | only queued and running tasks |
| `--cursor-base-url` |  | string |  | cursor API base URL: https, or http to a loopback host only (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--cursor-token-env` |  | string | HALO_CLOUD_CURSOR_TOKEN | environment variable holding the cursor API credential |
| `--cursor-token-file` |  | string |  | file holding the cursor API credential (read once, never logged) |
| `--cursor-user` |  | string |  | direct reads: Halos user the Cursor key belongs to |
| `--github-base-url` |  | string |  | github API base URL: https, or http to a loopback host only (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--github-token-env` |  | string | HALO_CLOUD_GITHUB_TOKEN | environment variable holding the github API credential |
| `--github-token-file` |  | string |  | file holding the github API credential (read once, never logged) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) for its inventory; credential from HALO_TOKEN or HALO_SESSION |
| `--since` |  | duration | 24h0m0s | direct reads: tasks created this recently (GitHub filters by day) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo cloud-agents`](/halos/reference/cli/cloud-agents/)
