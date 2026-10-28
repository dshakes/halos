---
title: "halo cloud-agents"
description: "Govern cloud and background coding agents: render workflows, list tasks, kill (ADR-0034)"
---

Govern cloud and background coding agents: render workflows, list tasks, kill (ADR-0034)

## Usage

```console
halo cloud-agents
```

## Flags

None.

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Commands

| Command | Description |
|---|---|
| [`halo cloud-agents kill`](/halos/reference/cli/cloud-agents-kill/) | Cancel the cloud tasks of a user, ring or experiment through halo-server (dry run unless --execute) |
| [`halo cloud-agents list`](/halos/reference/cli/cloud-agents-list/) | List active and recent cloud agent tasks with policy alerts |
| [`halo cloud-agents render`](/halos/reference/cli/cloud-agents-render/) | Render the SHA-pinned, least-privilege workflow files of the repo-configured cloud agents |

## Parent

[`halo`](/halos/reference/cli/)
