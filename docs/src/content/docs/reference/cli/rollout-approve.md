---
title: "halo rollout approve"
description: "Approve advancing a rollout from its live step on halo-server (audited; counts toward the approval quorum)"
---

Approve advancing a rollout from its live step on halo-server (audited; counts toward the approval quorum)

## Usage

```console
halo rollout approve <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) ; credential from HALO_TOKEN or HALO_SESSION |
| `--ticket` |  | string |  | change ticket reference (e.g. CHG0012345), when an approval rule requires one |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo rollout`](/halos/reference/cli/rollout/)
