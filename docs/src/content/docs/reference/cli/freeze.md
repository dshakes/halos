---
title: "halo freeze"
description: "Change freezes: policy windows and the incident freeze (ADR-0030); rollbacks are never frozen"
---

Change freezes: policy windows and the incident freeze (ADR-0030); rollbacks are never frozen

## Usage

```console
halo freeze
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
| [`halo freeze check`](/halos/reference/cli/freeze-check/) | Exit non-zero while a change to --ring (default: any ring) is frozen; rollback branches always pass (CI status check) |
| [`halo freeze off`](/halos/reference/cli/freeze-off/) | Lift the incident freeze on halo-server (admin) |
| [`halo freeze on`](/halos/reference/cli/freeze-on/) | Set the incident freeze on halo-server: no rollout advances or promotions until lifted (admin) |
| [`halo freeze status`](/halos/reference/cli/freeze-status/) | Show which rings are frozen now (or --at), why, and when each opens |

## Parent

[`halo`](/halos/reference/cli/)
