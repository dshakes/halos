---
title: "halo toggle"
description: "Feature toggles: list, evaluate, kill, find stale"
---

Feature toggles: list, evaluate, kill, find stale

## Usage

```console
halo toggle
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
| [`halo toggle eval`](/halos/reference/cli/toggle-eval/) | Show which toggles are on for a user, and why |
| [`halo toggle kill`](/halos/reference/cli/toggle-kill/) | Kill a toggle fleet-wide via halo-server (off everywhere at the next poll) |
| [`halo toggle list`](/halos/reference/cli/toggle-list/) | List feature toggles |
| [`halo toggle stale`](/halos/reference/cli/toggle-stale/) | List toggles past their expiry date |

## Parent

[`halo`](/halos/reference/cli/)
