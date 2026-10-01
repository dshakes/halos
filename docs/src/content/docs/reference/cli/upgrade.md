---
title: "halo upgrade"
description: "Watch upstream CLIs and models; open eval-gated upgrade PRs (never merges)"
---

Watch upstream CLIs and models; open eval-gated upgrade PRs (never merges)

## Usage

```console
halo upgrade
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
| [`halo upgrade check`](/halos/reference/cli/upgrade-check/) | Check once for new CLI versions and models |
| [`halo upgrade publish`](/halos/reference/cli/upgrade-publish/) | Rebuild and push the candidate release a `halo upgrade start` rollout names (no ring pointer moves) |
| [`halo upgrade start`](/halos/reference/cli/upgrade-start/) | Roll a CLI version out: build and publish the candidate (no ring moves) and write its phased rollout |
| [`halo upgrade watch`](/halos/reference/cli/upgrade-watch/) | Check on an interval until interrupted |

## Parent

[`halo`](/halos/reference/cli/)
