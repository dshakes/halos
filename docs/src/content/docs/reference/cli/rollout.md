---
title: "halo rollout"
description: "Phased rollouts: plan, status, simulate; advance opens a PR, never merges"
---

Phased rollouts: plan, status, simulate; advance opens a PR, never merges

## Usage

```console
halo rollout
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
| [`halo rollout advance`](/halos/reference/cli/rollout-advance/) | Open a PR moving the rollout to its next step (or completing it); never merges |
| [`halo rollout list`](/halos/reference/cli/rollout-list/) | List rollouts |
| [`halo rollout pause`](/halos/reference/cli/rollout-pause/) | Open a PR pausing the rollout (exposure stays; no further steps) |
| [`halo rollout plan`](/halos/reference/cli/rollout-plan/) | Show the rollout's steps, gates and earliest timeline |
| [`halo rollout rollback`](/halos/reference/cli/rollout-rollback/) | Open a PR aborting the rollout: experiment paused, rings back on baseline.release |
| [`halo rollout simulate`](/halos/reference/cli/rollout-simulate/) | Run the state machine on synthetic or recorded evidence (writes nothing) |
| [`halo rollout status`](/halos/reference/cli/rollout-status/) | Show the live step, gate values vs thresholds and the next action |

## Parent

[`halo`](/halos/reference/cli/)
