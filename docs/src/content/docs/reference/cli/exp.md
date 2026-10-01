---
title: "halo exp"
description: "Manage experiments"
---

Manage experiments

## Usage

```console
halo exp
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
| [`halo exp analyze`](/halos/reference/cli/exp-analyze/) | Evaluate experiment evidence from ClickHouse (promote\|rollback\|continue\|expired) |
| [`halo exp conclude`](/halos/reference/cli/exp-conclude/) | Set experiment status to concluded (edits the YAML in place) |
| [`halo exp list`](/halos/reference/cli/exp-list/) | List experiments |
| [`halo exp pause`](/halos/reference/cli/exp-pause/) | Set experiment status to paused (edits the YAML in place) |
| [`halo exp promote`](/halos/reference/cli/exp-promote/) | Open a PR pointing --ring at --release (never merges); requires a promote verdict |
| [`halo exp show`](/halos/reference/cli/exp-show/) | Show an experiment |
| [`halo exp start`](/halos/reference/cli/exp-start/) | Set experiment status to running (edits the YAML in place) |

## Parent

[`halo`](/halos/reference/cli/)
