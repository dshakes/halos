---
title: "halo eval steps"
description: "Step-level regression suites harvested from shadow traffic"
---

Step-level regression suites harvested from shadow traffic

## Usage

```console
halo eval steps
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
| [`halo eval steps run`](/halos/reference/cli/eval-steps-run/) | Replay each harvested step against a model route and score the next action (deterministic matcher, session-clustered CIs) |

## Parent

[`halo eval`](/halos/reference/cli/eval/)
