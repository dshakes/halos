---
title: "halo eval"
description: "Offline replay evals"
---

Offline replay evals

## Usage

```console
halo eval
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
| [`halo eval harvest`](/halos/reference/cli/eval-harvest/) | Turn shadow steps where the candidate regressed into redacted step-level eval cases (ADR-0020) |
| [`halo eval online`](/halos/reference/cli/eval-online/) | Grade sampled halo-shadow pairs with the judge rubric; emit halo.eval.* metrics and append history |
| [`halo eval run`](/halos/reference/cli/eval-run/) | Run an eval suite and print the scorecard |
| [`halo eval steps`](/halos/reference/cli/eval-steps/) | Step-level regression suites harvested from shadow traffic |

## Parent

[`halo`](/halos/reference/cli/)
