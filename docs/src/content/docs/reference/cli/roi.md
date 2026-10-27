---
title: "halo roi"
description: "Delivery ROI of a policy change: PR outcomes per experiment arm (ADR-0027)"
---

Delivery ROI of a policy change: PR outcomes per experiment arm (ADR-0027)

## Usage

```console
halo roi
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
| [`halo roi ingest`](/halos/reference/cli/roi-ingest/) | Import pull-request outcomes (read-only on the source) |
| [`halo roi report`](/halos/reference/cli/roi-report/) | Estimate delivery effects per experiment arm (randomized) or compare rings (observational) |

## Parent

[`halo`](/halos/reference/cli/)
