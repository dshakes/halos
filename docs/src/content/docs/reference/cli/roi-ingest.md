---
title: "halo roi ingest"
description: "Import pull-request outcomes (read-only on the source)"
---

Import pull-request outcomes (read-only on the source)

## Usage

```console
halo roi ingest
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
| [`halo roi ingest file`](/halos/reference/cli/roi-ingest-file/) | Import outcomes from a generic CSV/JSONL export (any SCM or tracker) |
| [`halo roi ingest github`](/halos/reference/cli/roi-ingest-github/) | Import pull requests from GitHub (GraphQL, read-only query) |

## Parent

[`halo roi`](/halos/reference/cli/roi/)
