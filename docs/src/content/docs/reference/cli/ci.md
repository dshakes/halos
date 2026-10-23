---
title: "halo ci"
description: "Governed gateway credentials and config for headless CI / cloud agents"
---

Governed gateway credentials and config for headless CI / cloud agents

## Usage

```console
halo ci
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
| [`halo ci config`](/halos/reference/cli/ci-config/) | Write one harness's managed config for a headless run from the ring's release |
| [`halo ci token`](/halos/reference/cli/ci-token/) | Exchange this job's OIDC token for a short-lived gateway credential and export it for the harnesses |

## Parent

[`halo`](/halos/reference/cli/)
