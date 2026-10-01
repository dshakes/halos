---
title: "halo gateway"
description: "Compile gateway artifacts from the policy repo"
---

Compile gateway artifacts from the policy repo

## Usage

```console
halo gateway
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
| [`halo gateway compile`](/halos/reference/cli/gateway-compile/) | Compile the policy snapshot (policy.json) the gateway loads |
| [`halo gateway deck`](/halos/reference/cli/gateway-deck/) | Generate the decK declarative config (kong.yml) for Kong + halo-kong |
| [`halo gateway routes`](/halos/reference/cli/gateway-routes/) | Print the effective model route table and the target a user/session would hit |

## Parent

[`halo`](/halos/reference/cli/)
