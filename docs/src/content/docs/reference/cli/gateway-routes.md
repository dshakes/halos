---
title: "halo gateway routes"
description: "Print the effective model route table and the target a user/session would hit"
---

Print the effective model route table and the target a user/session would hit

## Usage

```console
halo gateway routes [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--group` |  | stringSlice | [] | IdP group of the user (repeatable); ring membership may depend on it |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--session` |  | string |  | harness session id (weighted picks are sticky per user+session) |
| `--user` |  | string |  | verified user id (e.g. alice@acme.com): selects ring, experiment variant and the sticky weighted pick |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo gateway`](/halos/reference/cli/gateway/)
