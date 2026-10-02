---
title: "halo onboard proxy"
description: "Write a single-developer halo-proxy config (loopback, keys from your env) into .halos/local"
---

Write a single-developer halo-proxy config (loopback, keys from your env) into .halos/local

## Usage

```console
halo onboard proxy [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--apply` |  | bool | false | write the files (default: dry run) |
| `--listen` |  | string | 127.0.0.1:8088 | loopback address halo-proxy listens on |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo onboard`](/halos/reference/cli/onboard/)
