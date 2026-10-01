---
title: "halo render"
description: "Render a ring's harness config files under --out, mirroring absolute paths"
---

Render a ring's harness config files under --out, mirroring absolute paths

## Usage

```console
halo render [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--os` |  | string | darwin | target OS: darwin\|linux\|windows |
| `--out` |  | string | rendered | output directory |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--release-version` |  | string | 0.0.0-dev | release version label stamped into config |
| `--ring` |  | string |  | ring to render (required) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
