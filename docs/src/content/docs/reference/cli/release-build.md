---
title: "halo release build"
description: "Build a release tarball for a ring"
---

Build a release tarball for a ring

## Usage

```console
halo release build [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--no-artifacts` |  | bool | false | skip resolving vendor install artifacts (offline builds); halod will not install CLIs without them unless allowShellInstall |
| `--out` | `-o` | string | release.tar | output tarball |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--release-version` |  | string | 0.0.0-dev | release version label |
| `--ring` |  | string |  | ring to build (required) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo release`](/halos/reference/cli/release/)
