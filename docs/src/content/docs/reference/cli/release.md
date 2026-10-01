---
title: "halo release"
description: "Build, publish and promote releases"
---

Build, publish and promote releases

## Usage

```console
halo release
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
| [`halo release build`](/halos/reference/cli/release-build/) | Build a release tarball for a ring |
| [`halo release promote`](/halos/reference/cli/release-promote/) | Point --to-ring at the release --from-ring's signed pointer names; experiment channels stay with the ring they were built for |
| [`halo release publish`](/halos/reference/cli/release-publish/) | Build, sign and push a ring release (and its client-axis experiment channels); tags v&lt;version> and ring-&lt;ring> |
| [`halo release refresh`](/halos/reference/cli/release-refresh/) | Re-sign a ring's pointer and its experiment channel pointers (same releases, new seq and expiry) |

## Parent

[`halo`](/halos/reference/cli/)
