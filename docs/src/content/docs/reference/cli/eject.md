---
title: "halo eject"
description: "Write simple mode's generated Gateway, Profile and Rings out as files and drop the simple keys from halos.yaml"
---

Write simple mode's generated Gateway, Profile and Rings out as files and drop the simple keys from halos.yaml

The policy loads to exactly the same thing afterwards; from then on you edit the low-level files.

## Usage

```console
halo eject [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--dry-run` |  | bool | false | print the diff instead of writing |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
