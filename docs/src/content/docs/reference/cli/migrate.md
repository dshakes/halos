---
title: "halo migrate"
description: "Rewrite policy documents from apiVersion halos.dev/v1alpha1 to halos.dev/v1"
---

Rewrite policy documents from apiVersion halos.dev/v1alpha1 to halos.dev/v1

Only the apiVersion value changes: comments, formatting and every other byte stay as they are. Semantics are identical, so the policy loads to the same thing afterwards. Running it again is a no-op.

## Usage

```console
halo migrate [flags]
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
