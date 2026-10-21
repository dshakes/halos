---
title: "halo units codeowners"
description: "Print a CODEOWNERS file that gives each unit's owners its directory in the policy repo"
---

Print a CODEOWNERS file that gives each unit's owners its directory in the policy repo

Each Unit's directory goes to its owners and its ancestors' owners; --owner sets the catch-all line (the central team keeps halos.yaml, profiles and rings) and is required when there is a top-level unit: a top-level unit's own file goes to those root owners alone, because its members selector draws from the whole org. Paths are relative to the git repository root containing the policy dir. Pair it with branch protection that requires code-owner review and `halo validate`.

## Usage

```console
halo units codeowners [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--owner` |  | stringSlice | [] | owner of everything outside unit directories (repeatable), e.g. @acme/ai-platform |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo units`](/halos/reference/cli/units/)
