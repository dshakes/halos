---
title: "halo freeze check"
description: "Exit non-zero while a change to --ring (default: any ring) is frozen; rollback branches always pass (CI status check)"
---

Exit non-zero while a change to --ring (default: any ring) is frozen; rollback branches always pass (CI status check)

A required status check for policy-repo pull requests. --branch is the PR's head branch: Halos'
rollback and pause branches (halos/rollback-*, halos/rollout-*-rollback, -pause) always pass, so the way
back is never blocked. Run it in the merge queue (merge_group) so it is evaluated at merge time.

## Usage

```console
halo freeze check [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--at` |  | string |  | evaluate at this RFC 3339 time instead of now (planning; policy windows only) |
| `--branch` |  | string |  | PR head branch; rollback and pause branches always pass |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--ring` |  | string |  | only this ring (default: every ring) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) to include the incident freeze; session from HALO_SESSION |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo freeze`](/halos/reference/cli/freeze/)
