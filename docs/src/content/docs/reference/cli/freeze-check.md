---
title: "halo freeze check"
description: "Exit non-zero while a change to --ring (default: any ring) is frozen; rollbacks always pass (CI status check)"
---

Exit non-zero while a change to --ring (default: any ring) is frozen; rollbacks always pass (CI status check)

A required status check for policy-repo pull requests and the merge queue. With --event (the
GitHub event payload: pull_request or merge_group) or --base, freeze windows are read from the base
branch, never from the change itself, and the change is classified from its diff: one that only
pauses or aborts rollouts, pauses experiments, or moves rings back to a release they pointed at
before on the base branch is a rollback and always passes. Needs the base history (actions/checkout
fetch-depth: 0). Without either flag it checks the local policy's windows and exempts nothing.

## Usage

```console
halo freeze check [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--at` |  | string |  | evaluate at this RFC 3339 time instead of now (planning; policy windows only) |
| `--base` |  | string |  | git ref of the protected base branch (e.g. origin/main): windows from it, rollbacks from the diff against it |
| `--event` |  | string |  | GitHub event payload ($GITHUB_EVENT_PATH; pull_request or merge_group): windows from the base branch, rollbacks from the diff |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--ring` |  | string |  | only this ring (default: every ring) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) to include the incident freeze; session from HALO_SESSION |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo freeze`](/halos/reference/cli/freeze/)
