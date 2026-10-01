---
title: "halo kill"
description: "Kill an experiment, toggle or rollout fleet-wide via halo-server (effective at the next poll)"
---

Kill an experiment, toggle or rollout fleet-wide via halo-server (effective at the next poll)

Resolves &lt;name> in the policy repo. Experiments and toggles go on halo-server's signed kill list;
a rollout kills its backing experiment (then open the abort PR: halo rollout rollback &lt;name> --reason ...).
The admin session comes from HALO_SESSION, never a flag.

## Usage

```console
halo kill <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--kind` |  | string |  | experiment \| toggle \| rollout, when the name is ambiguous |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--reason` |  | string |  | why; recorded in the audit log (required to kill) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) |
| `--unkill` |  | bool | false | clear the kill instead |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
