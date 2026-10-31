---
title: "halo cloud-agents kill"
description: "Cancel the cloud tasks of a user, ring or experiment through halo-server (dry run unless --execute)"
---

Cancel the cloud tasks of a user, ring or experiment through halo-server (dry run unless --execute)

Plans, and with --execute sends, the vendor cancel call for every active cloud task of --scope user|ring|experiment
--name. halo-server resolves rings and experiments from the tasks' Halos identities (internal/assign), audits the
intent before any call and every result after, and needs the operate permission. Vendors without a cancel API get
a manual step. Nothing is ever resumed automatically.

## Usage

```console
halo cloud-agents kill [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--execute` |  | bool | false | send the cancel calls (default: plan only) |
| `--name` |  | string |  | the user id, ring or experiment |
| `--reason` |  | string |  | why (required; recorded in the audit log) |
| `--scope` |  | string | user | user \| ring \| experiment |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) ; credential from HALO_TOKEN or HALO_SESSION |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo cloud-agents`](/halos/reference/cli/cloud-agents/)
