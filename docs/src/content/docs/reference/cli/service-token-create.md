---
title: "halo service-token create"
description: "Create a service-account token; it is printed once and never again"
---

Create a service-account token; it is printed once and never again

Prints the token once: store it in your secret manager right away and pass it to automation as HALO_TOKEN. The role is one of viewer, operator, approver, auditor, admin and may not exceed your own; --ttl defaults to the server's maximum (90 days unless configured). --scope-ring and --scope-unit bound the role to those rings and units (ADR-0037); the scope must be within your own admin grants. Without them the token is global.

## Usage

```console
halo service-token create [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--description` |  | string |  | what the token is for |
| `--name` |  | string |  | service account name (lowercase), e.g. ci-killswitch |
| `--owner` |  | string |  | the team or person accountable for it |
| `--role` |  | string |  | halo-server role the token holds: viewer, operator, approver, auditor, admin |
| `--scope-ring` |  | stringSlice | [] | bound the role to these rings (repeatable or comma-separated) |
| `--scope-unit` |  | stringSlice | [] | bound the role to these units and their descendants (repeatable or comma-separated) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER); credential from HALO_SESSION (an interactive admin session) |
| `--ttl` |  | string |  | lifetime as a duration, e.g. 720h (default and maximum: the server's --service-token-max-ttl) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo service-token`](/halos/reference/cli/service-token/)
