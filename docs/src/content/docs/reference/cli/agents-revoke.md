---
title: "halo agents revoke"
description: "Revoke an agent or workload credential (--jti) or a subject's credentials (--subject) via halo-server (admin)"
---

Revoke an agent or workload credential (--jti) or a subject's credentials (--subject) via halo-server (admin)

--jti kills one credential and every credential exchanged from it. --subject kills every credential issued so far for an agent (agent:&lt;name>, anywhere in a delegation chain), a workload (workload:...) or a human root (their id: also ends their sessions). halo-server refuses revoked credentials at once on every replica; gateways with a directory configured within 30s. New credentials for an agent or workload subject are refused for one minute (clock-skew pad).

## Usage

```console
halo agents revoke [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--jti` |  | string |  | the credential's jti (from the agent.token.exchange or workload.token.exchange audit entry) |
| `--reason` |  | string |  | why; recorded in the audit log (required) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) |
| `--subject` |  | string |  | agent:&lt;name>, workload:&lt;subject>, or a human user id |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo agents`](/halos/reference/cli/agents/)
