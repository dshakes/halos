---
title: "halo agents"
description: "Delegated and remote (A2A) agents (ADR-0024)"
---

Delegated and remote (A2A) agents (ADR-0024)

## Usage

```console
halo agents
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
| [`halo agents revocations`](/halos/reference/cli/agents-revocations/) | List active credential revocations (halo-server, admin) |
| [`halo agents revoke`](/halos/reference/cli/agents-revoke/) | Revoke an agent or workload credential (--jti) or a subject's credentials (--subject) via halo-server (admin) |
| [`halo agents verify`](/halos/reference/cli/agents-verify/) | Fetch an A2A AgentCard, verify its signature and pinned digest, and print the digest to pin |

## Parent

[`halo`](/halos/reference/cli/)
