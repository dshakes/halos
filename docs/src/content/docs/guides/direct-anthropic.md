---
title: Direct Anthropic
description: Managing users who talk to the Anthropic API directly, alongside the Bedrock path.
---

Some users go straight to Anthropic. They can still receive releases, rings and pinned versions; traffic-axis experiments need a gateway in the path.

## Two cases

| Case | Config delivery | Traffic experiments |
|---|---|---|
| Direct, no gateway | Files, MDM or dev container (same as the Bedrock path) | Not possible (nothing to rewrite the route) |
| Direct upstream behind `halo-proxy` or Kong | Same, with `upstreams.anthropic` | Yes |

:::note
Whether Claude Code fetches server-managed settings with a first-party login is a vendor feature outside Halos. Halos's file-based delivery works regardless and is what the docs assume.
:::

## Gateway with an Anthropic upstream

```yaml
apiVersion: halos.dev/v1
kind: Gateway
name: acme-direct
baseURL: https://ai.acme.example
protocols: {claude-code: anthropic-messages}
auth: {helperCommand: acme-sso-token --audience halos-gateway, ttlSeconds: 900}
models:
  sonnet: {upstream: anthropic, model: claude-sonnet-4-5}
upstreams:
  anthropic: {url: https://api.anthropic.com, kind: anthropic}
```

The provider key is injected by `halo-proxy`, not distributed to developers:

```yaml
# halo-proxy.yaml
upstreamHeaders:
  anthropic: {x-api-key: "${ANTHROPIC_API_KEY}", anthropic-version: "2023-06-01"}
```

Model ids are examples. Mixing upstreams is fine: alias `sonnet` can go to `orchestrator` (Bedrock) for one ring and `anthropic` for another via an experiment's `routes`. The Anthropic upstream is the path the `deploy/compose` mock (`anthropic-mock`) stands in for; a live Anthropic API account was **not** used.

## Client-only management

With no gateway you still get version pins (`requiredMinimumVersion`/`requiredMaximumVersion`), model allowlists, MCP and hook locks, and permissions. You lose verified cohort stamping, traffic experiments and shadow.
