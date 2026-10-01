---
title: Examples gallery
description: Ready-to-copy policy repos for common stacks. Copy one, validate it, change the placeholders.
---

Each example is a complete policy repo that `halo validate` passes with no errors and no warnings, and a Go test fails the build if any of them stops validating. All hosts, ARNs and project ids are placeholders (`*.example`, account `111122223333`); credentials are environment-variable references only, never values.

## Pick one

| Example | Stack | Harnesses | What it shows |
|---|---|---|---|
| [`startup-minimal`](https://github.com/dshakes/halos/tree/main/examples/startup-minimal) | `halo-proxy` to Anthropic | Claude Code | The smallest useful repo: one profile, two rings, one alias. No identity provider yet. |
| [`direct-anthropic`](https://github.com/dshakes/halos/tree/main/examples/direct-anthropic) | `halo-proxy` to Anthropic | Claude Code | OIDC identity, model allowlist, secret denies, a draft traffic canary for a new Opus snapshot. |
| [`bedrock-kong`](https://github.com/dshakes/halos/tree/main/examples/bedrock-kong) | Kong + `halo-kong`, auth gateway, orchestrator, Bedrock | Claude Code | `engine: kong`, managed-only MCP and hooks, a client toggle, a draft blue-green rollout with approval gates. |
| [`multi-provider-failover`](https://github.com/dshakes/halos/tree/main/examples/multi-provider-failover) | `halo-proxy` to Anthropic, Bedrock and Vertex | Claude Code | Priority tiers, a 70/30 weighted split sticky per user, failover on 5xx/429, a draft A/B on route order. |
| [`codex-heavy`](https://github.com/dshakes/halos/tree/main/examples/codex-heavy) | `halo-proxy` to OpenAI, Azure OpenAI as failover | Codex | `openai-responses` wire, env-var provider credentials, a toggle that adds an MCP server to part of a ring. |
| [`regulated`](https://github.com/dshakes/halos/tree/main/examples/regulated) | `halo-proxy` to Bedrock in one region | Claude Code | No web fetch, network tools denied, `sandboxRequired`, managed-only MCP and hooks, egress allowlist, self-service off, approval-gated rollout. |

[`acme-corp`](https://github.com/dshakes/halos/tree/main/examples/acme-corp) is the full reference repo (three harnesses, four rings, experiments, toggles, rollouts, eval scorecards) that the docs use throughout.

Each example has a `README.md` with who it is for, the tree, and how to adopt it.

## Copy it

From a checkout of the Halos repo:

```bash
cp -r examples/startup-minimal my-policy
halo validate --policy-dir my-policy
```

```console
$ halo validate --policy-dir examples/startup-minimal
OK: policy valid (0 warnings)
```

Warnings are reported as `warning <path>  <message>` and do not fail the command; errors exit with status 2. Then:

1. Replace the placeholder domains, ARNs and users with yours.
2. Check what a user would get: `halo whoami --user you@example.com --policy-dir my-policy`, and for multi-target routes `halo gateway routes --user you@example.com --policy-dir my-policy`.
3. Inspect the rendered harness config: `halo render --policy-dir my-policy --ring <ring> --os linux --out /tmp/rendered`.
4. Commit it to your own policy repo and follow the [quickstart](/halos/getting-started/quickstart/) to sign and publish a release.

## What every example holds to

- `permissions.disableBypass: true` on every ring. Halos never renders `bypassPermissions` or `danger-full-access`.
- Telemetry on for every ring (a guardrail requires it).
- Exact CLI version pins, never ranges or `latest`.
- In the gallery examples (not acme-corp), experiments and rollouts ship as `draft`: nothing is exposed until a human starts them, and promotion is a PR a human merges.

Examples are starting points, not endorsements of a model, a version or a provider order. Pins such as `2.1.280` and model ids age; update them before you ship.
