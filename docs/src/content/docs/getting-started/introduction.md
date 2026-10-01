---
title: Introduction
description: What Halos is, the problem it solves, and how the pieces fit.
---

Halos (`halo`) is a control plane for AI developer tools in organizations. It treats configuration of Claude Code, Codex, Gemini CLI, Copilot CLI and similar harnesses as a **signed, ring-deployed release**, gates promotion on evidence, and routes model traffic through a plane you control so the most common rollback is instant.

## The problem

AI coding CLIs have become production infrastructure, but they are still managed like personal tools. A vendor release or a model change reaches the whole engineering organization at once, unmeasured. When behaviour regresses behind a corporate gateway, platform teams lack three answers: who is running which version, whether the change made outcomes worse, and how to reverse it without asking every engineer to act.

- **Settings sprawl.** Each harness has its own config format and enforcement knobs.
- **No central channel on gateways.** Claude Code's server-managed settings are not fetched with Bedrock or a custom `ANTHROPIC_BASE_URL`, so config must be delivered as files, MDM profiles or environment definitions.
- **All-at-once upgrades.** No way to A/B a CLI or model upgrade.
- **No eval gate, no rollback.**

## What you get

| Need | Halos feature |
|---|---|
| One source of truth | [Policy repo](/halos/concepts/policy-model/) validated by strict typed decoding and Go guardrails (JSON Schemas are for editors and CI) |
| Safe rollout | [Rings and releases](/halos/concepts/rings-and-releases/) with signed pointers |
| Prove a model or CLI change | [Experiments](/halos/concepts/experiments/), [shadow](/halos/concepts/shadow-traffic/), [evals](/halos/guides/writing-evals/) |
| Enforce on every machine | [Delivery](/halos/concepts/delivery/): dev containers first, `halod` and MDM for laptops |
| Developers help themselves | [Self-service portal](/halos/concepts/self-service-portal/) |
| Any gateway, any IdP | [Stack-agnostic traffic plane](/halos/concepts/stack-agnostic/) |
| Trust | [Signed bundles and pointers, verified identity, stripped headers](/halos/concepts/security-model/) |
| Let an agent drive it, safely | [Agentic operations](/halos/guides/agentic-operations/) |

## Mental model

<img class="diagram dark:sl-hidden" src="/halos/diagrams/measure-loop-light.svg" alt="A change is evaluated offline (pass@k, LLM judge, harness by model matrix), exposed to a ring, measured through OTEL in ClickHouse, and judged by mSPRT. A pass opens a promotion PR a human merges; a guardrail breach rolls back automatically and fires the signed kill switch." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/measure-loop-dark.svg" alt="A change is evaluated offline (pass@k, LLM judge, harness by model matrix), exposed to a ring, measured through OTEL in ClickHouse, and judged by mSPRT. A pass opens a promotion PR a human merges; a guardrail breach rolls back automatically and fires the signed kill switch." width="880" />

## Where to go next

1. [Quickstart](/halos/getting-started/quickstart/).
2. [Architecture](/halos/concepts/architecture/).
3. The guide matching your setup: [Bedrock via Kong](/halos/guides/bedrock-via-kong/) or [direct Anthropic](/halos/guides/direct-anthropic/).
4. Going live: [production deployment](/halos/guides/production-deployment/) and the [threat model](/halos/reference/threat-model/).
