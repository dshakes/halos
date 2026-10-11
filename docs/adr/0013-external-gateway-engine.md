---
title: "ADR-0013: Halos manages clients behind a gateway it does not run"
description: Gateway.engine external renders provider model ids for a company's own API gateway; Halos keeps client policy and gives up the gateway-side guarantees, and says so.
status: accepted
date: 2026-10-05
---

# ADR-0013: Halos manages clients behind a gateway it does not run

## Context and problem statement

A field trial at a company whose model traffic already runs Kong → an auth gateway → an orchestrator → Bedrock found no way to describe that setup. Every engine (`halo-proxy`, `kong`) assumes a Halos data plane that maps aliases such as `default` to provider model ids, so pointing `gateway` at the company's own URL sent `default` to a backend that has never heard of it. The company cannot put a new proxy in front of its gateway to try Halos, and it already delivers Claude Code managed settings through MDM. Can Halos be adopted for client policy alone, and what does it promise then?

## Decision drivers

- Adoption must not require replacing or fronting an existing, approved model gateway.
- Invariants 1 to 7 must still hold, and nothing may silently stop being enforced.
- No new trust boundary: Halos must not start reading or forwarding the company's credentials.

## Considered options

1. **`Gateway.engine: external`.** Clients are rendered with each alias's primary provider model id; routes may omit `upstream`; validation warns about what no longer applies.
2. **Require halo-proxy in front of the company gateway** (an `orchestrator` upstream). Keeps every guarantee but needs a new hop in the request path before anyone can evaluate Halos.
3. **Let users put raw model ids in `models.allowed`.** No new concept, but aliases are what experiments, rings and the guardrails reason about, so every policy would fork into two vocabularies.

## Decision outcome

Chosen: **option 1**, with option 2 still the recommended end state for companies that want the gateway-side guarantees.

`hutil.ClientModel` resolves an alias to `ModelRoute.Primary().Model` when the engine is external, and to the alias itself otherwise. Claude Code (`model`, `availableModels`, `ANTHROPIC_DEFAULT_*_MODEL`, `modelOverrides`), Codex and Gemini CLI use it. Copilot CLI is not gateway-routed and is unchanged. Validation accepts `external`, skips the upstream lookup for a route without one, warns on multi-target routes (only the first is rendered), and warns once on the gateway that posture and version gates, the kill switch and model-axis experiment metrics do not apply.

## Consequences

- Good: Halos can be evaluated and adopted for version pins, permissions, MCP and hook policy without touching the request path.
- Good: the loss of guarantees is a validation warning on every run, not a footnote.
- Bad: no failover, weights or alias-level experiments, and no Halos traffic metrics, until a Halos data plane is added.
- Neutral: `x-halo-ring` and `x-halo-release` are still sent; a company gateway can log or route on them. They are not trusted for anything (invariant 4 governs Halos gateways only).

## More information

- `internal/harness/hutil/hutil.go` (`ClientModel`), `internal/policy/validate.go` (`gateway`, `route`), `internal/policy/simple.go` (`gatewayEngine`).
- [Start here: a company laptop](/halos/getting-started/start-here/#my-machine).
