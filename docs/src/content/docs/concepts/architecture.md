---
title: Architecture
description: The three planes, the components, and how a change flows from git to production.
---

Halos has three planes plus a policy source. Each plane can be adopted independently, but the loop closes only when all three run.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/architecture-light.svg" alt="Policy compiles to a signed release and ring pointers. The client plane (halod, MDM, Dev Container Feature, Coder, CI action) applies it; the traffic plane (halo-proxy or the Kong plugin) routes to Anthropic, Bedrock, Vertex or OpenAI; the evidence plane (OTEL, ClickHouse, halo eval, controller, console, MCP) proposes promotion PRs and fires the kill switch." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/architecture-dark.svg" alt="Policy compiles to a signed release and ring pointers. The client plane (halod, MDM, Dev Container Feature, Coder, CI action) applies it; the traffic plane (halo-proxy or the Kong plugin) routes to Anthropic, Bedrock, Vertex or OpenAI; the evidence plane (OTEL, ClickHouse, halo eval, controller, console, MCP) proposes promotion PRs and fires the kill switch." width="880" />

## Planes

**Client plane.** Makes the developer environment match a signed release. It writes each harness's native managed configuration (Claude Code `managed-settings.json`, managed MCP config and a managed `CLAUDE.md`; Codex `requirements.toml` and `managed_config.toml`; Gemini CLI system `settings.json`; Copilot CLI `managed-settings.json`) and installs the pinned CLI from a verified artifact. See [delivery](/halos/concepts/delivery/) and the [self-service portal](/halos/concepts/self-service-portal/).

**Traffic plane.** `halo-proxy` (or Kong with the `halo-kong` plugin) verifies the caller's OIDC JWT, derives the ring and variant from the verified identity, rewrites model aliases to the variant route, stamps `x-halo-*` headers and enforces a fail-closed model allowlist. `halo-shadow` receives async copies of sampled first-turn requests. The gateway also polls `halo-server`'s signed kill list so a bad experiment can be switched off in seconds ([experiments](/halos/concepts/experiments/#kill-switch)), and can sign Bedrock requests with its own AWS identity. See [stack-agnostic](/halos/concepts/stack-agnostic/) and [shadow traffic](/halos/concepts/shadow-traffic/).

**Evidence plane.** An OTEL collector normalizes harness telemetry to `halo.*` in ClickHouse; `halo eval run` runs containerized headless replays; `halo exp analyze` applies sequential tests and guardrails; `halo exp promote` opens a PR, and the controller runs that loop on a timer. See [evidence plane](/halos/concepts/evidence-plane/).

## Design constraints

- Rings point at immutable releases through signed pointers ([ADR-0002](/halos/adr/0002-rings-point-at-immutable-releases/), [ADR-0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/)).
- Model experiments live at the gateway ([ADR-0003](/halos/adr/0003-experiments-on-traffic-plane-first/)).
- Assignment is one Go package (`internal/assign`) shared by `halod`, `halo-proxy`, `halo-kong` and `halo-shadow` ([ADR-0006](/halos/adr/0006-go-and-kong-go-pdk/)).
- Shadow is first-turn only ([ADR-0004](/halos/adr/0004-shadow-single-turn-only/)).
- A human owns every irreversible step. Promotion opens a PR; automatic rollback (the kill switch, [ADR-0009](/halos/adr/0009-signed-kill-switch/)) is the only automatic direction, and it only returns users to control.

## Request path

<img class="diagram dark:sl-hidden" src="/halos/diagrams/request-path-light.svg" alt="Claude Code sends a request with a bearer JWT; halo-proxy strips client x-halo headers, verifies the token against the issuer JWKS, assigns ring, experiment and variant, enforces the model allowlist, forwards with x-halo stamps, streams the response and mirrors the first turn to halo-shadow asynchronously." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/request-path-dark.svg" alt="Claude Code sends a request with a bearer JWT; halo-proxy strips client x-halo headers, verifies the token against the issuer JWKS, assigns ring, experiment and variant, enforces the model allowlist, forwards with x-halo stamps, streams the response and mirrors the first turn to halo-shadow asynchronously." width="760" />

The mirror is asynchronous and dropped when its queue is full. A shadow job carries only the experiment, variant, protocol, path, allowlisted headers and body; `halo-shadow` resolves both upstreams from its own copy of the policy.

## Components

| Component | Language | Notes |
|---|---|---|
| `halo` | Go | Compiler and operator CLI |
| `halod` | Go | Static binary; `run`/`once`/`status`; launchd and systemd units in `cmd/halod/packaging`, scheduled task on Windows |
| `halo-proxy` | Go | Stack-agnostic proxy; `/healthz` and `/metrics` on the admin listener (`--admin-listen`) |
| `halo-kong` | Go (go-pdk) | External Kong plugin, same decision code |
| `halo-shadow` | Go | Async mirror, optional AES-256-GCM pair store |
| `halo-server` | Go + embedded web console | Inventory, drift, releases, experiments, audit log, portal, enrollment, device store, kill-list endpoint, optional controller (`--controller`) |
