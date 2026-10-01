---
title: "ADR-0006: Go and the Kong Go PDK"
description: One language for CLI, agent, gateway plugin and shadow service, so assignment logic is shared.
status: accepted
date: 2026-09-30
---

# ADR-0006: Go and the Kong Go PDK

- Status: accepted
- Date: 2026-09-30

## Context and problem statement

Cohort assignment must give identical answers in `halod` (client), `halo-kong` (gateway) and `halo-shadow`. Kong plugins can be written in Lua or, via PDK, in Go, Python or JavaScript. The agent must be a static cross-platform binary (launchd, systemd, Windows service).

## Decision drivers

- One implementation of `internal/assign` shared by all components.
- Static binaries and easy cross-compilation.
- Fit with the cloud-native ecosystem (ORAS, cosign, OTEL are Go).

## Considered options

1. Lua plugin plus Go everything else (assignment logic duplicated).
2. Go throughout, with the gateway plugin built on `go-pdk`.
3. Rust or TypeScript.

## Decision outcome

Chosen: **option 2**.

### Consequences

- Good: single assignment implementation and test suite; the ecosystem libraries we need are first-class.
- Bad: Kong Go plugins run as a separate process over a socket (extra hop; an operational component to run and monitor). Latency must be measured in the compose e2e (UNVERIFIED until then).
- Bad: less familiar to Kong users who write Lua.
