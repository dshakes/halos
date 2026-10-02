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

## Addendum 2026-10-02: plugin-server latency is measured

The consequence above left the Go plugin-server hop UNVERIFIED. The Kong UAT (`scripts/uat-kong.sh`, `test/uat/kong`) now times the same mock upstream through a plugin-free route and through `halo-kong` (JWT verify, decision, rewrite), 60 interleaved requests each, and fails if the median overhead exceeds 50 ms; the measured p50/p95 of both paths is recorded in the UAT evidence column. The bound is deliberately loose so a busy laptop does not flake; the evidence is the number.

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| One `internal/assign` implementation shared by `halod`, `halo-kong`, `halo-shadow` | `internal/assign`; callers `internal/policy/resolve.go` (`ResolveVariant`), `internal/gateway/decision.go`, `cmd/halod/agent.go` (`selectVariant`); no other hashing of users (AGENTS.md invariant 3) | `assign_test.go` `TestBucketKnownAnswers`, `TestBucketSaltIndependence`; `cmd/halod` `TestVariantSelectionMatchesGateway` | Done |
| Gateway plugin on `go-pdk` | `cmd/halo-kong/main.go`; `internal/gateway/kong/deck.go` renders the decK config | `cmd/halo-kong` `TestAccess*`; `test/uat/kong` (real Kong, digest-pinned) | Done |
| Static, cross-compiled binaries | `.goreleaser.yaml` (`CGO_ENABLED=0`; darwin, linux, windows); `Makefile` (`-trimpath`) | release workflow builds every target; `scripts/package-check.sh` | Done |
| Agent as launchd, systemd and Windows service | `cmd/halod/service.go` (`PlanService`, `RunService`) | `service_test.go` `TestPlanServiceGolden`, `TestPlanServiceWindows`, `TestRunService`, `TestServiceInstallRefusesUntrustedExe` | Done |
| Plugin-server latency measured in the compose e2e | `test/uat/kong/kong_test.go` (`latency` step) | the step itself (addendum above) | Done (was UNVERIFIED) |
