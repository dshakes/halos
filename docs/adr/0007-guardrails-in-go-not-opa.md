---
title: "ADR-0007: Guardrails in Go, not OPA"
description: Default org guardrails are compiled-in Go checks; Rego stays pluggable for later.
status: accepted
date: 2026-09-30
---

# ADR-0007: Guardrails in Go, not OPA

- Status: accepted
- Date: 2026-09-30

## Context and problem statement

Policy must be checked before release: no `bypassPermissions` or `danger-full-access` in any ring, egress must be non-empty for managed environments, hooks must be managed-only in GA, and so on. The initial plan considered OPA/Rego. The default rule set is small and stable, and it guards security invariants that should not depend on an optional runtime.

## Decision drivers

- Invariants must always run; no missing-policy-bundle failure mode.
- Small dependency footprint for `halo`, `halod`.
- Orgs will want their own rules eventually.

## Considered options

1. OPA/Rego only.
2. Go checks in `internal/policy` for the default guardrails, with a plugin point for extra Rego later.
3. Both required.

## Decision outcome

Chosen: **option 2**. Default guardrails are Go code, unit-tested, run by `halo validate` and again at `halo release build` and `halo release publish`. The guardrail interface allows an optional Rego evaluator to be added later for org-specific rules; it can only add restrictions, never remove built-in ones.

### Consequences

- Good: no extra runtime; invariants cannot be misconfigured away.
- Bad: org-specific rules require a Go change until the Rego hook ships; the roadmap item is tracked.
