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

## Addendum 2026-10-02: the three named guardrails, and the plug-in contract

- The three examples in the context are each a built-in: `guardNoBypass` plus `release.Check` (no `bypassPermissions` or `danger-full-access` in any ring; the release build re-parses every rendered file as a backstop), `guardSandboxEgress` (a ring profile with `permissions.sandboxRequired: true` must set a non-empty `egress.allowedDomains`, the managed-environment case), and `guardGARing` (the default ring ships hooks only with `hooks.managedOnly: true`).
- The plug-in point is `policy.ExtraGuardrails`, a slice of `func(*Org) []Issue` set at start-up. Extras run after the built-ins on a copy of the policy, so they can add issues but cannot remove, downgrade or edit what the built-ins judged. A Rego evaluator would register there; none ships yet (roadmap).

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Default guardrails are Go code in `internal/policy`, always run by `Validate` | `internal/policy/guardrails.go` (`builtinGuardrails`, unexported so no caller can drop one); `validate.go` | `guardrails_test.go` `TestSecurityGuardrails`, `TestSecurityGuardrailAllowances` | Done |
| No `bypassPermissions` / `danger-full-access` in any ring | `guardNoBypass`, `guardRingProfiles`; `internal/release/check.go` (rendered-output backstop); adapters never emit them (`codex.go`) | `TestSecurityGuardrails`; `release` `TestCheckRendered`, `TestBuildBackstop`; `claudecode` `TestRenderPassesReleaseChecks`, `TestOverridesCaughtByReleaseChecks` | Done |
| Egress non-empty for managed environments | `guardSandboxEgress` | `TestSandboxRequiredNeedsEgress` | Done (was Missing) |
| Hooks managed-only in GA | `guardGARing` | `TestGARingHooksManagedOnly` | Done |
| Run by `halo validate` and again at `release build` and `release publish` | `cmd/halo/root.go` `loadValid` (every `release` subcommand loads through it before any registry or key is touched; exit 2) | `cmd/halo` `TestValidate`, `TestReleaseBuildPublishGuardrailExit2` | Done |
| Plugin point for extra rules that can only add restrictions | `policy.ExtraGuardrails` (runs on a clone) | `TestExtraGuardrailsOnlyAdd` | Done |
| Optional Rego evaluator | not shipped; roadmap item | n/a | Open (tracked, not a GA commitment) |
| Guardrails documented | [policy model](/halos/concepts/policy-model/#guardrails) table | `make docs-gen` | Done |
