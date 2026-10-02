---
title: "ADR-0003: Experiments on the traffic plane first"
description: Prefer gateway-side assignment for model experiments; client-axis experiments use rings.
status: accepted
date: 2026-09-30
---

# ADR-0003: Experiments on the traffic plane first

- Status: accepted
- Date: 2026-09-30

## Context and problem statement

An experiment can vary the client (a different release or profile on the machine) or the traffic (a different model route at the gateway). Client-side variation needs a delivery round trip and cannot be changed mid-flight without touching machines. Traffic-side variation is a gateway config change.

## Decision drivers

- Speed and reversibility of changing an allocation.
- Trustworthy assignment (clients must not choose their own arm).
- Sticky assignment: an agent session must never switch model mid-task.

## Considered options

1. Client-side assignment only.
2. Traffic-plane assignment (`halo-kong` plugin) for model experiments; client-axis experiments realized as ring/release assignment.

## Decision outcome

Chosen: **option 2**. Model upgrades are traffic-axis experiments: `halo-kong` derives the cohort from the verified identity (`hash(user, salt)`), rewrites the model alias to the variant route, and stamps `x-halo-*` headers. Client-axis experiments (CLI upgrade, new hook) use ring-scoped releases. Assignment is sticky per user and per session.

### Consequences

- Good: changing or killing a model experiment takes effect without touching clients.
- Good: clients cannot self-select an arm; spoofed `x-halo-*` are stripped.
- Bad: requires a gateway plugin (see ADR-0006); `both`-axis experiments need coordination across planes.
- Bad: the API surface must speak each harness's wire protocol (Anthropic messages, Bedrock, OpenAI Responses).

## Addendum 2026-10-02: what "sticky" means, and no `both` axis

- **Stickiness.** The variant comes from `hash(user, salt)` alone (`internal/assign` via `policy.Experiment.ResolveVariant`), so a user keeps the same arm across sessions and machines. Within a variant, the route target is chosen by `StickyKey(user, session)`. A session changes model only when the allocation itself changes (weights, salt, pause or a [kill](/halos/adr/0009-signed-kill-switch/)). That is intended: a kill must take effect mid-session. There is no per-session pin that would hold an old arm.
- **No `both` axis.** The consequence above anticipated `both`-axis experiments. They are not offered: `axis` is `client` or `traffic` and validation rejects anything else. An org that wants both runs two experiments. [ADR-0010](/halos/adr/0010-release-channels-for-client-experiments/) defines how the gateway attributes a request when both apply (traffic-axis wins).

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Cohort from verified identity, `hash(user, salt)` | `cmd/halo-kong/main.go` (`PrepareVerified`); `internal/policy/resolve.go`; `internal/assign` | `assign_test.go` `TestBucketKnownAnswers`; `resolve_test.go` `TestResolveVariantSalt`; `halo-kong` `TestAccessRejectsUnverifiedByDefault` | Done |
| Rewrite the model alias and stamp `x-halo-*` | `internal/gateway/decision.go`, `rewrite.go` | `decision_test.go` `TestPrepareRewrites`; `test/uat/kong` | Done |
| Spoofed `x-halo-*` stripped | gateway `Prepare`, `halo-proxy` | `decision_test.go` `TestSpoofingImpossible`; `halo-kong` access tests; `halo-proxy` `proxy_test.go` | Done |
| Sticky per user and per session | `resolve.go`; `decision.go` (`StickyKey`) | `TestCanarySplitAndSticky`; `TestResolveVariantStickyAndDistribution` | Done (scope clarified above) |
| Client-axis experiments use ring-scoped releases | ADR-0010 channels; `cmd/halod/agent.go` `selectVariant` | `cmd/halod` `TestVariantSelectionMatchesGateway`; `test/e2e` `TestClientAxisExperiment` | Done |
| Anthropic, Bedrock and OpenAI Responses wires | `internal/gateway/inspect.go`, `internal/gateway/adapters` | `decision_test.go` `TestInspect`; `translate_test.go` | Done (Gemini too) |
| `both`-axis coordination | not offered (addendum above) | `policy` axis validation | Superseded |
