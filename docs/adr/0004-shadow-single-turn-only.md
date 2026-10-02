---
title: "ADR-0004: Shadow traffic is single-turn only"
description: Why halo-shadow mirrors first-turn requests only, and what replaces it for whole tasks.
status: accepted
date: 2026-09-30
---

# ADR-0004: Shadow traffic is single-turn only

- Status: accepted
- Date: 2026-09-30

## Context and problem statement

Shadow testing sends a copy of production requests to a candidate and compares. That works for stateless request/response APIs. Coding agents are multi-turn: the model's output triggers tool calls (edit a file, run tests) whose results shape the next request. A shadow candidate's tool calls are never executed in the developer's workspace, so from turn 2 on the candidate would be responding to a conversation it did not produce. Executing them would be unsafe and would double side effects.

## Decision drivers

- Never cause side effects from a shadow.
- Do not report misleading comparisons.
- Zero impact on primary latency.

## Considered options

1. Full-session shadowing.
2. First-turn (single-turn) shadowing with an LLM judge, plus replay evals for whole tasks.
3. No shadowing.

## Decision outcome

Chosen: **option 2**. `halo-shadow` mirrors sampled, first-turn requests asynchronously (Kong OSS has no mirroring plugin, so we ship this), replays each to the control and candidate routes (non-streaming, using its own credentials), stores request/response pairs and grades them with a judge. Whole-task comparison uses containerized replay evals (`halo eval`) where tool calls really execute in a sandbox.

### Consequences

- Good: safe, cheap, off the hot path; catches regressions in format, refusal rate, latency and cost.
- Bad: does not measure multi-step agent quality. Documented prominently; do not promote on shadow alone (the recipe is shadow, then canary, gated by replay evals).
- Bad: judge bias; mitigate with rubric pinning and paired comparison.

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Mirror sampled, first-turn requests asynchronously; no primary-latency impact | `internal/gateway/decision.go` (`req.FirstTurn`, sample rate); `internal/shadow/mirror.go` (non-blocking queue, drops when full) | `decision_test.go` `TestShadowSampling`, `TestShadowEligibility`; `shadow_test.go` `TestMirrorerNonBlockingDrop`, `TestQueueFullDrops` | Done |
| Replay to control and candidate, non-streaming, with halo-shadow's own credentials | `internal/gateway/rewrite.go` (`stream: false` in the mirror body); `internal/shadow/server.go` `UpstreamHeaders` (per-upstream, never forwarded elsewhere) | `shadow_test.go` `TestPairCaptured`, `TestMirrorerURLValidation`, `TestBedrockPathStaysOnPolicyHost`; `cmd/halo-shadow` `TestLoadUpstreamHeaders` | Done |
| Store request/response pairs | `internal/shadow/shadow.go` (`FileStore`, encrypted, pruned) | `TestFileStore`, `TestFileStoreEncryptedAndPruned`, `TestDecryptPairs` | Done |
| Grade with an LLM judge; rubric pinning and paired comparison | `internal/eval/online.go` `RunOnline` (same pinned rubric `id@version` on both sides, delta paired by pair, bootstrap CI, win rate) | `online_test.go` `TestRunOnline`, `TestOnlineHistoryAndOTLP` | Done |
| Catches regressions in format, refusal rate, latency and cost | `internal/eval/online.go` (`OpsResult`: per-arm error rate, mean latency and output tokens over every pair, errored ones included; `halo.eval.shadow.*` metrics); format is the rubric's job | `online_test.go` `TestRunOnline` (ops), `TestOnlineHistoryAndOTLP` (metrics) | Done (was Partial: pairs carried latency and status but nothing read them) |
| Never cause side effects from a shadow | tool calls are never executed: the pair stores the response only (`internal/shadow/server.go`) | `TestPairCaptured` | Done |
| Whole-task comparison via containerized replay evals | `internal/eval` (`docker.go`, `driver.go`), `halo eval run` | `eval_test.go` `TestRunTrial`, `TestRunSuiteErrors`; `test/e2e` | Done |
| Do not promote on shadow alone; documented prominently | `internal/promote/promote.go` (judge evidence yields `hold`, promote needs gateway canary evidence); [shadow traffic](/halos/concepts/shadow-traffic/) and [security model](/halos/concepts/security-model/) | `promote_test.go` `TestShadowEvidenceNeverPromotes` | Done |
