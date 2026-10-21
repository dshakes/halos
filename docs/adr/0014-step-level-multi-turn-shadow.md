---
title: "ADR-0014: Step-level shadowing of multi-turn agent sessions"
description: How halo-shadow compares a candidate on every step of real coding-agent sessions without executing anything, and how the result is read statistically.
status: accepted
date: 2026-10-21
---

# ADR-0014: Step-level shadowing of multi-turn agent sessions

- Status: accepted (amends [ADR-0004](/halos/adr/0004-shadow-single-turn-only/))
- Date: 2026-10-21

## Context and problem statement

ADR-0004 limited shadow traffic to first-turn requests. Its reasoning: from turn 2 on, a candidate would be answering a conversation it did not produce, and executing its tool calls would double side effects. That is true of **trajectory** shadowing. It does not rule out a **step-level** comparison, and the first-turn limit leaves most agent traffic unmeasured. A Claude Code, Codex or Gemini CLI session is dozens of model calls. Each call after the first carries the real tool results: terminal output, test failures, file contents, diffs. Those are where models differ most: whether they read the failure correctly, call a tool that exists, pass valid arguments, or stop before the work is done.

## Decision drivers

- Never execute a shadow's tool calls. Never send side effects anywhere.
- Never report a trajectory comparison that was not run.
- Measure the steps where agents fail in practice: after tool results.
- Statistical validity: steps of one session are not independent samples.
- Zero primary-latency impact. Bounded cost.

## Considered options

1. Keep first-turn only (ADR-0004).
2. **Teacher-forced step shadowing.** Mirror every step of a sampled session. Each step replays the real prefix to both arms, and only the next action is compared.
3. Simulated-environment trajectory shadowing. Answer the candidate's tool calls from recorded results until it diverges, then stop.
4. Full trajectory replay in a sandbox, which is `halo eval run`.

## Decision outcome

Chosen: **option 2**, alongside option 4. Option 3 was rejected: after the first divergent call, a recorded result is not the result the candidate's call would have produced. "Matching" outputs then hide divergence instead of measuring it, which is the misleading comparison ADR-0004 warned about.

A shadow experiment sets `turns: all`. The default `first` keeps ADR-0004 behaviour.

- **Sampling is per session.** It uses the same `assign.Bucket(salt/shadow, session)` as before, so a sampled session is mirrored on every step and an unsampled one on none. Eligibility needs a parsed model call with its history in the request. `count_tokens` is never eligible. A Responses call chained by `previous_response_id` is not eligible either, because the prefix lives server-side and a replay would not carry it.
- **What is compared.** Each pair holds the developer's real prefix. Both arms answer it, non-streaming, and nothing they return is executed. `internal/eval/agentic.go` reads each arm's **action**, the multiset of tool calls (name and canonical arguments), or "ended its turn". It reads all four wire protocols: Anthropic Messages, Bedrock (invoke and Converse), OpenAI Responses, and Gemini.
- **Production reference.** When the session's following step was also mirrored, its request contains the action production actually took at this step. It is recovered only when that later request's history extends this one: same length plus one model turn, and the same last pre-step turn with cache markers stripped. Subagent and compacted conversations share the session id but not the prefix, so they are never used as a reference.
- **Metrics per experiment.**
  - **Tool agreement** and **argument agreement**: candidate vs control replay.
  - **Fidelity** of each arm: agreement with production's action. The control's fidelity is the noise floor, the same model re-sampled, and the candidate is read against it. **Fidelity delta** is candidate minus control, paired by step.
  - **Invalid-call rate**: a tool the request did not offer, or a missing required argument.
  - **Premature-stop rate**: the arm ended its turn where production kept working.
  - **Divergence**: share of sessions, and mean first step.
  - Agreement **by depth**, for steps 0, 1-4, 5-19 and 20+.
- **Statistics.** Steps of one session are correlated, so every interval is a **session-clustered bootstrap** (`stats.ClusterBootstrapMean`, `stats.PairedClusterBootstrap`). This includes the judge-score delta, which previously assumed independent pairs. With one pair per session the cluster bootstrap is identical to the old pair bootstrap, a property the tests check, so first-turn readings are unchanged. Exported analysis samples (`halo.eval.agent.fidelity`, `halo.eval.agent.invalid_call_rate`) are one per **session** and arm. Their `halo.unit` is a hash of the session id, so `halo exp analyze`'s per-unit tests stay valid and raw session ids never leave the eval host.
- **Judge.** The judge sees the head of the request (system prompt and task) and its **tail** (the latest tool results). Before this change it saw only the first 24 KiB, which on a long session cut exactly the state being answered.
- **Promotion.** Unchanged. Step-level evidence measures decisions, not outcomes. It can pause or roll back an experiment through the registered `halo.eval.agent.*` guardrails, and it never promotes. Promotion still needs gateway canary evidence (invariant 5; `TestShadowEvidenceNeverPromotes`).

### Consequences

- Good: every step of real agent sessions is measured, including the steps after terminal output where models differ, at no risk. Nothing is executed and the developer's response is untouched.
- Good: there is a measured noise floor. "92% agreement" means something only next to the control's own agreement with production.
- Bad: cost scales with session length, because every step replays the full prefix to two arms. The bounds are `sampleRate`, `maxSpendUSD`, halo-shadow's `-budget-usd` reservation and the proxy's mirror `maxBytes` (default 1 MiB; long sessions exceed it and are not mirrored past that point unless it is raised). halo-shadow accepts bodies up to 8 MiB.
- Bad: teacher forcing measures each decision given the real state, not where the candidate's own trajectory would have gone. Option 4, the sandboxed replay evals, remains the whole-task gate.
- Neutral: the mirror and job format are unchanged. The gateway marks any-turn eligibility (`RequestInfo.AnyTurn`), and step depth is derived from the stored request at grading time, so old halo-shadow builds accept the new jobs.

## Implementation status (2026-10-21)

| Commitment | Code | Test | Status |
|---|---|---|---|
| `turns: first\|all` on shadow experiments, validated | `internal/policy/types.go` (`Experiment.Turns`), `validate.go`; `schemas/experiment.schema.json` | `policy_test.go` (`shadow turns unknown`, `turns on a non-shadow experiment`) | Done |
| Any-turn eligibility, session-keyed sampling; count_tokens and `previous_response_id` excluded | `internal/gateway/inspect.go` (`inspect`, `AnyTurn`), `decision.go` `shadowTargets` | `decision_test.go` `TestShadowEligibility`, `TestNewRequestInfoAnyTurn` | Done |
| Action extraction across Anthropic, Bedrock invoke/Converse, Responses, Gemini; offered tools and required args | `internal/eval/agentic.go` `parseRequest`, `parseResponse`, `toolSpec.validity` | `agentic_test.go` `TestParseProtocols` | Done |
| Production reference with prefix check (subagents, compaction excluded) | `agentic.go` `reference` | `TestAnalyzeAgentSession` (subagent pair), `TestParseProtocols` (Codex reference) | Done |
| Agreement, fidelity, noise floor, invalid calls, premature stop, divergence, depth | `agentic.go` `AnalyzeAgent` | `TestAnalyzeAgentSession` | Done |
| Session-clustered bootstrap for every interval, judge delta included | `internal/stats/bootstrap.go`; `internal/eval/online.go` | `stats_test.go` `TestClusterBootstrapMean` | Done |
| Per-session analysis samples, hashed unit; registered guardrail metrics | `online.go` `Export`, `SessionUnit`; `internal/policy/metrics.go`; `internal/promote/source.go` `evalMean` | `TestOnlineAgentExport` | Done |
| Judge sees the tail of long requests | `online.go` `clip` | `TestClipKeepsTail` | Done |
| Never promote on shadow evidence | `internal/promote/promote.go` | `promote_test.go` `TestShadowEvidenceNeverPromotes` | Done (unchanged) |
