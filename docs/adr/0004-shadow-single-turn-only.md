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
