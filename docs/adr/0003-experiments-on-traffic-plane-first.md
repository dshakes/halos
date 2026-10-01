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
