---
title: "ADR-0020: Harvesting shadow sessions into replay evals"
description: How halo eval harvest turns shadow steps where a candidate regressed into redacted step-level regression cases, and how halo eval steps run grades them.
status: accepted
date: 2026-10-21
---

# ADR-0020: Harvesting shadow sessions into replay evals

- Status: accepted (builds on [ADR-0014](/halos/adr/0014-step-level-multi-turn-shadow/))
- Date: 2026-10-21

## Context and problem statement

ADR-0014 measures every step of real agent sessions and says where a candidate regressed: it diverged from production, called a tool it was not offered, or stopped early. That reading is gone when the experiment ends. The task suites under `evals/` are written by hand and never contain the steps production found hard. Those failing steps are the best regression tests there are, but they sit in the halo-shadow pair store. That store is encrypted, holds raw prompts, code and terminal output, and is kept only for `-retention`.

## Decision drivers

- A regressed step must become a test that runs again on every future candidate.
- Nothing from a pair reaches disk unredacted. Redaction cannot be turned off, and any failure writes nothing.
- No raw session id leaves the pair store. Steps of one session must still be clustered in the statistics.
- One definition of "same action" and "valid call", shared with the shadow reading.
- No new trust boundary or side effect: harvesting and replay execute no tool call. A human decides what is committed.

## Considered options

1. Export whole sessions as task suites: rebuild the repository and replay the trajectory in a sandbox.
2. **Step-level cases.** One case per selected step: the real prefix, the offered tools, and production's action. A model answers the prefix once and a deterministic matcher grades its next action.
3. Keep the raw pairs and re-run `halo eval online` against new candidates.

## Decision outcome

Chosen: **option 2**. Option 1 needs the developer's repository at that moment. The pair has the conversation, not the workspace. Option 3 keeps unredacted pairs around indefinitely and inherits the store's retention and access problems.

- **Selection** (`halo eval harvest --select`): `diverged` (the candidate's tools differ from the control replay, or from production's action), `invalid-call` (a tool not offered, a missing required argument, or a malformed call), `premature-stop` (production kept working, the candidate stopped), `judge-loss` (control minus candidate judge score above a threshold, read from the `halo eval online` history, which now keeps per-pair scores by pair id), and `sample` (seeded, a fixed number per depth bucket 0, 1-4, 5-19, 20+). Steps come from the same parser ADR-0014 uses (`agentSteps`), so auxiliary requests, retries and truncated steps are never cases.
- **Case.** The redacted request in its own wire protocol, the offered tools with their required arguments, and the expected action. That is production's action when it was recovered, otherwise the control replay's. A valid control action that differs from production's is stored as an allowed alternative, because it is the incumbent model's own choice. A step whose expected action is itself invalid is skipped. `match` is `tools` by default and can be set to `calls` per case.
- **Provenance.** Each case records the pair id, experiment, `SessionUnit(session)` (a hash), step depth, harvest time and the redaction rules version. That version is the built-in version plus a hash of the operator's extra patterns and fields. The raw session id is never written.
- **Redaction** (`internal/eval/redact.go`), on by default with no off switch:
  - an allowlist of top-level request fields (`--keep-field` extends it). This drops `metadata.user_id`, `prompt_cache_key`, `user` and similar identifiers;
  - credential shapes in every string, reusing `policy.HasTokenShape` and `policy.LooksSecret`: private keys, JWTs, vendor tokens, AWS access key ids, `Bearer`/`Basic` values, `PASSWORD=`-style assignments, credential-named JSON keys, high-entropy strings;
  - emails;
  - operator regexes (`--redact-pattern`).
  Provider ids, thinking signatures and encrypted reasoning skip the entropy rule only, so the request still replays. After redaction the request must parse as the same step. Every encoded file is re-scanned for credential shapes, and all files are checked before the first one is written. Files are 0600 in a 0700 directory, written atomically.
- **Replay** (`halo eval steps run --suite DIR --model ROUTE --url URL`). Each case is sent non-streaming on its own protocol, through the rewrite halo-shadow uses (`gateway.ForceNonStreaming`, `gateway.RewriteRequest`). Grading uses `SameTools`, `SameCalls` and `toolSpec.validity` from `agentic.go`, not a copy. Pass means a valid call that matches the expected action or an alternative. Every rate has a session-clustered bootstrap CI (`stats.ClusterBootstrapMean`, clustered by the stored session hash). An optional rubric judge adds a secondary score that never changes pass.
- **MCP.** `eval_harvest` is registered always. Its dry run returns provenance and expected tool names, never content. `dry_run: false` needs `--allow-writes` and writes only under the policy dir.

### Consequences

- Good: every regression shadow found becomes a cheap, deterministic test of a real decision. A case costs one model call.
- Good: the test set keeps real prompts and tool outputs, the inputs that hand-written suites do not have.
- Bad: redaction is pattern based. A secret with no recognisable shape, or personal data that is not an email, can survive. The docs and the tool's `next_steps` require a human review before cases are committed.
- Bad: a step case is teacher-forced like the shadow reading. It tests one decision, not where the candidate's own trajectory would go. Task suites remain the outcome gate, and step suites never promote (invariant 5).
- Bad: redaction can change what the model sees (a redacted path or token), so a few cases may need `match: calls` loosened to `tools` or an alternative added by hand.
- Neutral: the eval history now keeps per-pair judge scores (pair id and two numbers, never the session) so `judge-loss` can be selected later.

## Implementation status (2026-10-21)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Selection: diverged, invalid call, premature stop, judge loss, depth sample; non-steps excluded | `internal/eval/harvest.go` `Harvest`; `agentic.go` `agentSteps` | `harvest_test.go` `TestHarvestSelection`, `TestHarvestNonSteps` | Done |
| Case with real prefix, offered tools, expected action, alternatives, provenance (hashed session) | `harvest.go` `buildCase`, `StepCase`, `Provenance` | `TestHarvestSelection`, `TestHarvestRunRoundTrip` | Done |
| Mandatory redaction: field allowlist, credentials, JWTs, keys, entropy, emails, operator regexes; fail closed; 0600 | `internal/eval/redact.go`; `harvest.go` `WriteStepCases` | `TestRedactorText`, `TestRedactorRequestAndVersion`, `TestHarvestFailsClosed`, `TestHarvestRunRoundTrip` | Done |
| Judge scores kept in history for judge-loss | `online.go` `PairScore`, `HistoryScores` | `TestHistoryScores` | Done |
| `halo eval steps run`: replay on the case's wire, shared matcher, session-clustered CIs, optional rubric | `internal/eval/steps.go` `RunSteps`, `GradeStep`; `cmd/halo/cmd_eval.go` | `TestGradeStep`, `TestHarvestRunRoundTrip`, `cmd/halo` `TestEvalHarvestAndSteps` | Done |
| MCP `eval_harvest`: preview without `--allow-writes`, content never returned | `internal/mcpserver/tools_eval.go` | `tools_harvest_test.go` `TestEvalHarvest` | Done |
| Replay against live provider APIs (headers such as `anthropic-beta` are not stored in pairs) | | | UNVERIFIED: tests use httptest models |
