---
title: "ADR-0035: Policy copilot"
description: An LLM drafts policy changes, experiment designs and explanations; Halos' deterministic validator, plan, impact preview, bypass-token check and internal/stats verify them; a human approves every write. Output is schema-checked, every call is token- and cost-capped, and an offline template mode needs no model.
status: accepted
date: 2026-10-27
---

# ADR-0035: Policy copilot

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

Writing Halos policy is precise work: a ring, a profile, an experiment with arms, a primary metric, guardrails, an alpha, a minimum sample and a stop date. Operators know what they want ("move ring1 to Claude Code 2.1.300", "does opus-5-5 raise accept rate without hurting latency?") but translating that into valid YAML, sizing the experiment and reading the plan output takes expertise. Language models are good at the translation and bad at being trusted: they invent fields, drift from the schema, get arithmetic wrong and can be talked into emitting `bypassPermissions`.

How can Halos let a model draft and explain policy without letting the model decide anything?

## Decision drivers

- The model proposes; deterministic code verifies; a human approves. No model output reaches a release, a ring pointer or a merge.
- Invariant 1 holds against the model: a bypass token in anything it writes is an error, even inside a YAML comment that validation would not see.
- Invariant 5 holds: the copilot writes at most a local branch. It never pushes, opens a PR, merges or promotes.
- Numbers come from code. Sample size, minimum detectable effect and duration are computed by `internal/stats`, never by the model.
- Explanations cite Halos outputs only. A claim without a citation to a field Halos produced is rejected.
- Bounded spend: a hard ceiling on iterations, tokens and estimated cost per run, checked before each call.
- No prompt text in logs by default; credentials only from an environment variable, never printed.
- Works air-gapped: an offline template mode with the same verification and output shape.
- No new dependency, provider client or trust boundary.

## Considered options

1. **Model drafts, Halos verifies in a bounded repair loop, human approves.** Chosen.
2. **Model emits commands that Halos runs.** Rejected: the model would choose actions; a confused or injected model could pick `rollback` or `kill` with real effects.
3. **Model output written straight to the working tree for the human to review with `git diff`.** Rejected: it skips the deterministic gate and leaves a half-valid policy where `halo release build` can pick it up.
4. **A separate copilot service holding provider keys.** Rejected: a new process and a new credential holder for something a CLI can do with the operator's own key.

## Decision outcome

### One provider client

The copilot reuses the eval judge's provider client (`eval.HTTPLLM`): the Anthropic Messages or OpenAI Responses wire, temperature 0, https only (plain http only to loopback), the credential read from one named environment variable (`--api-key-env`, default `ANTHROPIC_API_KEY`) and sent only in the provider's auth header. The base URL defaults to the policy's gateway `baseURL` (a halo-proxy or Kong listener, so calls carry the org's routing, budgets and audit), else `https://api.anthropic.com`. The model defaults to `claude-opus-5-5` and must be a pinned id. `HTTPLLM` now also returns the provider's reported token usage.

### Structured output

Every model reply must be one JSON object matching a Go-side schema (a struct decoded with unknown fields disallowed, plus semantic checks). The schema text is sent in the system prompt. A reply that fails is not used: the failure becomes feedback for the next iteration, which counts against the same ceilings.

### Ceilings and logging

Per run: `--max-iterations` (default 3), `--max-tokens` (input plus output, default 60000) and `--max-cost-usd` (default 2, from `--price-in`/`--price-out` per million tokens). Before each call the copilot estimates the worst case (prompt bytes / 4 plus the output cap) and stops if it would cross a ceiling; after each call it adds the provider's reported usage (or the estimate when none is reported). Each call logs one stderr line: call number, model, input, output and total tokens, estimated cost. Prompt and reply text are logged only with `--debug`.

### `halo copilot draft "<intent>"`

The model returns whole-file contents for the policy YAML files it changes. Paths must be relative `.yaml`/`.yml` files inside the policy directory. Halos copies the policy to a temporary directory, writes the files, and checks:

1. every written byte with `policy.BypassToken` (comments included);
2. `policy.Load` and `Org.Validate` (errors fail, warnings are reported);
3. `release.BuildRing` for every ring, diffed against the current policy's build (`release.Diff`);
4. the impact preview (`impact.Compute` over `impact.PolicyMembers`, the same estimate as `halo plan --diff`).

Errors go back to the model as feedback until it passes or a ceiling stops the run. The result is the unified file diff, the per-ring plan, the impact summary and risk notes (the model's, plus deterministic ones: rings whose release changes, members affected, warnings). `--apply` re-runs the checks and refuses unless they pass, then commits the files to a new local `halos/copilot-*` branch with `promote.CommitOnBranch` (a temporary worktree; the user's checkout is untouched). It refuses when a touched file has uncommitted changes, because the draft was made against the working tree and the commit is made against HEAD. Pushing and the PR are human steps.

### `halo copilot experiment "<hypothesis>"`

The model proposes only the design: name, axis, rings, arms (profiles or routes, one control), primary metric and direction, guardrails. The human supplies the baseline mean, the standard deviation (derived as `sqrt(p(1-p))` for a rate metric when omitted), the relative MDE, alpha, power and expected daily units. `stats.SampleSize` computes the per-arm sample size of a two-sided two-sample z-test, `n = 2 (z(1-alpha/2) + z(power))^2 sd^2 / delta^2`, and the duration in days from the smallest arm's share of daily units. Halos renders the experiment YAML itself (status `draft`, `stopping.minSamples` = the per-arm n, `maxDays` = twice the duration, at least 7) and runs the same checks as `draft`. Because promotion uses an always-valid mSPRT, the fixed-horizon n is a minimum, not a guarantee of power. Starting the experiment stays a human step (`halo exp start`).

### `halo copilot explain release <ring> | diff <git-ref> | experiment <name>`

Halos computes the facts (plan, file diff, impact, experiment fields, a verdict from `--verdicts-file`, a scorecard gate, an ROI report) as keyed values. The model sees them fenced as untrusted data (the eval judge's nonce fencing) and must return points that each cite at least one fact key; a point citing a key that does not exist is rejected. The output lists the facts used.

### `halo copilot next`

Deterministic, no model: rules over the policy (draft, running, paused experiments), the verdicts file, eval scorecards, an ROI report and, with `--server` and `HALO_SESSION`, budget counters. Each suggestion carries its evidence and the exact command. Commands that change state are marked as human gates.

### Offline mode

`--offline` replaces the model with deterministic templates: `draft` understands `set <harness> version|model <value> in profile <name>`; `experiment` builds the design from flags; `explain` renders a templated summary of the same facts with the same citations. No network call is made.

### MCP

The calling agent is the model, so the MCP tools never call a provider: `copilot_draft` takes the agent's files and returns the same checks (dry run by default; `dry_run: false` needs `--allow-writes`, a reason and passing checks, and commits to a local branch); `copilot_experiment` computes the design's statistics and YAML (same write rule); `copilot_explain` returns the keyed facts; `copilot_next` returns the suggestions. The `copilot` prompt drives the draft, check, fix loop with the human gates.

## Consequences

- Good: operators get YAML, sized experiments and plain-language plans from intent, and nothing the model writes is trusted until the same checks a human change faces have passed.
- Good: an injected or confused model can at worst produce a rejected draft or a branch a human reviews; it cannot publish, promote, merge or emit a bypass token.
- Bad: whole-file replacement can reformat a file the model rewrote; the diff shows it and the human reviews it.
- Bad: the policy-only impact estimate is approximate (as for `halo plan --diff` without a server).
- Bad: the sample size assumes independent units and a normal approximation; mSPRT may need more samples. The output says so.
- Neutral: token usage relies on the provider's `usage` field; when absent the byte estimate is used, which can be off by tens of percent. The ceilings are checked against the larger of the two before each call.
- Neutral: live provider calls were not made in building this; tests use an httptest fake of both wires.

## More information

`internal/copilot`, `internal/stats/power.go`, `internal/eval/judge.go` (`HTTPLLM.CompleteUsage`, `Fence`), `cmd/halo/cmd_copilot.go`, `internal/mcpserver/tools_copilot.go`; [Policy copilot guide](/halos/guides/policy-copilot/).
