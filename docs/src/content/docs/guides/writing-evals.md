---
title: Writing evals
description: Task specs, suites, headless drivers and scorecards for halo eval run.
---

An eval runs a task in Docker containers with a headless harness driver (each phase, `setup`, `agent` and `check`, gets a **fresh container** from the image with only `/work` carried over, so secrets passed to the agent step are not visible to the scorer and nothing the setup started survives), then scores the resulting workspace by a shell command. Whole-task comparison is what shadow traffic cannot give ([ADR-0004](/halos/adr/0004-shadow-single-turn-only/)).

## Task

`evals/tasks/<name>/task.yaml` plus a small fixture repo under `repo/`:

```yaml
# evals/tasks/fix-failing-go-test/task.yaml
id: fix-failing-go-test
repo: repo                 # git URL, or a directory relative to the task
prompt: |
  `go test ./...` is failing in this repo. Find the bug in the non-test code
  and fix it. Do not modify the tests.
check: go test ./...       # shell; exit 0 = pass
timeout: 10m
budget_usd: 1.0
max_turns: 20
tags: [go, bugfix, smoke]
```

Fields: `id`, `repo`, `setup` (shell commands run before the agent), `prompt`, `check`, `timeout`, `budget_usd`, `max_turns`, `tags`. Only the exit code of `check` counts. Roughly, against Harbor: `prompt` is `instruction.md`, `check` is `tests/test.sh`, `repo` plus `setup` is the `environment/` Dockerfile; Harbor's reward-file scoring is not read.

## Suite

`evals/suites/*.yaml` names tasks and the variants to compare:

```yaml
# evals/suites/model-upgrade.yaml
name: model-upgrade
tasks: [fix-failing-go-test, add-cli-flag, refactor-rename]
control: sonnet-current
repeats: 5
variants:
  - {name: sonnet-current,   harness: claude, version: "2.1.280", model: sonnet}
  - {name: sonnet-candidate, harness: claude, version: "2.1.280", model: sonnet-next}
```

A variant can add `settings: <path to a rendered managed-settings.json>` to mount that variant's rendered settings into its container.

## Drivers

| Harness | Command used |
|---|---|
| Claude Code | `claude -p --restricted --output-format stream-json --max-budget-usd` |
| Codex | `codex exec --json` (JSONL events: `turn.completed` usage, `turn.failed`, `item.completed`) |
| Gemini CLI | `gemini -p --output-format json` (`{response, stats, error?}`) |

Driver details are from vendor documentation (see [`internal/harness/FACTS.md`](https://github.com/dshakes/halos/blob/main/internal/harness/FACTS.md)); the Claude Code and Codex drivers run the pinned real CLIs in `make uat-clis` (`test/uat/clis_eval_test.go`, against a mock model server, so no real model quality is measured); the Gemini CLI driver is not covered there. A Codex run on an unmanaged, non-git workdir may need `--skip-git-repo-check`.

## Running

```bash
halo eval run evals/suites/cli-upgrade.yaml                       # text scorecard
halo eval run evals/suites/cli-upgrade.yaml --output json > scorecard.json
```

Flags: `--parallel` (default 2 trials at once), `--cpus 2`, `--memory 4g`, `--network none` (default: **no egress**), `--pass-env NAME,...` (host `UPPER_SNAKE` env vars forwarded into the agent step only), `--seed 1` (bootstrap seed, so confidence intervals reproduce), and `--local` to run on the host without isolation (testing only). Trials use images `ghcr.io/dshakes/eval-<harness>:<version>`; those images are not published to ghcr.io; build them from `evals/images` and tag them with those names (as `make uat-clis` does).

**Check:** the scorecard lists, per variant and task, pass rate, cost, latency and turns, with bootstrap confidence intervals against the control. `halo mcp serve` exposes the JSON form as the `eval_scorecard` tool.

## Step suites harvested from shadow traffic

A task suite tests whole outcomes on fixtures someone wrote. A **step suite** tests single decisions on real traffic: each case is one step of a production session, harvested from the [shadow](/halos/concepts/shadow-traffic/) pair store where the candidate went wrong ([ADR-0020](/halos/adr/0020-harvest-shadow-sessions-into-replay-evals/)).

```bash
halo eval harvest --pairs pairs.jsonl --pair-key-file pair.key \
  --experiment opus-5-5-shadow --out evals/steps/opus-5-5 \
  --history eval-history.jsonl --select diverged,invalid-call,premature-stop,judge-loss
halo eval steps run --suite evals/steps/opus-5-5 --model opus --url https://gateway.example.com --key-env HALO_GATEWAY_TOKEN
```

`--select` picks the steps:

| Reason | The step is a case when |
|---|---|
| `diverged` | The candidate's tools differed from the control replay, or from production's action |
| `invalid-call` | The candidate called a tool the request did not offer, missed a required argument, or produced a malformed call |
| `premature-stop` | Production kept working and the candidate ended its turn |
| `judge-loss` | The judge scored the candidate below the control by more than `--judge-loss` (default 0.2). Needs `--history` from `halo eval online` |
| `sample` | A seeded random sample of `--per-depth` steps (default 5) per depth bucket: 0, 1-4, 5-19, 20+ |

Auxiliary requests (no tools offered), byte-identical retries and steps an arm truncated are not steps and are never harvested.

Each case is one JSON file (`<id>.json`, mode 0600, directory 0700):

| Field | Holds |
|---|---|
| `request` | The real prefix, redacted, in the harness's wire protocol (Anthropic Messages, Bedrock, OpenAI Responses, Gemini) |
| `tools` | The offered tools and their required arguments |
| `expected`, `expectedFrom` | Production's action at that step when it was recovered, otherwise the control replay's |
| `alternatives` | Also accepted: the control replay, when it differed from production's action but was a valid call |
| `match` | `tools` (default: same multiset of tool names) or `calls` (same names and canonical arguments). Edit it per case |
| `reasons`, `provenance` | Why it was selected; pair id, experiment, hashed session, step depth, harvest time, redaction rules version. Never the raw session id |

A step whose expected action is itself an invalid call is skipped, not written.

**Redaction is always on and fails closed.** Only an allowlist of top-level request fields is kept (`model`, `system`, `messages`, `tools`, `input`, `contents`... ; add more with `--keep-field`), which drops Claude Code's `metadata.user_id`, Codex's `prompt_cache_key` and every other account or session identifier. Every string is then scanned for private keys, JWTs, vendor tokens (`sk-`, `ghp_`, `xoxb-`...), AWS access key ids, `Bearer`/`Basic` credentials, `PASSWORD=`-style assignments, high-entropy strings and emails, plus any `--redact-pattern` regex. Provider ids, thinking signatures and encrypted reasoning are exempt from the entropy rule only, so the request still replays. If a redacted request no longer parses as the same step, or a credential shape survives, the harvest fails and writes nothing. `--dry-run` prints the selection without writing. Redaction is pattern based: **review the cases before committing them**.

`halo eval steps run` replays every case against one model route, non-streaming, through the same request rewrite halo-shadow uses. `--model` is a gateway alias (with `--url` at the gateway) or an upstream model id; `--key-env` names the credential's variable. It grades each answer with the deterministic matcher (the `SameTools`/`SameCalls` and validity checks the shadow reading uses): **pass** means a valid call that matches the expected action or an alternative. The scorecard reports pass, same-tools, same-calls, valid-call and premature-stop rates with 95% CIs that resample **sessions**, so many steps from one long session do not narrow the interval. An errored call fails its case. `--rubric` with the `--judge-*` flags adds a judge score per step as a secondary reading; it never changes pass. The shape of the output (illustrative numbers):

```
suite evals/steps/opus-5-5  model opus  cases 48  sessions 17  errors 0

PASS              81% (70..90) n=48
SAME TOOLS        85% (75..93) n=48
SAME CALLS        52% (40..65) n=48
VALID CALLS       98% (94..100) n=48
PREMATURE STOP    6% (0..13) n=36
```

The MCP tool `eval_harvest` previews the selection (provenance and expected tool names only) and writes the cases only with `--allow-writes` and `dry_run: false`.

## Practices

1. **Deterministic scorers first.** Tests and diffs beat LLM judges.
2. **Budget caps per task.** `budget_usd`, `max_turns` and `timeout` keep a non-converging eval from spending.
3. **Pin everything** in the variants; run baseline and candidate on identical fixtures with several `repeats`.
4. **No egress by default.** Give trials only what the task needs; forward credentials with `--pass-env`, scoped to a gateway token rather than a production key.
5. **Report variance.** Agents are non-deterministic; the scorecard uses bootstrap intervals across repeats.
