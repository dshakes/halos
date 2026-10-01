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

Driver details are from vendor documentation (see [`internal/harness/FACTS.md`](https://github.com/dshakes/halos/blob/main/internal/harness/FACTS.md)); they were not run against real CLI releases here. A Codex run on an unmanaged, non-git workdir may need `--skip-git-repo-check`.

## Running

```bash
halo eval run evals/suites/cli-upgrade.yaml                       # text scorecard
halo eval run evals/suites/cli-upgrade.yaml --output json > scorecard.json
```

Flags: `--parallel` (default 2 trials at once), `--cpus 2`, `--memory 4g`, `--network none` (default: **no egress**), `--pass-env NAME,...` (host `UPPER_SNAKE` env vars forwarded into the agent step only), `--seed 1` (bootstrap seed, so confidence intervals reproduce), and `--local` to run on the host without isolation (testing only). Trials use images `ghcr.io/dshakes/eval-<harness>:<version>`; those images are not published yet, so build your own and override the image in the runner until then.

**Check:** the scorecard lists, per variant and task, pass rate, cost, latency and turns, with bootstrap confidence intervals against the control. `halo mcp serve` exposes the JSON form as the `eval_scorecard` tool.

## Practices

1. **Deterministic scorers first.** Tests and diffs beat LLM judges.
2. **Budget caps per task.** `budget_usd`, `max_turns` and `timeout` keep a non-converging eval from spending.
3. **Pin everything** in the variants; run baseline and candidate on identical fixtures with several `repeats`.
4. **No egress by default.** Give trials only what the task needs; forward credentials with `--pass-env`, scoped to a gateway token rather than a production key.
5. **Report variance.** Agents are non-deterministic; the scorecard uses bootstrap intervals across repeats.
