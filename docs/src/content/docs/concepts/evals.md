---
title: Evals and the measure loop
description: Offline replay evals with pass@k and pass^k, a pinned LLM judge, the harness × model × provider matrix, flake detection, a ship/hold/block gate, and online grading of shadow traffic.
---

Evals answer one question before a change reaches a ring: **is the candidate at least as good as what runs today?** `halo eval run` replays real tasks in containers, grades each trial, and returns a verdict: **ship**, **hold** or **block**. `halo eval online` keeps asking that question after rollout by grading shadow pairs.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/measure-loop-light.svg" alt="A change is evaluated offline, exposed to a ring, measured through OTEL in ClickHouse and judged by mSPRT. A pass opens a promotion PR a human merges; a breach rolls back automatically and fires the signed kill switch." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/measure-loop-dark.svg" alt="A change is evaluated offline, exposed to a ring, measured through OTEL in ClickHouse and judged by mSPRT. A pass opens a promotion PR a human merges; a breach rolls back automatically and fires the signed kill switch." width="880" />

## What gets measured

- **pass@1, pass@k, pass^k.** Each task runs `repeats` times. pass@k is the unbiased per-task chance that *any* of k trials passes, so it measures capability. pass^k is the chance that *all* k pass, so it measures reliability. Both are averaged over tasks.
- **Cost, tokens, wall time, tool calls**, per task, as the harness reports them.
- **Graders** run on every trial: the task's own check, plus suite-wide `diff` limits and `judge` rubrics.

## The judge

A pinned model (exact id, no `latest` aliases) reached through your gateway at temperature 0. It grades against a versioned rubric (`id@version` is recorded in the scorecard). The reply must be one strict JSON object with a score for every criterion and a non-empty rationale. Anything else is a **grader error**: never a pass, and it forces the gate to **hold**. Verdicts are cached by rubric, model and input hash, so reruns don't pay twice.

## The gate: ship, hold, block

The candidate is compared with the control **paired by task**, using bootstrap 95% CIs on the delta of pass rate, cost, tokens, wall time and tool calls.

| Verdict | When |
|---|---|
| **ship** | Pass-rate CI lower bound ≥ −`max_pass_drop`, no regressed task over the limit, every set cost/latency limit inside its CI |
| **hold** | Inconclusive: a CI straddles a margin, too few non-flaky tasks (`min_tasks`), or any grader error |
| **block** | Pass rate significantly worse, more regressed tasks than `max_regressed_tasks`, or a cost/latency limit confidently exceeded |

**Flake detection.** A task whose *baseline* passes some trials and fails others is flagged flaky and left out of every gated statistic, with the reason in the scorecard. A task that flips on unchanged code can't attribute a flip to the candidate.

## Example suite

```yaml
# evals/suites/upgrade-gate.yaml (excerpt)
name: upgrade-gate
tasks: [fix-failing-go-test, add-cli-flag, refactor-rename]
control: current
repeats: 5          # trials per task
k: 3                # pass@3 and pass^3
gate:
  max_pass_drop: 0.05          # ship needs the pass-rate CI lower bound >= -5 pp
  task_regression: 0.5         # a task losing >= 50 pp has regressed...
  max_regressed_tasks: 0       # ...and any regressed task blocks
  max_cost_increase: 0.20      # relative to baseline; only gated when set
  min_tasks: 2                 # fewer non-flaky tasks -> hold
judge: {url: https://ai.acme.example, wire: anthropic-messages, model: claude-sonnet-5-5, api_key_env: HALO_EVAL_GATEWAY_TOKEN}
variants:
  - {name: current,   harness: claude, version: "2.1.312", model: sonnet}
  - {name: candidate, harness: claude, version: "2.1.330", model: sonnet}
matrix:
  baseline: claude@2.1.312/sonnet/orchestrator
  harnesses:
    - {harness: claude, version: "2.1.312", models: [sonnet]}
    - {harness: codex,  version: "0.60.0",  models: [codex-default]}
  providers:
    - {name: orchestrator}
    - {name: anthropic-direct, aliases: {sonnet: sonnet-direct}}
```

## The matrix

`--matrix` expands the suite into cells named `<harness>@<version>/<model>/<provider>` and gates every cell against the baseline cell. Providers are gateway model aliases, so the CLI side stays provider-agnostic: the gateway routes each alias to its upstream.

```console
$ halo eval run evals/suites/upgrade-gate.yaml --matrix --report report.md --fail-on block
VARIANT                                 PASS@1  PASS@2  PASS^2    $/TASK      P50  TOOLS  VERDICT
claude@2.1.312/sonnet/anthropic            89%    100%     78%    $0.200    36.0s   13.0  baseline
claude@2.1.312/sonnet/bedrock              89%    100%     78%    $0.210    36.0s   13.0  ship
codex@0.60.0/gpt-5/anthropic               67%     67%     67%    $0.350    36.0s   13.0  block
gemini@0.13.0/gemini-2.5-pro/anthropic    100%    100%    100%    $0.120    72.0s   13.0  ship
gate: BLOCK
```

This table is the renderer's real output for the matrix test fixture (`internal/eval/testdata/golden/matrix.md`). A live run needs Docker and the harness images in `evals/images/`. `--report` writes a Markdown scorecard ready for a PR comment. `--fail-on block|hold` exits 3, which makes it a CI gate. Trials run with no network egress by default.

## The online loop

```console
$ halo eval online --pairs /var/lib/halo-shadow/pairs.jsonl --pair-key-file key.b64 \
    --rubric evals/rubrics/code-change-quality.yaml \
    --judge-url https://ai.acme.example --judge-model claude-sonnet-5-5 \
    --history scorecards.jsonl --otlp https://otel.acme.example:4319
```

This samples [halo-shadow](/halos/concepts/shadow-traffic/) pairs per experiment (a seeded shuffle, so reruns grade the same pairs) and judges both sides. For each experiment it reports the candidate − control score delta with a bootstrap CI, plus a win rate. Results go to the scorecard history (already-graded pairs are skipped) and are emitted as `halo.eval.*` metrics to the authenticated gateway receiver, so `halo exp analyze` and the [controller](/halos/concepts/experiments/) can read them next to latency and cost. Pairs where either side errored are skipped: that is a reliability signal, not a quality one.

Related: [writing evals](/halos/guides/writing-evals/), [reliable upgrades](/halos/guides/reliable-upgrades/), [evidence plane](/halos/concepts/evidence-plane/), [metrics reference](/halos/reference/metrics/).
