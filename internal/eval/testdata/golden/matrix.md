# Eval scorecard: matrix-fixture

Control: `claude@2.1.312/sonnet/anthropic`

**Gate: BLOCK**

| Variant | Trials | pass@1 (95% CI) | pass@2 | pass^2 | Cost/task | Wall p50 | Wall p95 | Tool calls | Tool errors | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| claude@2.1.312/sonnet/anthropic | 9 | 88.9% (66.7-100.0) | 100.0% | 77.8% | $0.2000 | 36.0s | 42.0s | 117 | 0 | 0 |
| claude@2.1.312/sonnet/bedrock | 9 | 88.9% (66.7-100.0) | 100.0% | 77.8% | $0.2100 | 36.0s | 42.0s | 117 | 0 | 0 |
| codex@0.60.0/gpt-5/anthropic | 9 | 66.7% (33.3-100.0) | 66.7% | 66.7% | $0.3500 | 36.0s | 42.0s | 117 | 0 | 0 |
| gemini@0.13.0/gemini-2.5-pro/anthropic | 9 | 100.0% (100.0-100.0) | 100.0% | 100.0% | $0.1200 | 72.0s | 84.0s | 117 | 0 | 0 |

## Paired comparison vs control

| Variant | Tasks | Delta pass rate (95% CI) | Verdict |
|---|---|---|---|
| claude@2.1.312/sonnet/bedrock | 3 | +0.0 pp (+0.0 to +0.0) | no_significant_difference |
| codex@0.60.0/gpt-5/anthropic | 3 | -22.2 pp (-100.0 to +33.3) | no_significant_difference |
| gemini@0.13.0/gemini-2.5-pro/anthropic | 3 | +11.1 pp (+0.0 to +33.3) | no_significant_difference |

## claude@2.1.312/sonnet/bedrock vs claude@2.1.312/sonnet/anthropic: SHIP

- non-inferior on 2 tasks: pass rate +0.0 pp (95% CI +0.0 to +0.0)

| Metric | Baseline | Delta (95% CI) |
|---|---|---|
| pass_rate | 100.0% | +0.0 pp (+0.0 to +0.0) |
| cost_usd | 0.2000 | +0.0100 (+0.0100 to +0.0100) |
| tokens | 20500 | +0 (+0 to +0) |
| wall_ms | 33500 | +0 (+0 to +0) |
| tool_calls | 12.5 | +0.0 (+0.0 to +0.0) |

Flaky tasks (excluded from the gate):

- `rename`: baseline passed 2/3 trials

## codex@0.60.0/gpt-5/anthropic vs claude@2.1.312/sonnet/anthropic: BLOCK

- pass rate CI lower bound -100.0 pp is below the -10.0 pp margin; inconclusive
- 1 tasks regressed (max 0)
- cost_usd up +75% (CI +75% to +75%), limit +25%

| Metric | Baseline | Delta (95% CI) |
|---|---|---|
| pass_rate | 100.0% | -50.0 pp (-100.0 to +0.0) |
| cost_usd | 0.2000 | +0.1500 (+0.1500 to +0.1500) |
| tokens | 20500 | +0 (+0 to +0) |
| wall_ms | 33500 | +0 (+0 to +0) |
| tool_calls | 12.5 | +0.0 (+0.0 to +0.0) |

Regressed tasks:

- `flag`: 100% -> 0%

Flaky tasks (excluded from the gate):

- `rename`: baseline passed 2/3 trials

## gemini@0.13.0/gemini-2.5-pro/anthropic vs claude@2.1.312/sonnet/anthropic: SHIP

- non-inferior on 2 tasks: pass rate +0.0 pp (95% CI +0.0 to +0.0)

| Metric | Baseline | Delta (95% CI) |
|---|---|---|
| pass_rate | 100.0% | +0.0 pp (+0.0 to +0.0) |
| cost_usd | 0.2000 | -0.0800 (-0.0800 to -0.0800) |
| tokens | 20500 | +0 (+0 to +0) |
| wall_ms | 33500 | +33500 (+31000 to +36000) |
| tool_calls | 12.5 | +0.0 (+0.0 to +0.0) |

Flaky tasks (excluded from the gate):

- `rename`: baseline passed 2/3 trials

<!-- terminal table -->
```
VARIANT                                 PASS@1  PASS@2  PASS^2    $/TASK      P50  TOOLS  VERDICT
claude@2.1.312/sonnet/anthropic            89%    100%     78%    $0.200    36.0s   13.0  baseline
claude@2.1.312/sonnet/bedrock              89%    100%     78%    $0.210    36.0s   13.0  ship
codex@0.60.0/gpt-5/anthropic               67%     67%     67%    $0.350    36.0s   13.0  block
gemini@0.13.0/gemini-2.5-pro/anthropic    100%    100%    100%    $0.120    72.0s   13.0  ship
gate: BLOCK
```
