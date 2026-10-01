---
title: "halo rollout simulate"
description: "Run the state machine on synthetic or recorded evidence (writes nothing)"
---

Run the state machine on synthetic or recorded evidence (writes nothing)

Runs the real gate logic (guardrails via the same sequential test as the controller) from "not started"
until the rollout completes, rolls back, pauses or hits --horizon, assuming every PR merges at once.
--scenario healthy|regression synthesises seeded per-user samples; --evidence replays a JSON array of
{"report": &lt;halo exp analyze --output json>, "approved": bool}, one per tick (the last repeats).

## Usage

```console
halo rollout simulate <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--approve-after` |  | duration | 4h0m0s | how long the simulated human takes to approve |
| `--breach-step` |  | int | 0 | regression: 0-based step index the regression starts at (default: the second guardrailed step) |
| `--evidence` |  | string |  | recorded evidence JSON (replaces the scenario) |
| `--horizon` |  | duration | 2880h0m0s | stop after this much simulated time |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--scenario` |  | string | healthy | synthetic evidence: healthy \| regression |
| `--seed` |  | uint64 | 1 | RNG seed (output is reproducible) |
| `--tick` |  | duration | 1h0m0s | controller tick |
| `--users-per-hour` |  | int | 1000 | new users the backing experiment sees per hour at 100% |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo rollout`](/halos/reference/cli/rollout/)
