---
title: Policy copilot
description: Draft policy changes, design sized experiments and explain plans from plain language. The model proposes, Halos' validator, plan, impact preview and statistics verify, and a human approves.
---

`halo copilot` turns an intent into a reviewed policy change. A language model drafts; Halos runs the same checks a human change faces; nothing is written until you pass `--apply`, and `--apply` only commits to a new local branch. Pushing, the PR, merging and starting an experiment stay with you. The design is in [ADR-0035](/halos/adr/0035-policy-copilot/).

## Configure the model

The copilot reuses the eval judge's provider client. Defaults:

| Flag | Default |
|---|---|
| `--model` | `claude-opus-5-5` (a pinned id) |
| `--llm-url` | the policy's gateway `baseURL` (a halo-proxy or Kong listener), else `https://api.anthropic.com` |
| `--wire` | `anthropic-messages` (or `openai-responses`) |
| `--api-key-env` | `ANTHROPIC_API_KEY`: the variable holding the credential; its value is never printed |

Plain `http` is accepted only to a loopback host. Every run has hard ceilings, checked before each call: `--max-iterations 3`, `--max-tokens 60000` (input plus output) and `--max-cost-usd 2` (estimated with `--price-in`/`--price-out` per million tokens). Each call logs one stderr line with its token counts; prompts and replies are logged only with `--debug`.

`--offline` uses deterministic templates instead of a model, for air-gapped machines and tests.

## Draft a change

```sh
halo copilot draft "move ring1-canary to Claude Code 2.1.300"
```

The model returns the whole new content of each YAML file it changes. Halos writes them over a copy of the policy and checks:

1. every written byte for a permission-bypass token (`policy.BypassToken`, comments included);
2. load and validation (`halo validate`);
3. a release build and diff for every ring (`halo plan`);
4. the impact preview (`halo plan --diff`'s policy estimate).

Errors go back to the model until the draft passes or a ceiling stops the run. The output is the file diff, the rings whose release changes, the impact summary and risk notes. A draft that does not pass exits 2 and writes nothing.

```sh
halo copilot draft "move ring1-canary to Claude Code 2.1.300" --apply
# ok committed to local branch halos/copilot-move-ring1-canary-to-claude-code-2-1-300-1a2b3c
# human gate: git push -u origin <branch> && gh pr create --head <branch> --fill
```

`--apply` re-runs the checks, refuses if a touched file has uncommitted changes, and commits in a temporary worktree, so your checkout and branch are untouched.

Offline, `draft` understands one template:

```sh
halo copilot draft --offline "set claude-code version 2.1.300 in profile engineering"
```

## Design an experiment

```sh
halo copilot experiment "opus-5-5 raises accept rate without hurting latency" \
  --baseline 0.31 --mde 0.05 --daily-units 400
```

The model proposes only the shape: name, rings, arms (one control), the primary metric and guardrails. You supply the numbers it must not invent: the primary metric's current mean (`--baseline`), its per-user standard deviation (`--sd`, derived as `sqrt(p(1-p))` for a rate), the relative minimum detectable effect (`--mde`), `--alpha`, `--power` and the users entering per day (`--daily-units`). `internal/stats` computes the per-arm sample size, `n = 2 (z(1-alpha/2) + z(power))^2 sd^2 / delta^2`, and the duration from the smallest arm's share. Halos renders `experiments/<name>.yaml` with `status: draft`, `stopping.minSamples` set to n and `maxDays` to twice the duration (at least 7), and checks it like a draft. mSPRT may stop earlier or need more than the fixed-horizon n; the output says so.

Offline, pass the design as flags:

```sh
halo copilot experiment --offline "cli-next raises accept rate" --name cli-next-accept \
  --ring ring1-canary --control engineering --treatment engineering-next \
  --metric halo.edit.accept_rate --baseline 0.31 --mde 0.05 --daily-units 400
```

Starting the experiment is a separate human step: `halo exp start <name>`.

## Explain

```sh
halo copilot explain diff main
halo copilot explain release ring1-canary --diff main
halo copilot explain experiment opus-5-5-canary --verdicts-file verdicts.json --scorecard sc.json --roi roi.json
```

Halos computes the facts (file diffs, each ring's plan, the impact, the experiment's settings, a verdict, a scorecard, an ROI report) as keyed values. The model must cite a fact key for every point; a point citing a key that does not exist is rejected and retried. The output ends with the facts used.

## What next

```sh
halo copilot next --verdicts-file verdicts.json --scorecard sc.json --roi roi.json
```

Rules over existing data, no model: draft experiments to start, running ones without a verdict to analyze, promote/rollback/expired verdicts, paused experiments, eval gates that block an arm, an ROI sample ratio mismatch, and, with `--server` and `HALO_SESSION`, budgets over a threshold. Each suggestion lists its evidence and the exact command; state-changing commands are marked `[human gate]`.

## From an agent (MCP)

`halo mcp serve` exposes the same flow without a provider key, because the calling agent is the model: `copilot_draft` checks the agent's files, `copilot_experiment` sizes its design, `copilot_explain` returns the facts to cite and `copilot_next` the suggestions. The `copilot` prompt drives the loop. Writes default to `dry_run`; `dry_run: false` needs `--allow-writes`, a reason and passing checks, and only commits a local branch. See [Agentic operations](/halos/guides/agentic-operations/).

## Limits

- Whole-file replacement can reformat a file the model rewrote; the diff shows it.
- The impact preview is the policy-only estimate, as for `halo plan --diff` without a server.
- Token usage comes from the provider's `usage` field; when it is absent the byte estimate is counted.
- No live provider was called in testing; the tests use a fake of both wires.
