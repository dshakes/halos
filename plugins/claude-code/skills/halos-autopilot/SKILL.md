---
name: halos-autopilot
description: Drive the whole Halos lifecycle hands-off (onboard, draft, validate, plan, eval, start an experiment, wait for evidence, promote or roll back, advance the rollout) and stop only at the human gates. Use when asked to "roll out X end to end", "run the rollout for me", "take this change to GA", or to monitor and finish an in-flight experiment or rollout.
---

# Halos autopilot

Tools come from the `halos` MCP server (`halo mcp serve`). The authoritative procedure is the server's `autopilot` prompt, also served as the resource `halos://guide/autopilot`; read it once per session. This file is the short form. Every tool answers with `next_steps`: the next call, or the exact command the human runs at a gate. Follow `next_steps`; never improvise shell edits to release state.

## Hard rules

- A human publishes releases (`halo release publish`), retags rings (`halo release promote|rollback`), merges and pushes to main. You print the command and stop.
- Every write tool: `dry_run: true` (default) first, show the patch, wait for a yes, then `dry_run: false`. Always a real `reason`. One yes covers one call.
- Rollback is the only automatic direction: `kill_switch` and `propose_rollback` need no verdict. Promotion needs `promote` from `wait_for` / `analyze_experiment`.
- Never emit `bypassPermissions` or `danger-full-access`. Never print or ask for a credential value.
- If a tool is missing, the server was started without `--allow-writes`, `--clickhouse` or `--server`: relay the restart command from `status.next_steps` and stop.

## The loop

1. `status`. Note what is in flight and which planes are on (writes, ClickHouse, halo-server).
2. First time only: `doctor` -> `detect_harnesses` -> `init_policy` or `onboard_company` (dry run, yes, write); `local_install`, `local_proxy`, `verify_harness` the same way (the `halos-onboard` skill has the detail).
3. Draft: edit the profile/ring/experiment YAML (read `halos://schema/<kind>` first); experiment `status: draft` in the first ring.
4. `validate` (no errors), `release_build` for the ring, `plan` against the current `release.tar`, `render_preview` for the ring's OS mix. Call out permissions, MCP, hooks and model changes.
5. `eval_matrix`, then `eval_run` (dry run, yes, real); `eval_scorecard`. `hold` or `block` stops here.
6. **GATE 1: approval to start.** Patch, plan, warnings, scorecard. Wait for yes.
7. Human publishes the release with the command from `release_build.next_steps`.
8. `start_experiment` (dry run, yes, real). Hand over the push/PR command from `next_steps`.
9. `wait_for kind=experiment` until `satisfied` (call again while false). `promote` -> step 10; `rollback` -> step 11; `expired` -> ask.
10. **GATE 2: approval to promote.** `propose_promotion` dry run, yes, real: it opens the PR; a human merges. Then per ring: `wait_for kind=rollout`, `propose_rollout_advance` (`open_pr: true` after a yes), repeat from step 9.
11. Rollback: `kill_switch` (dry run, yes, real) for the immediate stop; `propose_rollback` or `propose_rollout_rollback` to record it; `halo rollback` (registry) is human.
12. `audit_tail`, `kill_switch_status`, `fleet_status` to confirm what the fleet did. Report tool outputs verbatim, not paraphrased.
