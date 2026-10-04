# Halos autopilot: the full lifecycle, stopping only at human gates

Halos is a control plane for AI coding CLIs (Claude Code, Codex, Gemini CLI, Copilot CLI). A policy repo (profiles, rings, experiments, rollouts, toggles) renders to signed, content-addressed releases; rings point at releases; changes roll out ring by ring behind experiments with guardrails and eval gates. You drive it through the `halos` MCP tools. Every tool answers with `next_steps`: the next call, or the exact command a human runs at a gate.

## Invariants (enforced in code; do not work around them)

1. Never emit `bypassPermissions` or `danger-full-access` in any config, ring or profile.
2. No tool publishes a release, retags a registry ring, merges, or pushes to main. `halo release publish`, `halo release promote|rollback` and the merge button are human steps: print the command and stop.
3. Every write tool defaults to `dry_run: true` and needs a `reason`. Show the patch, wait for an explicit yes, then call again with `dry_run: false`. One yes covers one call.
4. Rollback is the only automatic direction: `kill_switch` and `propose_rollback` need no promotion verdict; promotion needs a `promote` verdict from evidence.
5. Releases are immutable; rollback means re-pointing a ring at a known-good digest.
6. Never print or ask for a credential value. `doctor` only says whether a variable is set.

If a tool you need is missing, the human started the server without `--allow-writes`, `--clickhouse` or `--server`: say so with the restart command from `status.next_steps`. Do not substitute shell edits to release state.

## The loop

Call `status` first; it tells you what is in flight and what this server can do.

1. **Onboard** (first time only): `doctor`, fix every `fail`; `detect_harnesses`; then `init_policy` (my machine) or `onboard_company` (my company), dry run, yes, write. `local_install`, `local_proxy`, `verify_harness` the same way.
2. **Draft the change**: edit profile/ring/experiment YAML in the policy repo (read `halos://schema/<kind>` and the existing files first). The experiment starts as `status: draft` in the first ring.
3. **Validate**: `validate`. Fix every error; explain warnings. Never continue on errors.
4. **Plan**: `release_build` for the ring (digest, versions, adapter warnings), `plan` against the current `release.tar`, `render_preview` for the ring's OS mix. Call out permissions, MCP servers, hooks and model changes.
5. **Eval**: `eval_matrix` to see the cells, then `eval_run` (dry run shows the command; it spends credentials, so it is gated like a write). `eval_scorecard` on the result; a `hold` or `block` gate stops here.
6. **GATE: approval to start.** Present the patch, plan, warnings and scorecard. Wait for yes.
7. **Publish** (human): the release the ring will pin is published with the `halo release publish` command from `release_build.next_steps`. You never run it.
8. **Start**: `start_experiment` (dry run, yes, real). It commits to a local branch; `next_steps` prints the push and PR command for the human.
9. **Wait for evidence**: `wait_for kind=experiment` (bounded; call again while `satisfied` is false). Verdicts: `continue` keep waiting; `rollback` go to step 11; `promote` go to step 10; `expired` ask the human.
10. **GATE: approval to promote.** `propose_promotion` dry run shows the verdict and the ring re-point; on yes, `dry_run: false` opens the PR. A human merges. Then `wait_for kind=rollout` / `propose_rollout_advance` (`open_pr: true` opens the PR) for the next ring, and repeat from step 9 per ring.
11. **Rollback path**: `kill_switch` (dry run, yes, real) stops the experiment fleet-wide at the next poll; then `propose_rollback` (experiment) or `propose_rollout_rollback` (rollout) records it in policy and `next_steps` prints the push/PR command. Re-pointing the registry (`halo rollback`) is human.
12. **Audit**: `audit_tail`, `kill_switch_status`, `fleet_status` to confirm what the fleet actually did.

Stop at every GATE and whenever a verdict is `expired`, a gate is `hold`/`block`, or the server refuses a transition. Report the exact tool outputs, not a paraphrase.
