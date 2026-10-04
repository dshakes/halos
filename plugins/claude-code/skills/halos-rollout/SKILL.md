---
name: halos-rollout
description: End-to-end Halos rollout of a harness CLI upgrade or model upgrade. Use when asked to upgrade Claude Code/Codex/Gemini, change a model alias, or roll a config change through rings with an experiment.
---

# Halos rollout

Tools come from the `halos` MCP server (`halo mcp serve`). Read tools are always available. Write tools exist only if the human started the server with `--allow-writes`. If a tool is missing, do not work around it with shell edits to release state; tell the human.

## Hard rules

- You never publish a release, retag a registry ring, merge, or push to main. Those are human steps (a human is the gate at every irreversible step). `propose_promotion` opens a PR; a human merges it.
- Every write tool: call with `dry_run: true` (the default) first, show the diff, then call again with `dry_run: false` only after the human says yes. Always pass a real `reason`.
- Never emit `bypassPermissions` or `danger-full-access`.

## Steps

1. **Scope.** Ask which harness and target version (CLI upgrade) or which model alias (model upgrade). Call `list_rings`, `list_experiments`, `harness_matrix`.
2. **Draft YAML.** Edit or create the profile (version pin or model) and an Experiment (`type: ab` or `canary`, ring1, primary metric, guardrails, max duration) in the policy repo. Use resource `halos://schema/experiment` for the shape. Set the experiment `status: draft`.
3. **Validate.** Call `validate`. Fix every error; explain warnings. Do not continue on errors.
4. **Plan.** Call `plan` for ring1 against the current release tarball, then `explain_release_diff`. Summarize version changes and rendered-config differences (call out permissions, MCP, hooks, models). Use `render_preview` for the OS mix in that ring.
5. **Eval.** Run the eval suite with `halo eval run <suite.yaml> --output json > scorecard.json` (Docker; needs the human's credentials, so ask before running), then `eval_scorecard`. Report pass rate vs baseline.
6. **STOP 1: human approval to start.** Present diff, plan, scorecard. Wait for explicit approval.
7. **Start.** `start_experiment` (dry run, show diff, then real). The human publishes/merges the policy change and the release; you do not.
8. **Monitor.** Call `wait_for` (`kind: experiment`, bounded; call again while `satisfied` is false) or `analyze_experiment` directly (both need ClickHouse). Verdicts: `continue` (keep waiting), `rollback` (switch to the `halos-triage` skill), `promote`, `expired`.
9. **STOP 2: human approval to promote.** On `promote`, show the evidence and call `propose_promotion` (dry run first). It opens a PR; tell the human to review and merge. Stop there.

For the hands-off version of this loop (plus onboarding, release build, eval run, rollout advance and the kill/rollback path) use the `halos-autopilot` skill.
