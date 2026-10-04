# Halos (Gemini CLI extension)

Tools come from the `halos` MCP server this extension starts (`halo mcp serve --policy-dir .`: the policy repo is the directory Gemini CLI runs in). It is read-only; to let the agent write, the human adds the same server to `settings.json` with `--allow-writes` (the settings.json entry takes precedence over this extension's).

## Onboarding

Say "onboard me onto Halos" (or "try halos", "set up my machine", "set up my company"), or use the server's `onboard` prompt. Follow `plugins/claude-code/skills/halos-onboard/SKILL.md` from the Halos repo (https://github.com/dshakes/halos); it is agent-neutral. Three paths: try it (`halo quickstart`), my machine (`doctor` -> `init_policy` -> `plan` -> `local_install` -> `local_proxy` -> `verify_harness`), my company (`onboard_company` -> `validate`/`plan`/`eval_scorecard` -> PR).

## Rules

- Call `doctor` first and give the human each `fix` verbatim.
- Every write tool defaults to `dry_run: true`: show what would change and wait for a yes before `dry_run: false`. One yes covers one step.
- Never print, echo or ask for a credential value; `doctor` and `detect_harnesses` only say whether a variable is set.
- Never publish a release, enroll a device, retag a registry ring, push, merge or deploy. Hand the human the command and stop.
- Never emit `bypassPermissions` or `danger-full-access`.

For rollouts (CLI or model upgrades) follow `plugins/claude-code/skills/halos-rollout/SKILL.md`.

## Autopilot

To run the whole lifecycle hands-off, use the server's `autopilot` prompt (or read `halos://guide/autopilot`): `status` first, then validate -> `release_build`/`plan` -> `eval_run` -> **GATE 1** -> `start_experiment` -> `wait_for` -> **GATE 2** -> `propose_promotion` (PR) -> `propose_rollout_advance` per ring, or `kill_switch` + `propose_rollback` on a bad verdict. Follow every tool's `next_steps`; stop at each GATE. The fleet tools need the server started with `--server <halo-server URL>` and `HALO_SESSION` exported.
