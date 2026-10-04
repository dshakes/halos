---
name: halos-autopilot
description: Drive the whole Halos lifecycle from Codex (onboard, draft, validate, plan, eval, start an experiment, wait for evidence, promote or roll back, advance the rollout), stopping only at the human gates. Use when asked to roll a CLI or model change out end to end, or to monitor and finish an in-flight experiment or rollout.
---

# Halos autopilot (Codex)

The procedure is `plugins/claude-code/skills/halos-autopilot/SKILL.md` in this repo, and in full the `autopilot` prompt (resource `halos://guide/autopilot`) of the `halos` MCP server configured in `.codex/README.md`. Read it and follow it exactly; it is agent-neutral. Start with the `status` tool and follow every tool's `next_steps`.

Rules that do not bend: every write tool is a dry run first and waits for a yes; a human publishes releases, retags rings, merges and pushes to main (you print the command and stop); `kill_switch` and `propose_rollback` need no verdict, promotion needs `promote`; never print or ask for a credential value.
