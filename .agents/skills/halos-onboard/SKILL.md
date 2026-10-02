---
name: halos-onboard
description: Onboard a person or a company onto Halos from Codex (try it, my machine, my company). Use when asked to set up, try, install or roll out Halos, or to manage this machine's AI CLI config with Halos.
---

# Halos onboarding (Codex)

The procedure is `plugins/claude-code/skills/halos-onboard/SKILL.md` in this repo; read it and follow it exactly. It is agent-neutral: the tools it names (`doctor`, `detect_harnesses`, `init_policy`, `plan`, `local_install`, `local_proxy`, `verify_harness`, `onboard_company`, `validate`, `harness_matrix`, `eval_scorecard`) come from the `halos` MCP server configured in `.codex/README.md`. When a tool is unavailable, run the `halo` command it mirrors (`halo doctor`, `halo onboard detect|local|install|proxy|verify|company`, each with `--output json`, dry run unless `--apply`).

Rules that do not bend: show every write as a dry run and wait for a yes; never print or ask for a credential value; never publish, enroll, retag, push, merge or deploy.
