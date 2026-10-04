# Codex + Halos

Add the MCP server to `~/.codex/config.toml` (or a project `.codex/config.toml`):

```toml
[mcp_servers.halos]
command = "halo"
args = ["mcp", "serve", "--policy-dir", "/path/to/policy-repo"]
# Read-only by default. To let Codex propose changes, append "--allow-writes".
# For analyze_experiment append "--clickhouse", "http://localhost:8123".
```

or: `codex mcp add halos -- halo mcp serve --policy-dir /path/to/policy-repo`

## Onboarding

First time? From this checkout, run `codex` and say `$halos-onboard` (the skill in `.agents/skills/halos-onboard`, which Codex discovers in the repo), or use the `onboard` prompt the MCP server serves. Three paths: try it (`halo quickstart`), my machine (policy, managed config, local proxy, headless verify), my company (policy repo, Helm values, IdP client, enrollment, PR). Every write is shown as a dry run first; Codex stops before anything outward (publish, enroll, push).

## Autopilot

Say `$halos-autopilot <what to roll out>` (the skill in `.agents/skills/halos-autopilot`), or use the server's `autopilot` prompt: Codex calls `status`, then drives validate -> `release_build`/`plan` -> `eval_run` -> **GATE 1** -> `start_experiment` -> `wait_for` -> **GATE 2** -> `propose_promotion` (PR) -> `propose_rollout_advance` per ring, or `kill_switch` + `propose_rollback` on a bad verdict, following each tool's `next_steps`. The fleet tools (`kill_switch`, `kill_switch_status`, `fleet_status`, `audit_tail`) need `"--server", "https://halo-server"` in the args above and `HALO_SESSION` (an admin session cookie value) in Codex's environment.

Rules for the agent are in the repo-root `AGENTS.md`. For the rollout procedure, read `plugins/claude-code/skills/halos-rollout/SKILL.md`; it is agent-neutral apart from tool prefixes. Every write tool is dry_run by default; a human approves before any `dry_run: false` call, and a human publishes, retags, and merges.

UNVERIFIED: the snippets follow Codex's documented `mcp_servers` schema and repo skill discovery (`.agents/skills`) but were not run against a Codex install.
