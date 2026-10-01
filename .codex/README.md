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

Rules for the agent are in the repo-root `AGENTS.md`. For the rollout procedure, read `plugins/claude-code/skills/halos-rollout/SKILL.md`; it is agent-neutral apart from tool prefixes. Every write tool is dry_run by default; a human approves before any `dry_run: false` call, and a human publishes, retags, and merges.

UNVERIFIED: the snippet follows Codex's documented `mcp_servers` schema but was not run against a Codex install.
