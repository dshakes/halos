# Halos plugin for Claude Code

Skills (`halos-onboard`, `halos-rollout`, `halos-author-policy`, `halos-triage`), commands (`/halos:halo-onboard`, `/halo-rollout`, `/halo-status`), an agent (`halos-release-manager`) and an MCP server wiring for `halo mcp serve`.

New here? `/halos:halo-onboard` walks you through try it, my machine or my company (see the Start here docs page).

Requires `halo` on PATH. Set `HALOS_POLICY_DIR` to your policy repo (default: the current directory).

```
/plugin marketplace add ./plugins/claude-code
/plugin install halos@halos
```

The bundled `.mcp.json` is read-only. To let the agent propose changes, override the server with `--allow-writes` (and `--clickhouse URL` for `analyze_experiment`):

```
claude mcp add halos -- halo mcp serve --policy-dir /path/to/policy --allow-writes
```

Write tools default to `dry_run`, need a `reason` (recorded in the commit message) and only commit to a local branch or open a PR. Nothing here publishes releases, retags registry rings, merges, or pushes to main: a human owns each irreversible step.
