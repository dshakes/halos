# Halos for Copilot CLI

Repository rules are in `AGENTS.md` (Copilot CLI reads it too). The `halos` MCP server comes from `.github/mcp.json` (`halo mcp serve --policy-dir .`, read-only; `copilot mcp add halos -- halo mcp serve --policy-dir . --allow-writes` to let the agent write, which goes to `~/.copilot/mcp-config.json`).

## Onboarding

When asked to try, set up, install or roll out Halos, follow `plugins/claude-code/skills/halos-onboard/SKILL.md` (agent-neutral) or ask the server for its `onboard` prompt. Call `doctor` first. Show every write as a dry run and wait for a yes. Never print or ask for a credential value. Never publish, enroll, retag, push, merge or deploy: hand the human the command and stop.
