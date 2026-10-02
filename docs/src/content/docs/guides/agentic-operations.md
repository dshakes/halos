---
title: Agentic operations
description: Onboard and drive rollouts from Claude Code, Codex, Gemini CLI or Copilot CLI through the Halos MCP server, with a write model that keeps a human at every irreversible step.
---

`halo mcp serve` exposes Halos over stdio MCP so an agent can survey rings, draft and validate a change, read a scorecard, analyze an experiment and propose a promotion or rollback. It is built so that the agent can prepare everything and *cannot* do the irreversible parts.

## Start the server

```bash
halo mcp serve --policy-dir /path/to/policy-repo                       # read-only
halo mcp serve --policy-dir /path/to/policy-repo --allow-writes         # add write tools
halo mcp serve --policy-dir /path/to/policy-repo --clickhouse http://localhost:8123 --database halo
```

| Flag | Purpose |
|---|---|
| `--policy-dir` | Policy repo (default `.`) |
| `--allow-writes` | Expose experiment status and proposal tools |
| `--clickhouse`, `--database`, `--user` | Enables `analyze_experiment`; the password comes from `HALO_CLICKHOUSE_PASSWORD` |
| `--schema-dir` | JSON Schema directory (default: auto-detect) |

## Tools

Read tools are always on and annotated read-only.

| Tool | What it does |
|---|---|
| `validate` | Load and validate the policy repo |
| `plan` | Diff the release a ring would get against a baseline `release.tar` |
| `render_preview` | Render a ring's harness files for an OS and return their contents; writes nothing |
| `whoami` | Ring and experiment variants a user would be assigned |
| `list_rings`, `list_experiments`, `show_experiment` | Read the policy |
| `harness_matrix` | Capability matrix of the registered adapters |
| `explain_release_diff` | Diff two `release.tar` files and summarize per-harness version changes |
| `eval_scorecard` | Read a scorecard JSON produced by `halo eval run --output json` |
| `analyze_experiment` | Verdict `promote`, `rollback`, `continue` or `expired`. Only with `--clickhouse` |
| `list_rollouts`, `rollout_status` | Rollouts, their live step, and gate values against thresholds |
| `list_toggles`, `evaluate_toggle` | Toggles, and the rule trace for a user |
| `eval_matrix`, `upgrade_candidates` | Expand an eval suite's matrix without running it; list upstream CLI and model candidates |
| `doctor`, `detect_harnesses` | This machine: CLIs and versions, tools, which credential variables are set (never values), policy validity, gateway reachability, with a fix per problem |
| `verify_harness` | One headless model call per CLI (`claude -p`, `codex exec`, `gemini -p`, `copilot -p`); `dry_run` (default) returns the command; output is redacted |

Resources: `halos://policy/<path>` (every policy file) and `halos://schema/<kind>` (JSON Schema for `profile`, `experiment`, `gateway`, and so on). Prompts: `onboard` (the [Start here](/halos/getting-started/start-here/) procedure), `plan-cli-upgrade`, `plan-model-upgrade`, `triage-experiment`.

## Write safety model

Write tools exist only with `--allow-writes`:

| Tool | Effect |
|---|---|
| `start_experiment`, `pause_experiment`, `conclude_experiment` | Set the experiment's `status` in policy YAML |
| `propose_promotion` | Open a PR pointing a ring at a release and concluding the experiment. **Requires a `promote` verdict** |
| `propose_rollback` | Pause an experiment and optionally re-point a ring at a known-good release **in policy YAML**. Does not touch the registry |
| `propose_rollout_advance`, `propose_rollout_rollback` | Move a rollout to its next step or abort it in policy YAML (advance is refused when a gate failed) |
| `propose_toggle_change` | Change a toggle's default, a rule's rollout percent or its expiry |
| `init_policy`, `local_install`, `local_proxy`, `onboard_company` | Onboarding writes (`halo onboard local\|install\|proxy\|company --apply`). Registered always so every step can be previewed; `dry_run: false` needs `--allow-writes`, otherwise the tool returns the preview plus the `halo` command for the human. They write files only: no commit, no publish, no enrollment |

Rules enforced in code, not just in the prompt:

1. **`dry_run` defaults to true.** The tool returns the diff and changes nothing until called again with `dry_run: false`.
2. **`reason` is required** and is recorded in the commit message (and PR body).
3. **Local branch or PR only.** A real call commits to a new local branch or opens a PR. Nothing pushes to a default branch.
4. **No tool publishes a release, retags a registry ring, signs a pointer, merges, or pushes to a default branch** (`propose_promotion` pushes only its own review branch to open the PR). These are `halo release publish`, `promote`, `refresh`, `halo rollback` and a human clicking merge, and they are deliberately absent. Do not add one ([AGENTS.md](https://github.com/dshakes/halos/blob/main/AGENTS.md)).
5. **Status transitions are constrained:** `start` from draft, paused or unset; `pause` from running; `conclude` from running or paused.

Because promotion is a PR and rollback in policy is a PR-or-branch, the agent's worst case is a reviewable diff that a human rejects. Note the asymmetry: `propose_rollback` edits policy, which is not the same as the fast rollback a human performs with `halo kill` (effective at the next poll) or `halo rollback` (a new signed pointer, picked up on the next `halod` pull).

## Claude Code plugin

`plugins/claude-code` is a Claude Code plugin. Requires `halo` on `PATH`; set `HALOS_POLICY_DIR` to your policy repo (default: the current directory).

```
/plugin marketplace add ./plugins/claude-code
/plugin install halos@halos
```

The bundled `.mcp.json` runs `halo mcp serve --policy-dir ${HALOS_POLICY_DIR:-.}` **read-only**. To let the agent propose changes, register the server yourself with writes:

```bash
claude mcp add halos -- halo mcp serve --policy-dir /path/to/policy --allow-writes
```

| Piece | Name | Purpose |
|---|---|---|
| Skill | `halos-onboard` | Try it, my machine or my company: `doctor`, interview, dry run, **approval**, write, verify; stops before anything outward |
| Skill | `halos-rollout` | End-to-end CLI or model upgrade: scope, draft YAML, validate, plan, eval, **stop for approval**, start, monitor, **stop for approval**, propose promotion |
| Skill | `halos-author-policy` | Edit profiles, rings and experiments; always validates; reads schemas and existing files first |
| Skill | `halos-triage` | Diagnose a failing guardrail and propose a rollback |
| Command | `/halos:halo-onboard [try\|machine\|company]` | Starts the onboarding skill |
| Command | `/halo-rollout <harness\|model> <target>` | Starts the rollout skill |
| Command | `/halo-status` | Read-only table of rings, experiments and verdicts |
| Agent | `halos-release-manager` | Read-mostly subagent (Sonnet) limited to read tools and `halo validate\|plan\|exp list\|exp show\|exp analyze`; proposes, never changes anything |

## Codex

Add the server to `~/.codex/config.toml` (or a project `.codex/config.toml`):

```toml
[mcp_servers.halos]
command = "halo"
args = ["mcp", "serve", "--policy-dir", "/path/to/policy-repo"]
# append "--allow-writes" to let Codex propose changes
# append "--clickhouse", "http://localhost:8123" for analyze_experiment
```

Or `codex mcp add halos -- halo mcp serve --policy-dir /path/to/policy-repo`. Inside a Halos checkout, `$halos-onboard` runs the onboarding skill (`.agents/skills/halos-onboard`, a pointer at the agent-neutral `plugins/claude-code/skills/halos-onboard/SKILL.md`). For rollouts, follow the flow in the plugin's `halos-rollout` skill (it is agent-neutral apart from tool prefixes): edit YAML, `validate`, `plan`, eval, start an experiment in ring1, `analyze_experiment`, `propose_promotion`, stopping for human approval before starting and before promoting. **UNVERIFIED:** the Codex snippet follows Codex's documented `mcp_servers` schema but was not run against a Codex install.

## Gemini CLI

`extensions/gemini/halos` is a Gemini CLI extension: `gemini-extension.json` starts `halo mcp serve --policy-dir .` (the directory Gemini runs in) and `GEMINI.md` carries the rules and points at the onboarding and rollout skills.

```bash
gemini extensions install ./extensions/gemini/halos   # copies it; or `link` to develop against the checkout
```

The extension's server is read-only; a `halos` entry in `settings.json` with `--allow-writes` takes precedence over it.

## Copilot CLI

Inside a Halos checkout, Copilot CLI loads `.github/mcp.json` (the `halos` server, `type: local`, read-only) and `.github/copilot-instructions.md` plus `AGENTS.md` for the rules. For writes, or outside the checkout:

```bash
copilot mcp add halos -- halo mcp serve --policy-dir /path/to/policy-repo --allow-writes   # ~/.copilot/mcp-config.json
```

The Gemini extension was installed and enabled by `gemini extensions install` with Gemini CLI 0.26.0 (it lists the `halos` server and the `GEMINI.md` context); an onboarding session in Gemini was not run. **UNVERIFIED:** the Copilot files follow the documented format (`.github/mcp.json` with `mcpServers.<name>.type: local`, `.github/copilot-instructions.md`) but were not run against a Copilot install.
