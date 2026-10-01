---
title: Agentic operations
description: Drive rollouts from Claude Code or Codex through the Halos MCP server, with a write model that keeps a human at every irreversible step.
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

Resources: `halos://policy/<path>` (every policy file) and `halos://schema/<kind>` (JSON Schema for `profile`, `experiment`, `gateway`, and so on). Prompts: `plan-cli-upgrade`, `plan-model-upgrade`, `triage-experiment`.

## Write safety model

Write tools exist only with `--allow-writes`:

| Tool | Effect |
|---|---|
| `start_experiment`, `pause_experiment`, `conclude_experiment` | Set the experiment's `status` in policy YAML |
| `propose_promotion` | Open a PR pointing a ring at a release and concluding the experiment. **Requires a `promote` verdict** |
| `propose_rollback` | Pause an experiment and optionally re-point a ring at a known-good release **in policy YAML**. Does not touch the registry |

Rules enforced in code, not just in the prompt:

1. **`dry_run` defaults to true.** The tool returns the diff and changes nothing until called again with `dry_run: false`.
2. **`reason` is required** and is recorded in the commit message (and PR body).
3. **Local branch or PR only.** A real call commits to a new local branch or opens a PR. Nothing pushes to a default branch.
4. **No tool publishes a release, retags a registry ring, signs a pointer, merges, or pushes to a default branch** (`propose_promotion` pushes only its own review branch to open the PR). These are `halo release publish`, `promote`, `refresh`, `halo rollback` and a human clicking merge, and they are deliberately absent. Do not add one ([AGENTS.md](https://github.com/dshakes/halos/blob/main/AGENTS.md)).
5. **Status transitions are constrained:** `start` from draft, paused or unset; `pause` from running; `conclude` from running or paused.

Because promotion is a PR and rollback in policy is a PR-or-branch, the agent's worst case is a reviewable diff that a human rejects. Note the asymmetry: `propose_rollback` edits policy, which is not the same as the instant rollback the human performs with `halo rollback` (new signed pointer) or by pausing a traffic-axis experiment.

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
| Skill | `halos-rollout` | End-to-end CLI or model upgrade: scope, draft YAML, validate, plan, eval, **stop for approval**, start, monitor, **stop for approval**, propose promotion |
| Skill | `halos-author-policy` | Edit profiles, rings and experiments; always validates; reads schemas and existing files first |
| Skill | `halos-triage` | Diagnose a failing guardrail and propose a rollback |
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

Or `codex mcp add halos -- halo mcp serve --policy-dir /path/to/policy-repo`. Follow the flow in the plugin's `halos-rollout` skill (it is agent-neutral apart from tool prefixes): edit YAML, `validate`, `plan`, eval, start an experiment in ring1, `analyze_experiment`, `propose_promotion`, stopping for human approval before starting and before promoting. **UNVERIFIED:** the Codex snippet follows Codex's documented `mcp_servers` schema but was not run against a Codex install, and the plugin has not been exercised in a live Claude Code session.
