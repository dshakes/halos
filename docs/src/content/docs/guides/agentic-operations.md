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
HALO_SESSION=<admin halo_session cookie> halo mcp serve --policy-dir ... --server https://halo.acme.example   # fleet tools
```

| Flag | Purpose |
|---|---|
| `--policy-dir` | Policy repo (default `.`) |
| `--allow-writes` | Expose experiment status and proposal tools; lets `kill_switch` and `eval_run` run for real |
| `--clickhouse`, `--database`, `--user` | Enables `analyze_experiment` and `wait_for` on experiments; the password comes from `HALO_CLICKHOUSE_PASSWORD` |
| `--server` (or `HALO_SERVER`) | halo-server base URL for `kill_switch`, `kill_switch_status`, `fleet_status`, `audit_tail`. The admin session is read from `HALO_SESSION`, never a flag or a tool argument; plain `http` is accepted on loopback only |
| `--schema-dir` | JSON Schema directory (default: auto-detect) |

## Autopilot: the whole lifecycle, hands-off

An agent can run the lifecycle end to end and stop only at the human gates. The procedure is the server's `autopilot` prompt (also the resource `halos://guide/autopilot`, and the plugin's `halos-autopilot` skill / `/halo-autopilot` command): `status` -> draft YAML -> `validate` -> `release_build` + `plan` + `render_preview` -> `eval_run` -> **GATE 1 (start)** -> `start_experiment` -> `wait_for` -> **GATE 2 (promote)** -> `propose_promotion` (PR) -> `propose_rollout_advance` (`open_pr: true`) per ring; on a `rollback` verdict `kill_switch` then `propose_rollback` / `propose_rollout_rollback`. Every tool answers with `next_steps`: the next call, or the exact command the human runs (`halo release publish`, `git push` + `gh pr create`, merge, `halo rollback`).

What the human still does, in order: approve GATE 1; publish the release (`halo release publish`); push and merge the start branch; approve GATE 2; merge the promotion or advance PR; on a rollback, merge the rollback PR and re-point the registry (`halo rollback`). Nothing else.

Verified: `test/e2e` `TestAutopilotLifecycle` drives all of it through `halo mcp serve` (real halo-server kill switch, bare origin, recording `gh`), and three headless `claude -p` sessions with the plugin ran the same loop (stop at GATE 1; approve, start, wait, stop at GATE 2; regression: kill, rollback PR). In every case origin `main` never moved and the only remote branches were the review branches the tools opened.

## Tools

Read tools are always on and annotated read-only.

| Tool | What it does |
|---|---|
| `status` | One call: policy health, rings with pinned releases, experiments, rollouts, toggles, which planes this server has (writes, ClickHouse, halo-server), the kill list and fleet counts when halo-server is configured, and `next_steps` |
| `validate` | Load and validate the policy repo |
| `release_build` | Build a ring's release in memory: digest, per-harness versions, file list, adapter warnings, and the human's `halo release publish` command |
| `wait_for` | Poll an experiment (until the verdict leaves `continue`; needs `--clickhouse`) or a rollout (until its decision leaves `hold`) with a bounded timeout (default 60 s, max 600 s); call again to keep waiting |
| `kill_switch_status`, `fleet_status`, `audit_tail` | halo-server's kill list, devices per ring with drift, and the audit log (needs `--server` + `HALO_SESSION`) |
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
| `verify_harness` | The command for one headless model call per CLI (`claude -p`, `codex exec`, `gemini -p`, `copilot -p`); `dry_run` (default) only returns it. A real run is gated like a write (below) |

Resources: `halos://policy/<path>` (every policy file), `halos://schema/<kind>` (JSON Schema for `profile`, `experiment`, `gateway`, and so on) and `halos://guide/autopilot` (what Halos is, the invariants, the lifecycle and its gates). Prompts: `autopilot` (the full lifecycle), `onboard` (the [Start here](/halos/getting-started/start-here/) procedure), `plan-cli-upgrade`, `plan-model-upgrade`, `triage-experiment`.

## Write safety model

Write tools exist only with `--allow-writes`:

| Tool | Effect |
|---|---|
| `start_experiment`, `pause_experiment`, `conclude_experiment` | Set the experiment's `status` in policy YAML |
| `propose_promotion` | Open a PR pointing a ring at a release and concluding the experiment. **Requires a `promote` verdict** |
| `propose_rollback` | Pause an experiment and optionally re-point a ring at a known-good release **in policy YAML**. Does not touch the registry |
| `propose_rollout_advance`, `propose_rollout_rollback` | Move a rollout to its next step or abort it in policy YAML (advance is refused when a gate failed). `open_pr: true` pushes a review branch and opens the PR instead of committing locally |
| `kill_switch` | Kill or unkill an experiment, toggle or rollout (its backing experiment) through halo-server's signed kill list: the fast, reversible rollback. Registered always; `dry_run: false` needs `--allow-writes`, a `reason`, `--server` and `HALO_SESSION`. Never edits policy |
| `eval_run` | `halo eval run --output json` with a bounded timeout, scorecard under `<policy>/.halos/scorecards`. Registered always; the real run spends credentials and needs `--allow-writes` |
| `propose_toggle_change` | Change a toggle's default, a rule's rollout percent or its expiry |
| `init_policy`, `local_install`, `local_proxy`, `onboard_company`, `verify_harness` | Onboarding side effects (`halo onboard local\|install\|proxy\|company --apply`, `halo onboard verify`). Registered always so every step can be previewed; `dry_run: false` needs `--allow-writes`, otherwise the tool returns the preview plus the `halo` command for the human. They write local files or run one CLI with the human's own credentials: no commit, no publish, no enrollment |

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
| Skill | `halos-autopilot` | The whole lifecycle hands-off: `status`, draft, validate, `release_build`/`plan`, `eval_run`, **GATE 1**, start, `wait_for`, **GATE 2**, promotion/advance PRs, or `kill_switch` + rollback |
| Skill | `halos-rollout` | End-to-end CLI or model upgrade: scope, draft YAML, validate, plan, eval, **stop for approval**, start, monitor, **stop for approval**, propose promotion |
| Skill | `halos-author-policy` | Edit profiles, rings and experiments; always validates; reads schemas and existing files first |
| Skill | `halos-triage` | Diagnose a failing guardrail and propose a rollback |
| Command | `/halos:halo-onboard [try\|machine\|company]` | Starts the onboarding skill |
| Command | `/halo-autopilot <what to roll out>` | Starts the autopilot skill |
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

Or `codex mcp add halos -- halo mcp serve --policy-dir /path/to/policy-repo`. Inside a Halos checkout, `$halos-autopilot <goal>` runs the full loop and `$halos-onboard` runs the onboarding skill (`.agents/skills/halos-onboard`, a pointer at the agent-neutral `plugins/claude-code/skills/halos-onboard/SKILL.md`). For rollouts, follow the flow in the plugin's `halos-rollout` skill (it is agent-neutral apart from tool prefixes): edit YAML, `validate`, `plan`, eval, start an experiment in ring1, `analyze_experiment`, `propose_promotion`, stopping for human approval before starting and before promoting. **UNVERIFIED:** the Codex snippet follows Codex's documented `mcp_servers` schema but was not run against a Codex install (the MCP server itself is covered by the `internal/mcpserver` tests).

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

The Gemini extension was installed and enabled by `gemini extensions install` with Gemini CLI 0.26.0 (it lists the `halos` server and the `GEMINI.md` context); an onboarding session in Gemini was not run. **UNVERIFIED:** the Copilot files follow the documented format (`.github/mcp.json` with `mcpServers.<name>.type: local`, `.github/copilot-instructions.md`) but were not run against a Copilot install (the MCP server itself is covered by the `internal/mcpserver` tests).
