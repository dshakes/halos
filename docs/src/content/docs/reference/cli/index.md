---
title: "CLI reference"
description: "Every halo command and flag, generated from the code."
---

Generated from the command tree in `cmd/halo`; do not edit. Regenerate with `make docs-gen`.

Global flag: `--output text|json`. Commands that read a policy repo take `--policy-dir D` (default `.`). `halo validate` exits 0 when valid and 2 on validation errors; other failures exit 1 with `error: ...` on stderr.

The other binaries (`halod`, `halo-proxy`, `halo-server`, `halo-shadow`) are covered in [Binaries and runtime configuration](/halos/reference/binaries/).

## Usage

```console
halo
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Commands

| Command | Description |
|---|---|
| [`halo admin`](/halos/reference/cli/admin/) | Sync vendor admin consoles (Claude, ChatGPT/Codex, Gemini, Copilot, Cursor) with policy (ADR-0025) |
| [`halo agents`](/halos/reference/cli/agents/) | Delegated and remote (A2A) agents (ADR-0024) |
| [`halo artifact`](/halos/reference/cli/artifact/) | Digest, scan and sign agent extension artifacts (skills, plugins, hooks, commands, agents; ADR-0028) |
| [`halo audit`](/halos/reference/cli/audit/) | Inspect halo-server's hash-chained audit log |
| [`halo budget`](/halos/reference/cli/budget/) | Gateway cost budgets: spend per user, group, ring and org |
| [`halo ci`](/halos/reference/cli/ci/) | Governed gateway credentials and config for headless CI / cloud agents |
| [`halo cloud-agents`](/halos/reference/cli/cloud-agents/) | Govern cloud and background coding agents: render workflows, list tasks, kill (ADR-0034) |
| [`halo controller`](/halos/reference/cli/controller/) | Automated experiment loop (evaluate, kill on rollback, PRs, notify) |
| [`halo copilot`](/halos/reference/cli/copilot/) | AI-assisted policy operations: the model drafts, Halos verifies, a human approves (ADR-0035) |
| [`halo dlp`](/halos/reference/cli/dlp/) | Gateway data-loss prevention and prompt-injection defense (ADR-0033) |
| [`halo doctor`](/halos/reference/cli/doctor/) | Check this machine and the policy repo; print the exact fix for each problem |
| [`halo egress`](/halos/reference/cli/egress/) | Explain the sandbox egress policy (ADR-0032) |
| [`halo eject`](/halos/reference/cli/eject/) | Write simple mode's generated Gateway, Profile and Rings out as files and drop the simple keys from halos.yaml |
| [`halo enable`](/halos/reference/cli/enable/) | Enable an MCP server or hook for everyone (profile) or a cohort (toggle) |
| [`halo eval`](/halos/reference/cli/eval/) | Offline replay evals |
| [`halo exp`](/halos/reference/cli/exp/) | Manage experiments |
| [`halo explain`](/halos/reference/cli/explain/) | Print the full low-level policy halos.yaml expands to, or with --user one user's effective config and which layer set each field |
| [`halo export`](/halos/reference/cli/export/) | Export a signed release for a delivery channel |
| [`halo freeze`](/halos/reference/cli/freeze/) | Change freezes: policy windows and the incident freeze (ADR-0030); rollbacks are never frozen |
| [`halo gateway`](/halos/reference/cli/gateway/) | Compile gateway artifacts from the policy repo |
| [`halo harnesses`](/halos/reference/cli/harnesses/) | Show the harness capability matrix |
| [`halo init`](/halos/reference/cli/init/) | Create a policy repo: one simple halos.yaml (--full for the multi-file scaffold) |
| [`halo keys`](/halos/reference/cli/keys/) | Signing key management |
| [`halo kill`](/halos/reference/cli/kill/) | Kill an experiment, toggle or rollout fleet-wide via halo-server (effective at the next poll) |
| [`halo mcp`](/halos/reference/cli/mcp/) | Model Context Protocol server for agents |
| [`halo migrate`](/halos/reference/cli/migrate/) | Rewrite policy documents from apiVersion halos.dev/v1alpha1 to halos.dev/v1 |
| [`halo model`](/halos/reference/cli/model/) | Change which model an alias routes to |
| [`halo onboard`](/halos/reference/cli/onboard/) | Agent-friendly onboarding steps: detect, local, install, proxy, verify, company (dry run unless --apply) |
| [`halo plan`](/halos/reference/cli/plan/) | Diff the release each ring (or --ring) would get against a previous release, and with --diff who is affected |
| [`halo quickstart`](/halos/reference/cli/quickstart/) | Try it: bring up the whole stack on Docker (make demo), open the console and print a guided tour |
| [`halo release`](/halos/reference/cli/release/) | Build, publish and promote releases |
| [`halo render`](/halos/reference/cli/render/) | Render a ring's harness config files under --out, mirroring absolute paths |
| [`halo roi`](/halos/reference/cli/roi/) | Delivery ROI of a policy change: PR outcomes per experiment arm (ADR-0027) |
| [`halo rollback`](/halos/reference/cli/rollback/) | Point a ring (and its experiment channels) back at an earlier signed release (version or manifest digest) |
| [`halo rollout`](/halos/reference/cli/rollout/) | Phased rollouts: plan, status, simulate; advance opens a PR, never merges |
| [`halo service-token`](/halos/reference/cli/service-token/) | Create, list and revoke halo-server service-account API tokens (admin) |
| [`halo sessions`](/halos/reference/cli/sessions/) | Agent session ledger: one identity-linked record per agent session (ADR-0031) |
| [`halo status`](/halos/reference/cli/status/) | One screen: rings, rollouts, live experiments, toggles and policy health |
| [`halo telemetry`](/halos/reference/cli/telemetry/) | Telemetry pipeline artifacts |
| [`halo test`](/halos/reference/cli/test/) | Test a policy change offline in seconds: validate, render, release, invariants, impact, policy tests, rollouts |
| [`halo toggle`](/halos/reference/cli/toggle/) | Feature toggles: list, evaluate, kill, find stale |
| [`halo units`](/halos/reference/cli/units/) | Org hierarchy: business units and teams with delegated owners (ADR-0018) |
| [`halo upgrade`](/halos/reference/cli/upgrade/) | Watch upstream CLIs and models; open eval-gated upgrade PRs (never merges) |
| [`halo validate`](/halos/reference/cli/validate/) | Load and validate a policy repo (exit 2 on errors) |
| [`halo version`](/halos/reference/cli/version/) | Print the halo version |
| [`halo whoami`](/halos/reference/cli/whoami/) | Show the ring and experiment variants a user is assigned |

