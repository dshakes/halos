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
| [`halo controller`](/halos/reference/cli/controller/) | Automated experiment loop (evaluate, kill on rollback, PRs, notify) |
| [`halo doctor`](/halos/reference/cli/doctor/) | Check this machine and the policy repo; print the exact fix for each problem |
| [`halo eject`](/halos/reference/cli/eject/) | Write simple mode's generated Gateway, Profile and Rings out as files and drop the simple keys from halos.yaml |
| [`halo enable`](/halos/reference/cli/enable/) | Enable an MCP server or hook for everyone (profile) or a cohort (toggle) |
| [`halo eval`](/halos/reference/cli/eval/) | Offline replay evals |
| [`halo exp`](/halos/reference/cli/exp/) | Manage experiments |
| [`halo explain`](/halos/reference/cli/explain/) | Print the full low-level policy halos.yaml expands to (the hidden layer) |
| [`halo export`](/halos/reference/cli/export/) | Export a signed release for a delivery channel |
| [`halo gateway`](/halos/reference/cli/gateway/) | Compile gateway artifacts from the policy repo |
| [`halo harnesses`](/halos/reference/cli/harnesses/) | Show the harness capability matrix |
| [`halo init`](/halos/reference/cli/init/) | Create a policy repo: one simple halos.yaml (--full for the multi-file scaffold) |
| [`halo keys`](/halos/reference/cli/keys/) | Signing key management |
| [`halo kill`](/halos/reference/cli/kill/) | Kill an experiment, toggle or rollout fleet-wide via halo-server (effective at the next poll) |
| [`halo mcp`](/halos/reference/cli/mcp/) | Model Context Protocol server for agents |
| [`halo model`](/halos/reference/cli/model/) | Change which model an alias routes to |
| [`halo onboard`](/halos/reference/cli/onboard/) | Agent-friendly onboarding steps: detect, local, install, proxy, verify, company (dry run unless --apply) |
| [`halo plan`](/halos/reference/cli/plan/) | Diff the release a ring would get against a previous release |
| [`halo quickstart`](/halos/reference/cli/quickstart/) | Try it: bring up the whole stack on Docker (make demo), open the console and print a guided tour |
| [`halo release`](/halos/reference/cli/release/) | Build, publish and promote releases |
| [`halo render`](/halos/reference/cli/render/) | Render a ring's harness config files under --out, mirroring absolute paths |
| [`halo rollback`](/halos/reference/cli/rollback/) | Point a ring (and its experiment channels) back at an earlier signed release (version or manifest digest) |
| [`halo rollout`](/halos/reference/cli/rollout/) | Phased rollouts: plan, status, simulate; advance opens a PR, never merges |
| [`halo status`](/halos/reference/cli/status/) | One screen: rings, rollouts, live experiments, toggles and policy health |
| [`halo telemetry`](/halos/reference/cli/telemetry/) | Telemetry pipeline artifacts |
| [`halo toggle`](/halos/reference/cli/toggle/) | Feature toggles: list, evaluate, kill, find stale |
| [`halo upgrade`](/halos/reference/cli/upgrade/) | Watch upstream CLIs and models; open eval-gated upgrade PRs (never merges) |
| [`halo validate`](/halos/reference/cli/validate/) | Load and validate a policy repo (exit 2 on errors) |
| [`halo version`](/halos/reference/cli/version/) | Print the halo version |
| [`halo whoami`](/halos/reference/cli/whoami/) | Show the ring and experiment variants a user is assigned |

