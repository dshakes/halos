---
title: "halo onboard"
description: "Agent-friendly onboarding steps: detect, local, install, proxy, verify, company (dry run unless --apply)"
---

Agent-friendly onboarding steps: detect, local, install, proxy, verify, company (dry run unless --apply)

The deterministic core of onboarding. Each step is idempotent, supports --output json and writes
nothing without --apply. Start with `halo doctor`; see the Start here docs page for the three paths.

## Usage

```console
halo onboard
```

## Flags

None.

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Commands

| Command | Description |
|---|---|
| [`halo onboard company`](/halos/reference/cli/onboard-company/) | My company: generate the policy repo, Helm values, IdP client and enrollment config from interview answers |
| [`halo onboard detect`](/halos/reference/cli/onboard-detect/) | List the AI CLIs on PATH with versions, and which credential variables are set (never values) |
| [`halo onboard install`](/halos/reference/cli/onboard-install/) | Render a ring's managed config for this OS and show exactly what lands where; --apply writes it |
| [`halo onboard local`](/halos/reference/cli/onboard-local/) | My machine: create (or keep) halos.yaml, validate it and plan the managed-config install |
| [`halo onboard proxy`](/halos/reference/cli/onboard-proxy/) | Write a single-developer halo-proxy config (loopback, keys from your env) into .halos/local |
| [`halo onboard verify`](/halos/reference/cli/onboard-verify/) | Run each installed CLI headless (claude -p, codex exec, gemini -p, copilot -p) and check the reply |

## Parent

[`halo`](/halos/reference/cli/)
