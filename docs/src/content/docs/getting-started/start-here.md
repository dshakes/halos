---
title: Start here
description: Three ways in, driven from whichever AI coding CLI you already use. Try it in two minutes, manage your own machine, or set up your company. Every write is a dry run first; nothing is published, enrolled or pushed without you.
---

Pick a path. Each one can be driven by an agent (Claude Code, Codex, Gemini CLI, Copilot CLI) through the same `halo` commands and MCP tools, or typed by hand. The agent runs an ask, act, verify loop: it shows what a step would write, waits for your yes, then checks the result. It never prints a credential value and never publishes, enrolls, pushes, merges or deploys; those commands are handed to you.

| Path | For | Time | First command |
|---|---|---|---|
| **Try it** | A look at the whole thing on Docker | ~2 min | `halo quickstart` |
| **My machine** | Your laptop: pin your CLIs, manage their config, route through a local proxy | ~5 min | `halo doctor` |
| **My company** | A platform team: policy repo, gateway, IdP, fleet delivery, first PR | ~20 min | `halo onboard company` |

[Install `halo`](/halos/getting-started/install/) first. Then either type the commands below or hand the whole path to your CLI:

| CLI | Say or type | Setup |
|---|---|---|
| Claude Code | `/halo-onboard try` (or `machine`, `company`) | `/plugin marketplace add ./plugins/claude-code` then `/plugin install halos@halos`, from a Halos checkout |
| Codex | `$halos-onboard` | Run `codex` inside a Halos checkout (the skill is in `.agents/skills`); MCP snippet in [`.codex/README.md`](https://github.com/dshakes/halos/blob/main/.codex/README.md) |
| Gemini CLI | "onboard me onto Halos" | `gemini extensions install ./extensions/gemini/halos` (or `link`), from a Halos checkout |
| Copilot CLI | "onboard me onto Halos" | Run `copilot` inside a Halos checkout: `.github/mcp.json` adds the server and `.github/copilot-instructions.md` the rules |

All four read the same procedure, [`halos-onboard`](https://github.com/dshakes/halos/blob/main/plugins/claude-code/skills/halos-onboard/SKILL.md), and the same `onboard` prompt the MCP server serves. Each tool the agent calls (`doctor`, `detect_harnesses`, `init_policy`, `plan`, `local_install`, `local_proxy`, `verify_harness`, `onboard_company`) is a `halo` subcommand with `--output json`, so you can replay every step yourself.

## Try it

```sh
halo quickstart          # make demo from a Halos checkout (clones one into ~/.cache/halos/src if needed)
halo quickstart down     # stop it and delete its volumes
```

Needs Docker and git. It brings up the console with a mock IdP, halo-proxy, shadow mirror, mock models and the evidence plane, seeded from `examples/acme-corp`, opens `http://localhost:18080` and prints a six-step tour (sign in as `alice@acme.com`, then `bob@acme.com`; call the proxy; open Grafana). DEV ONLY: throwaway keys. Same thing by hand: [Playground](/halos/getting-started/playground/).

## My machine

```sh
halo doctor                                   # CLIs and versions, tools, which key variables are set (never values), fixes
halo onboard local --policy-dir ~/halos       # halos.yaml for this machine, validated, plus the install plan (dry run)
halo onboard local --policy-dir ~/halos --apply
halo onboard install --policy-dir ~/halos --show      # exactly what lands where (dry run)
sudo halo onboard install --policy-dir ~/halos --apply # admin-owned paths; idempotent, originals kept at *.halos-backup
halo onboard proxy --policy-dir ~/halos --apply       # loopback halo-proxy config, keys from your env at start
halo-proxy --config ~/halos/.halos/local/halo-proxy.yaml &
halo onboard verify                                   # claude -p / codex exec / gemini -p / copilot -p, one short call each
```

`halo onboard local` defaults come from the machine: every CLI on `PATH` pinned at its installed version, the provider whose key is exported, a local gateway on `http://127.0.0.1:8088`. Pass `--tools claude-code@2.1.280 --provider bedrock --model default=...` to override. `verify` skips a CLI with no key variable set; if it is logged in instead, pass `--assume-auth`. From here, upgrades are rollouts: [`halos-rollout`](/halos/guides/agentic-operations/).

## My company

```sh
halo onboard company --policy-dir acme-halos --org acme --tools claude-code@2.1.280,codex@0.99.0 \
  --provider bedrock --gateway https://ai.acme.com --gateway-kind halo-proxy --issuer https://login.acme.com \
  --admin-group ai-platform --delivery halod,devcontainer --registry ghcr.io/acme/halos-releases \
  --policy-repo https://github.com/acme/halos-policy.git --portal-url https://halos.acme.com        # dry run
halo onboard company ... --apply
halo validate --policy-dir acme-halos && halo plan --policy-dir acme-halos --ring ring3-ga
```

An agent asks those questions one at a time (IdP, gateway Kong or halo-proxy, provider Anthropic, Bedrock or Vertex, delivery dev containers, MDM or `halod`). The result is a policy repo: `halos.yaml`, `.halos/helm-values.yaml`, `.halos/oidc-client.yaml`, `.halos/enroll/*`, a validate-and-plan CI workflow, a smoke eval suite and a `README.md` listing the human steps in order (merge, register the OIDC client, generate the signing key, deploy Helm, `halo release publish`, enroll). Nothing in it is secret and nothing is published, enrolled or pushed; the agent opens a PR and stops there. Next: [Production deployment](/halos/guides/production-deployment/), then [Laptops via MDM](/halos/guides/laptops-mdm/) or [Dev containers](/halos/guides/dev-containers/).
