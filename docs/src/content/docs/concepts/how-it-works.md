---
title: How Halos works
description: Who does what, what a policy repo is, and how a change travels from a pull request to every developer's machine and gateway.
---

Halos is run by a **platform team** for everyone else. The platform team describes how the org's AI coding CLIs should behave in a **policy repo**. Halos turns each merged change into a signed release and rolls it out ring by ring. **Developers install nothing new and never touch the repo**: they keep running `claude`, `codex` or `gemini`, and their config and model routing change underneath them.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/how-it-works-light.svg" alt="The platform team owns a git policy repo. A pull request is validated, planned and evaluated in CI, a human merges, and halo publishes a signed immutable release. Rings point at releases; halod applies them on every machine and the gateway routes model traffic. Developers keep running their CLI as usual." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/how-it-works-dark.svg" alt="The platform team owns a git policy repo. A pull request is validated, planned and evaluated in CI, a human merges, and halo publishes a signed immutable release. Rings point at releases; halod applies them on every machine and the gateway routes model traffic. Developers keep running their CLI as usual." width="880" />

## Who does what

| | Platform team | Developer |
|---|---|---|
| Owns | The policy repo, the registry, the gateway, the rollout | Nothing new |
| Runs | `halo` in CI and on their laptop; reviews and merges PRs | `claude`, `codex`, `gemini` as usual |
| Sees | Plans, eval scorecards, experiment verdicts, the console | The config and models their ring gets; the portal to enroll a machine |

## What a policy repo is

A plain git repo of Halos YAML, owned by the platform team the way a Terraform repo is. Nothing in it is specific to one CLI: Halos compiles it into each harness's own config files. `halo init` starts you in **simple mode**, where one file is the whole policy:

```console
$ halo init
create halos.yaml
next: halo explain --policy-dir .   (the full policy this expands to)
next: halo validate --policy-dir .
```

```yaml
# halos.yaml, as scaffolded
apiVersion: halos.dev/v1alpha1
kind: Halos
org: my-org
tools:
  claude-code: 2.1.280
provider: anthropic   # anthropic | bedrock | vertex | openai | gemini | multi
models:
  default: claude-sonnet-4-5
gateway: https://ai.my-org.example
safety: standard   # strict | standard | relaxed
rollout: standard   # fast | standard | careful
```

`halo explain` prints the low-level policy those few lines expand to. When you need full control, `halo eject` writes it out as files; the policy loads to exactly the same thing afterwards:

```console
$ halo eject
create gateway.yaml
create profiles/default.yaml
create rings/ring0-team.yaml
create rings/ring1-canary.yaml
create rings/ring2-early.yaml
create rings/ring3-ga.yaml
update halos.yaml
$ halo validate
OK: policy valid (0 warnings)
```

```text
my-policy/
├── halos.yaml            # org, identity provider, self-service portal
├── gateway.yaml          # model aliases, upstreams, routes
├── profiles/             # desired behaviour: CLI versions, models, permissions, MCP, hooks, egress
├── rings/                # who gets which profile: team → canary → early → GA
├── experiments/          # optional: A/B, canary, shadow
├── rollouts/             # optional: phased steps with gates
└── toggles/              # optional: targeted switches with a kill path
```

`halo whoami` and `halo render` show what a developer gets, without publishing anything:

```console
$ halo whoami --user you@example.com
user     you@example.com
ring     ring3-ga
profile  default
variants (none: no running experiment enrolls this user)
$ halo render --ring ring3-ga --out rendered
write rendered/Library/Application Support/ClaudeCode/managed-settings.json
```

The paths mirror the target machine (macOS here; Linux and Windows get their own). The policy repo itself has a [complete model](/halos/concepts/policy-model/) and a [field reference](/halos/reference/policy/).

## How a change travels

1. **Pull request.** Someone edits YAML: bump a CLI version, add an MCP server, route `opus` to a new model.
2. **CI checks.** `halo validate` (schema and guardrails: `bypassPermissions` can never ship), `halo plan` (the diff each ring would get), and optionally an [eval gate](/halos/concepts/evals/).
3. **A human merges.** Halos never merges or promotes on its own; only rollback is automatic.
4. **Publish.** `halo release publish` builds the release for a ring, signs it and pushes it to your OCI registry. Releases are immutable and content-addressed.
5. **Rings.** A ring is a signed pointer to a release. Promotion moves the pointer to the next ring; rollback moves it back. See [rings and releases](/halos/concepts/rings-and-releases/) and [rollouts](/halos/concepts/rollouts/).
6. **Devices and gateway.** `halod`, the agent on each laptop, dev container or CI runner, verifies the signature and writes the managed config for its ring. The gateway (`halo-proxy` or Kong with `halo-kong`) loads the compiled policy and routes each model alias by the caller's verified identity, so experiments and canaries apply without touching the client.

Telemetry from the gateway and the CLIs feeds back into experiment verdicts. A breach measured at the gateway trips the kill switch on its own; any other breach, and everything else, waits for a PR.

## What runs where

| Component | Where | Does |
|---|---|---|
| `halo` | CI, platform laptops | Validate, plan, render, publish, eval, rollouts |
| `halod` | Every developer machine | Pull, verify, apply the ring's release; honour the kill switch |
| `halo-proxy` / `halo-kong` | Your network | Model routing, experiments, header stripping; failover and wire translation in `halo-proxy` only |
| `halo-server` | Your network | Console, self-service enrollment portal, signed kill switch |
| `halo-shadow` | Your network | Mirror sampled requests to a candidate for shadow evals |

You can adopt in pieces: config only (`halo` + `halod`), or traffic only (the gateway), or both. Next: try it all in the [playground](/halos/getting-started/playground/), or follow [your first 10 minutes](/halos/tutorials/first-10-minutes/).
