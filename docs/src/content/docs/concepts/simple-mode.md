---
title: Simple mode
description: One halos.yaml and a handful of intent commands; the low-level policy is generated, inspectable with halo explain and ejectable with halo eject.
---

Simple mode is the default way to run Halos. `halo init` writes a single `halos.yaml`, and `halo validate`, `render`, `release` and every server read it as if the full policy were on disk. The Gateway, the `default` Profile and the Rings are generated from it in memory, deterministically, and go through the same validation and guardrails as hand-written documents.

## The file

```yaml
apiVersion: halos.dev/v1
kind: Halos
org: acme
tools:                                         # exact version pins
  claude-code: 2.1.280
  codex: {version: 0.99.0, model: codex}       # codex speaks the OpenAI wire: its own start model
provider: anthropic                            # anthropic | bedrock | vertex | openai | gemini | multi
models:
  default: claude-sonnet-4-5                   # required: what every tool starts on unless it names its own
  strong: claude-opus-4-1
  codex: openai/gpt-5-codex
gateway: https://ai.acme.example
identity: {issuer: https://login.acme.example, audience: halos, adminGroups: [ai-platform]}
safety: standard                               # strict | standard | relaxed
rollout: standard                              # fast | standard | careful
```

| Key | Expands to |
|---|---|
| `tools` | `harnesses` in the `default` profile, plus the gateway protocol each tool speaks. `{version, model}` sets that tool's start model to one of the `models` aliases (`harnesses.<tool>.model`); a bare version starts it on `default`. Give a tool whose wire the default provider cannot serve (codex is `openai-responses`, gemini-cli is `gemini`) a model on a provider that can |
| `provider` | One gateway upstream. A mapping sets options: `{name: bedrock, region: eu-west-1}`, `{name: vertex, project: acme-ai, region: us-east5}`, `{name: anthropic, url: https://llm.internal}` |
| `models` | One gateway alias per key, all of them allowed and enforced in the profile. A list is a failover order: `default: [eu.anthropic.claude-sonnet-4-5-20250929-v1:0, anthropic/claude-sonnet-4-5]`. A `<provider>/` prefix picks another provider; with `provider: multi` every id needs one |
| `gateway` | The gateway's `baseURL` |
| `telemetry` | Optional OTLP/HTTP endpoint. Telemetry is always on |
| `team` | Optional ring0 members: IdP groups, or user ids containing `@`. Default `identity.adminGroups`, else `<org>-ai-platform` |
| `safety`, `rollout` | The presets below |

Decoding is strict, as everywhere: a misspelled key (`saftey:`) is an error with its line.

`halo init` never leaves a tool on a model it cannot reach. It gives `default` the provider's current model. For each tool whose wire the default model's provider cannot answer (codex speaks OpenAI Responses, gemini-cli speaks Gemini), it adds a model alias named after the tool on that vendor (`codex: openai/gpt-5-codex`, `gemini-cli: gemini/gemini-2.5-pro`, or `claude-code: anthropic/claude-sonnet-4-5` on an OpenAI or Gemini org), and prints a `note:` naming it:

```console
$ halo init --org acme --tools claude-code@2.1.280,codex@0.99.0
note: codex: added model alias codex = openai/gpt-5-codex (the default model's provider cannot serve codex; change it with --model codex=<id>)
create halos.yaml
next: halo explain --policy-dir .   (the full policy this expands to)
next: halo validate --policy-dir .
```

`--model codex=<id>` picks the model yourself (an id without a `<provider>/` prefix runs on the tool's vendor), and `halo init -i` asks. Provider `vertex` needs `--project`.

## Presets

Every safety preset sets `disableBypass`, the `workspace-write` sandbox, and denies reads of `.env`, `.env.*`, `secrets/**`, `~/.aws/**` and `~/.ssh/**`. None can produce `bypassPermissions`.

| `safety` | Adds |
|---|---|
| `strict` | `sandboxRequired`, denies for `~/.kube`, gcloud config, `*.pem`, `*.key`; an egress allowlist (gateway, telemetry, GitHub, npm, Go proxy, PyPI); managed-only MCP and hooks |
| `standard` (default) | Managed-only MCP and hooks |
| `relaxed` | Permission mode `acceptEdits`; developers may add their own MCP servers and hooks |

| `rollout` | Rings | Canary ramp | Bake: ring0 / later rings |
|---|---|---|---|
| `fast` | ring0-team, ring1-ga | 25% | 4h / 1d |
| `standard` (default) | ring0-team, ring1-canary 5%, ring2-early 25%, ring3-ga | 5, 25, 50% | 1d / 2d |
| `careful` | ring0-team, ring1-canary 1%, ring2-early 5%, ring3-broad 25%, ring4-ga | 1, 5, 25, 50% | 2d / 3d |

The rollout preset also sets the step template the intent commands write. Canary steps carry guardrails (tool and API error rate for CLI upgrades; API error rate and p95 latency for model switches), so a breach rolls back on its own. Every ring after ring0 needs a human approval.

## Intent commands

Each command writes ordinary policy documents, validates the result before writing anything (exit 2 and nothing written if it would not validate), supports `--dry-run` (prints the diff), and lists every file it creates or changes. You commit and merge them like any other policy change. None of them merges or moves a ring pointer.

| Command | Writes |
|---|---|
| `halo upgrade start <tool> <version>` | A client-axis rollout, its canary experiment and treatment profile; publishes the candidate release (see below) |
| `halo upgrade publish <rollout>` | Nothing in the repo: pushes the candidate a `--no-publish` start named |
| `halo model switch <alias> <model>` | `models.<alias>` in `halos.yaml` |
| `halo model switch <alias> <model> --canary` | A traffic-axis rollout and its experiment |
| `halo enable mcp <name> --url ... [--for ...]` | `--for all` (default): the profile. A ring, `N%`, `group:<name>` or `user:<id>`: a toggle |
| `halo enable hook <name> --event ... --command ... [--for ...]` | Same as `enable mcp` |
| `halo kill <name> --reason ...` | Nothing: kills an experiment or toggle (or a rollout's experiment) on halo-server's signed kill list |
| `halo status` | Nothing: rings, rollouts, live experiments, toggles and policy health on one screen |

### Upgrading a CLI

```console
$ export HALO_REGISTRY=registry.acme.example/halos HALO_KEY=keys/release.key
$ halo upgrade start claude-code 2.1.300
ok published registry.acme.example/halos vclaude-code-2.1.300 (sha256:56b5b656…); no ring pointer moved
ok published channel ring1-canary.x-claude-code-2.1.300-canary.next (sha256:8d142ad5…): reached only once the experiment runs
create experiments/claude-code-2.1.300-canary.yaml
create profiles/claude-code-2.1.300.yaml
create rings/ring0-team.yaml
create rings/ring1-canary.yaml
create rings/ring2-early.yaml
create rings/ring3-ga.yaml
create rollouts/claude-code-2.1.300.yaml
next: start it: merge this, then `halo rollout advance claude-code-2.1.300 --reason ...` opens the first step's PR
next: after it completes, set halos.yaml tools.claude-code to 2.1.300 so new releases keep the pin
```

`upgrade start` builds the candidate release (the treatment profile rendered for the GA ring), signs it and pushes it as `v<tool>-<version>` without moving any pointer. It publishes the treatment on its [experiment channel](/halos/concepts/experiments/), which devices reach only once the experiment runs. Then it writes the rollout with `change.release` set to the candidate's digest and `baseline.release` set to the digest the GA ring's signed pointer serves. The ring files are small stubs that let the rollout's PRs pin each ring's `release`; membership still comes from `halos.yaml`. `halo rollout plan claude-code-2.1.300` shows the timeline.

Without registry access (for example on a laptop), add `--no-publish`. It computes the same digest locally and tells you what to run later, typically in CI after merge:

```console
$ halo upgrade start claude-code 2.1.300 --no-publish --baseline sha256:877fd48a…
…
next: push the candidate (vclaude-code-2.1.300, sha256:56b5b656…; moves no ring pointer): halo upgrade publish claude-code-2.1.300 --registry <repo> --key <key>
```

`halo upgrade publish` rebuilds the release from the merged policy and pushes it only if its digest is exactly the rollout's `change.release`. `--release` and `--baseline` override either digest.

## Mixing in low-level documents

Any document with a generated name is merged over the generated one: explicit fields win, gateway `models` and `upstreams` are replaced per key, and profile `permissions.deny`, `mcp.denied` and hooks only add up (as with `extends`). Any other document (experiments, toggles, rollouts, extra rings or profiles) is simply added. So you can drop to full control one document at a time. For example, `profiles/default.yaml` with only an `mcp.servers` list adds those servers to the generated profile.

A field set to its zero value counts as unset, so an overlay cannot set a ring's `order` to 0 or turn a preset's `true` back to `false`; eject for that.

## See it: `halo explain`

```console
$ halo explain --kind ring
# source: halos.yaml (simple mode), overlaid by rings/ring0-team.yaml
apiVersion: halos.dev/v1
kind: Ring
name: ring0-team
order: 0
profile: default
membership:
  groups:
    - ai-platform
…
```

Every document of the effective policy, each with its source: generated, generated plus an overlay file, or a file. `--output json` gives the same as data.

## Outgrow it: `halo eject`

`halo eject` writes the generated Gateway, Profile and Rings (merged with any overlays) as ordinary files, and removes the simple keys from `halos.yaml`. The policy loads to exactly the same thing afterwards; from then on you edit the documents described in the [policy model](/halos/concepts/policy-model/). It refuses to overwrite a file that does not hold the document it is writing.
