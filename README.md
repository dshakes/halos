<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/hero-dark.svg">
  <img src="assets/hero-light.svg" alt="Halos: policy to signed release to rollout rings to every environment, with an evidence loop back" width="880">
</picture>

<h3 align="center">Ship AI coding tools like software.<br><sub>Versioned · signed · ring-deployed · proven by evals</sub></h3>

<p align="center">
  <a href="https://github.com/dshakes/halos/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dshakes/halos/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://goreportcard.com/report/github.com/dshakes/halos"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/dshakes/halos"></a>
  <a href="LICENSE"><img alt="Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://dshakes.github.io/halos/"><img alt="Docs" src="https://img.shields.io/badge/docs-dshakes.github.io%2Fhalos-0f766e.svg"></a>
</p>

<p align="center">
  <a href="https://dshakes.github.io/halos/getting-started/quickstart/">Quickstart</a> ·
  <a href="https://dshakes.github.io/halos/concepts/architecture/">Architecture</a> ·
  <a href="https://dshakes.github.io/halos/reference/cli/">CLI</a> ·
  <a href="https://dshakes.github.io/halos/reference/threat-model/">Threat model</a>
</p>

---

**Halos is the open-source control plane for AI coding CLIs**: Claude Code, Codex, Gemini CLI and Copilot CLI.

- One policy repo becomes a signed release.
- Releases roll out ring by ring, behind A/B tests, canaries, shadows and feature toggles.
- Every step is gated on evals and live telemetry.
- A human-merged PR promotes; a regression rolls back automatically.

| Today | With Halos |
|---|---|
| Every laptop runs a different CLI version and `settings.json` | One signed release per ring, enforced by the CLI and the `halod` agent |
| A model or CLI upgrade hits 100% of engineers at once | Dark launch → 1% → 5% → 25% → GA, each step gated |
| Nobody knows whether the new version is better | pass@k evals, LLM-judged shadow traffic, sequential stats, a verdict |
| Rollback is a Slack message | Auto-rollback, plus a signed kill switch that gateways pick up within ~10 s |

<img src="assets/rollout.gif" alt="halo rollout plan prints a six-step dark-launch, canary and holdout plan; halo rollout simulate shows a regression caught and rolled back at the 1% step" width="880">

## Every rollout technique, as code

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/rollout-strategies-dark.svg">
  <img src="assets/rollout-strategies-light.svg" alt="Progressive rings, canary ramp, blue-green, dark launch, holdout" width="880">
</picture>

A `Rollout` is an ordered list of steps. Each step sets:
- a strategy and an exposure
- a bake time and a minimum sample size
- gates: metric guardrails, an eval scorecard, a human approval

```yaml
kind: Rollout
name: opus-5-5-upgrade
axis: traffic                    # client: a CLI/config release · traffic: a model route
experiment: opus-5-5-canary
change: {alias: opus}
steps:
  - name: dark-launch            # mirrored to the candidate, nothing served
    strategy: dark-launch
    percent: 10
    bake: 2d
    gates:
      scorecard: {file: evals/opus-5-5.scorecard.json, variant: opus-5-5, minPass1: 0.75}
  - name: canary-5
    strategy: canary
    percent: 5
    bake: 12h
    minSamples: 500
    gates:
      guardrails: [{metric: halo.api.error_rate, direction: decrease, maxRegression: 0.05}]
  - name: holdout                # 5% stay on the old model for 14 days
    strategy: holdout
    percent: 5
    bake: 14d
    gates: {approval: true}
```

The controller evaluates every step continuously:
- **A regression rolls back on its own.**
- **Progress always opens a PR that a human merges.** Nothing auto-promotes.

Commands: `halo rollout plan | status | simulate | advance | rollback` ([docs](https://dshakes.github.io/halos/concepts/rollouts/)).

## Experiments and feature toggles

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/experiments-dark.svg">
  <img src="assets/experiments-light.svg" alt="A/B on the client axis, canary on the traffic axis, shadow mirrored to a judge, all assigned by one deterministic hash" width="880">
</picture>

- **A/B** a CLI version or settings change. Each arm is its own signed release channel, and `halod` picks the arm with the same hash the gateway uses.
- **Canary** a model at the gateway, sticky per user and session, so agents never switch model mid-task.
- **Shadow** first-turn requests to a candidate model and grade the pairs with an LLM judge. Nothing from the candidate is served.
- **Toggles** turn one capability (an MCP server, a hook, a model route) on for a ring, an IdP group or a percentage of users. The payload ships inside the signed release, and a kill is instant with no new release.

<img src="assets/toggles.gif" alt="halo toggle eval shows which toggles are on for a developer and why; halo gateway routes shows the model route table with weights and failover" width="880">

## Measure, don't guess

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/measure-loop-dark.svg">
  <img src="assets/measure-loop-light.svg" alt="Change, offline evals, ring exposure, telemetry, mSPRT verdict, promote PR or auto-rollback" width="880">
</picture>

| | |
|---|---|
| **Offline evals** | Replay real tasks in containers, N trials each. Reports pass@1, pass@k and pass^k, with paired bootstrap CIs on pass rate, cost, tokens and time. Flaky tasks are detected and excluded. Verdict: `ship`, `hold` or `block`. |
| **Matrix** | Runs one suite across harness × model × provider (Claude Code vs Codex vs Gemini, Anthropic vs Bedrock) and produces a PR-ready report. |
| **Online** | Shadow pairs are graded against a pinned LLM-judge rubric and land in the same evidence plane as cost, latency and errors. |
| **Sequential stats** | mSPRT guardrails stop an experiment as soon as a regression is real, not at an arbitrary horizon. |
| **Upgrade watch** | `halo upgrade watch` spots a new CLI or model release, pins it on a branch, runs the suite and opens a PR with the scorecard. |

## Any CLI, any provider

| | Claude Code | Codex | Gemini CLI | Copilot CLI |
|---|---|---|---|---|
| Version pin | CLI-enforced | `halod` | `halod` | `halod` |
| Model lock | ✓ | ✓ | ✓ | default only |
| MCP allowlist | ✓ | ✓ | ✓ | ✓ |
| Permissions | ✓ | ✓ | partial | ✓ |
| Gateway + telemetry | ✓ | ✓ | ✓ | telemetry only |

A setting a CLI can't enforce produces a warning in the release manifest; it is never silently dropped. The full matrix and its sources are in the [harness reference](https://dshakes.github.io/halos/reference/harness-matrix/).

Traffic goes through `halo-proxy` or the Kong plugin to Anthropic, Bedrock (SigV4), Vertex, OpenAI or Azure OpenAI:
- Model aliases map to weighted splits and priority failover, with a circuit breaker per target.
- Moving a model to another provider is a one-line policy change.
- If you already run a gateway, Halos sits in front of it.

## Runs everywhere

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/everywhere-dark.svg">
  <img src="assets/everywhere-light.svg" alt="macOS, Linux, Windows, Dev Containers, Codespaces and Coder workspaces, CI runners, Kubernetes via Helm" width="880">
</picture>

```sh
# macOS / Linux
brew install dshakes/tap/halo
curl -fsSL https://raw.githubusercontent.com/dshakes/halos/main/install/install.sh | sh -s -- --version vX.Y.Z --with-agent

# Windows (elevated)
irm https://raw.githubusercontent.com/dshakes/halos/main/install/install.ps1 | iex
```

Also available:
- deb, rpm and apk packages, and Scoop
- a [Dev Container Feature](features/halos) and a Coder module
- Jamf, Kandji and Intune exports
- a [GitHub Action](action.yml) and a GitLab template for CI runners
- a [Helm chart](deploy/helm/halos)

The installers verify checksums and cosign signatures. See the [install guide](https://dshakes.github.io/halos/getting-started/install/).

> **Pre-release.** No version is tagged yet, so build from source: `make build && bin/halo validate --policy-dir examples/acme-corp`.

## Agent-native

`halo mcp serve` exposes these to any MCP client: validate, plan, rollout status, experiment analysis, toggle evaluation and eval scorecards.

The write tools (propose a rollout step, a rollback or a toggle change) are opt-in and dry-run by default, and they only ever open a PR. The [Claude Code plugin](plugins/claude-code) and the [Codex config](.codex) drive the same flow: edit → validate → eval → experiment → propose.

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/architecture-dark.svg">
  <img src="assets/architecture-light.svg" alt="Client plane, traffic plane and evidence plane with their components" width="880">
</picture>

## Security by construction

- **Signed everything.** Releases, ring pointers and the kill list are ed25519-signed, and cosign co-signs. Ring pointers carry sequence numbers and an expiry, so a registry can't replay an old one.
- **Identity, never headers.** The gateway verifies OIDC JWTs, strips client `x-halo-*` headers and fails closed on unknown models.
- **Guardrails twice.** `bypassPermissions` and `danger-full-access` are rejected at validate time and again on the rendered output.
- **Humans own the irreversible step.** There is no auto-merge, no auto-promote and no tool that publishes. Privileged actions land in a hash-chained audit log.

[Threat model](https://dshakes.github.io/halos/reference/threat-model/) · [SECURITY.md](SECURITY.md)

## Status

Every component is implemented and covered by unit, race, e2e (`make e2e`) and evidence-plane (`make obs-e2e`) tests.

Not yet exercised against the real systems:
- AWS Bedrock, Vertex, Azure OpenAI and OpenAI
- Kong Enterprise
- Windows at runtime
- MDM-managed devices
- the Helm chart on a live cluster
- real CLIs inside the eval runner

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) · [AGENTS.md](AGENTS.md) for coding agents · [ADRs](docs/adr) · Apache-2.0
