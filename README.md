<p align="center">
  <img src="assets/hero.svg" alt="Halos architecture: policy repo to signed release to dev containers, workspaces and laptops, through halo-proxy or Kong to Bedrock or Anthropic, with an evidence loop back" width="900">
</p>

<h1 align="center">Halos</h1>

<p align="center"><b>Ship AI coding tools like you ship software: versioned, signed, ring-deployed, and proven by evals.</b></p>

<p align="center">
  <a href="https://github.com/dshakes/halos/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dshakes/halos/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://goreportcard.com/report/github.com/dshakes/halos"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/dshakes/halos"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://dshakes.github.io/halos/"><img alt="Docs" src="https://img.shields.io/badge/docs-halos--dev.github.io-0f766e.svg"></a>
</p>

Halos is an open-source control plane that rolls Claude Code, Codex, Gemini CLI and Copilot CLI configuration, versions and model routes out to a company like a software release: signed, ring by ring, gated on evals, with an automated controller that watches experiments and an instant, signed kill switch when one goes wrong.

> **Status: pre-release (`v1alpha1`).** The compiler, signing and ring pointers, `halod`, `halo-proxy` (including direct Bedrock signing), `halo-kong`, `halo-shadow`, `halo-server` (including the experiment controller and kill switch), the Helm chart and the MCP server are implemented and unit-tested. The evidence plane (collector to ClickHouse to verdicts and Grafana) is exercised end to end by `make obs-e2e` with synthetic telemetry. Several integrations have never run against the real third-party system; they are listed under [What is not verified](#what-is-not-verified). No tagged release exists yet: build from source.

## The problem

It is Tuesday, 9:40am. Claude Code ships a patch release that changes how it reads a managed setting. Your auto-update, or a helpful Slack message, gets it onto 300 laptops by 10:15. Bash tool calls start failing behind your gateway. Nobody on your platform team can say which developers are on which version, whether the new version is worse, or how to undo it. The rollback plan is a Slack message asking 300 people to downgrade a CLI and edit a JSON file.

Nothing about this is exotic. It is what "deploy" looks like when AI dev tools are treated as personal software instead of production dependencies:

- **Settings sprawl.** Claude Code, Codex, Gemini CLI and Copilot CLI each have their own config format, precedence rules and enforcement knobs. Nobody owns the union.
- **No staged rollout.** Every CLI upgrade and every model alias change goes to everyone at once.
- **No gate.** "The new model feels fine" is the release criterion.
- **No rollback.** Reverting is a human process, and a bad experiment keeps burning money until someone merges a PR.

## Why now

- **AI CLIs ship weekly and model upgrades land monthly.** The rate of change already exceeds what an org can review by hand.
- **The vendor's central push channel is not there for you.** Claude Code's server-managed settings are not fetched when you use Bedrock or a custom `ANTHROPIC_BASE_URL`, which is exactly what orgs with a gateway do. Config has to arrive as files, MDM payloads or environment definitions, and somebody has to own that pipeline.
- **The agent is now a privileged process.** A hook is a shell command; an MCP server is a network client with your credentials. Config for these tools is a supply-chain surface, not a preference file.

## The insight

Treat AI dev-tool configuration as a **signed, ring-deployed release** with **eval-gated promotion**, and put the model traffic behind a plane you control. Then:

- a CLI or config change is a release: immutable, content-addressed, signed, and rolled through rings by re-pointing a signed pointer;
- a model change is a route at the gateway, so the rollback for the most common change is instant and touches no client, and a **signed kill switch** switches a bad experiment off at every gateway in seconds, without waiting for a merge;
- promotion is evidence: replay evals, sticky A/B and canary experiments, single-turn shadow comparisons. A controller evaluates running experiments continuously; on a rollback verdict it trips the kill switch (when the evidence is gateway-sourced and a kill key is configured), opens the pause PR and notifies you; on a promote verdict it opens a PR. A human merges.

## What it is

You keep profiles, rings and experiments as YAML in git. Halos compiles them per harness, signs an immutable release, and publishes a signed pointer per ring. `halod` (or the Dev Container Feature, or an MDM export) verifies and applies it on each machine. `halo-proxy` (or the `halo-kong` Kong plugin) verifies the caller's OIDC token, assigns the cohort, rewrites the model alias and stamps the request. `halo-proxy` can also sign requests to Amazon Bedrock with its own AWS identity, so developers need no AWS credentials. Telemetry and evals feed an analysis that yields a verdict; the controller (`halo-server --controller`) acts on it: kill switch and pause PR on rollback, conclude PR on promote or expiry. `halo exp promote` turns a promote verdict into a rollout PR.

```mermaid
flowchart LR
  subgraph POLICY[Policy]
    P[policy repo<br/>git] --> C[halo release publish<br/>harness adapters]
    C --> R[(signed release<br/>+ signed ring pointer<br/>OCI registry)]
  end
  subgraph CLIENT[Client plane]
    R --> D1[Dev Container Feature]
    R --> D2[Coder module]
    R --> D3[halod agent<br/>+ MDM exports]
    PORTAL[halo-server portal<br/>launchers, enrollment] -.-> D3
  end
  subgraph TRAFFIC[Traffic plane]
    D1 & D2 & D3 -->|OIDC JWT| K[halo-proxy or Kong + halo-kong]
    K --> A[your gateway / auth GW] --> B[(Bedrock / Anthropic / OpenAI-compatible)]
    K -.async first-turn mirror.-> S[halo-shadow]
    K -->|SigV4, own AWS identity| BR[(Bedrock direct)]
  end
  subgraph EVIDENCE[Evidence plane]
    D1 & D2 & D3 -.OTLP.-> T[OTEL collector<br/>halo.* schema]
    S --> E[halo eval / judge]
    T --> N[halo exp analyze]
    E --> N
    N --> PR[halo exp promote<br/>opens PR]
    T --> CT[controller<br/>halo-server --controller]
    CT -->|pause / conclude PR| PR
  end
  CT ==>|rollback: signed kill list, polled| K
  PR -->|human merges: ring pointer moves| P
```

| Plane | Job | Components |
|---|---|---|
| **Client** | Make the developer environment match a signed release | `halod`, Dev Container Feature, Coder module, Codespaces, Jamf/Kandji/Intune exports, `halo-server` self-service portal |
| **Traffic** | Verify identity, assign cohorts, route and rewrite models, mirror, honor the kill switch, sign Bedrock requests | `halo-proxy` (stack-agnostic) or Kong + `halo-kong`, `halo-shadow` |
| **Evidence** | Prove a change is safe, and act when it is not | OTEL collector, ClickHouse, `halo eval`, `halo exp analyze`, `halo exp promote`, the controller and signed kill switch in `halo-server` |

### Rollout: a CLI upgrade from PR to GA

```mermaid
sequenceDiagram
  autonumber
  actor Eng as Platform engineer
  participant Git as Policy repo (PR + CI)
  participant Reg as OCI registry
  participant D as Devices (halod, dev containers)
  participant GW as halo-proxy / Kong
  participant EV as Evidence (OTEL, ClickHouse)
  actor Rev as Human reviewer
  Eng->>Git: PR: bump claude-code pin, add client-axis A/B in ring1
  Git->>Git: halo validate, halo plan, halo eval run (candidate vs current)
  Git-->>Rev: scorecard on the PR
  Rev->>Git: merge
  Eng->>Reg: halo release publish --ring ring0 (signed release + signed pointer)
  D->>Reg: halod pulls pointer, verifies signature, org, ring, seq, expiry
  D->>D: apply files atomically, install verified CLI artifact
  Note over D,GW: ring1 users split 50/50 by hash(user, salt)
  D->>GW: requests carry OIDC JWT, gateway stamps ring and variant
  D--)EV: OTLP with halo.ring, halo.release
  EV->>EV: halo exp analyze (mSPRT + guardrails)
  alt guardrail breach
    EV->>GW: controller trips the kill switch (signed list, polled ~10s): control routing
    EV->>Git: controller opens the pause PR (never merged for you)
    Eng->>Reg: halo rollback --ring ring1 --to previous
    D->>Reg: next pull: new pointer, higher seq, older digest
  else promote verdict
    Eng->>Git: halo exp promote opens PR moving ring2 pointer
    Rev->>Git: merge (ring2, then GA)
  end
```

## 90-second demo

Needs Go 1.25+, Docker with Compose v2, and `curl`. Nothing here talks to a real model provider: the upstreams are mocks.

```bash
git clone https://github.com/dshakes/halos && cd halos
make build && export PATH="$PWD/bin:$PATH"

halo validate --policy-dir examples/acme-corp                                            # schema + guardrails
halo whoami --policy-dir examples/acme-corp --user alice@acme.com --groups ai-platform   # ring0-harness-team
halo render --policy-dir examples/acme-corp --ring ring1-canary --os linux --out /tmp/rendered   # the files halod would write

cd deploy/compose && docker compose up -d --build                         # Kong + halo-kong, mock IdP, mock upstreams, halo-shadow
TOK=$(curl -s 'localhost:8081/token?user=alice@acme.com&groups=ai-platform')
curl -s localhost:8080/v1/messages \
  -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
  -H 'anthropic-version: 2023-06-01' -H 'x-claude-code-session-id: s1' \
  -H 'x-halo-ring: ring3-ga' \
  -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
# ... served-by=orch model=us.anthropic.claude-sonnet-4-5-v1:0 ... x-halo-ring:ring0-harness-team ...
docker compose down -v; cd ../..
```

The `x-halo-ring: ring3-ga` the client sent was discarded; the upstream saw the ring derived from the verified token, and the alias `sonnet` was rewritten to the upstream model id.

### The kill switch and audit log

The rollback half of the loop, locally, with no Docker. This is what the controller does on a `rollback` verdict; here you do it by hand as an admin (`--dev-insecure-user` disables login, demo only):

```bash
D=$(mktemp -d)
halo keys generate --name killswitch --out $D                     # a dedicated key, never the release key
printf 'gateway-token-0123456789' > $D/gw.token; printf 'fleet-token-0123456789' > $D/fleet.token
halo-server -policy-dir examples/acme-corp -token-file $D/fleet.token -data-dir $D/data \
  -killswitch-key-file $D/killswitch.key -gateway-token-file $D/gw.token \
  -dev-insecure-user admin@acme.com -dev-insecure-admin -listen 127.0.0.1:18080 &

curl -s -X POST localhost:18080/api/v1/experiments/opus-5-5-canary/kill -d '{"reason":"demo"}'
# {"changed":true,"experiment":"opus-5-5-canary","killed":true}
curl -s localhost:18080/api/v1/gateway/killswitch -H 'Authorization: Bearer gateway-token-0123456789'
# {"payload":"<base64 {version, experiments, issuedAt}>","signature":"<base64 ed25519>"}
curl -s localhost:18080/api/v1/audit         # "verified":true, one experiment.kill entry, hash-chained
kill %1
```

`halo-proxy` and `halo-kong` poll that signed list (every 10 seconds), verify it with the kill-switch public key (`$D/killswitch.pub`), and treat `opus-5-5-canary` as not running: control routing, no mirroring. Unit tests cover the gateway side; a live gateway polling a live `halo-server` has only been exercised in tests. See [experiments](https://dshakes.github.io/halos/concepts/experiments/#kill-switch).

### A/B a CLI upgrade on the client axis

```bash
halo release publish --policy-dir examples/acme-corp --ring ring1-canary --release-version 2.1.300 \
  --registry localhost:5055/acme/halos --key halo.key --plain-http --no-artifacts
# published ... tags v2.1.300, ring-ring1-canary
#   channel experiment claude-cli-2.1.3xx-ab variant control:  ... ring-ring1-canary.x-claude-cli-2.1.3xx-ab.control
#   channel experiment claude-cli-2.1.3xx-ab variant cli-next: ... ring-ring1-canary.x-claude-cli-2.1.3xx-ab.cli-next
```

Each variant is a signed release on its own channel. `halod` computes its variant with the gateway's hash and applies that channel (Claude Code pin plus `halo.experiment`/`halo.variant` telemetry attributes). Run against a local registry and a test build of `halod`; not against a live fleet. Walkthrough: [A/B a CLI upgrade](https://dshakes.github.io/halos/guides/cli-upgrade-ab/).

### The controller and the evidence plane

```bash
make obs-e2e    # Docker + network: collector -> ClickHouse -> verdicts -> Grafana, with synthetic telemetry
```

It brings up `deploy/observability`, sends synthetic harness telemetry (and gateway metrics from `halo-proxy`'s real emitter) with known regressions in cost, error rate and latency, asserts that `halo exp analyze` returns `rollback` for each and `continue` for an identical-arms experiment, and that every Grafana dashboard panel returns data. In production the controller runs that same evaluation on a timer:

```bash
halo-server ... -controller -clickhouse-url http://clickhouse:8123 -policy-repo-dir /srv/policy-writer \
  -killswitch-key-file killswitch.key -gateway-token-file gw.token -notify-slack-url-file slack.url
# or, from CI / cron:
halo controller run --once --policy-dir . --clickhouse http://clickhouse:8123 --data-dir /var/lib/halos
```

### Bedrock without an orchestrator

Declare `kind: bedrock` upstreams in the gateway policy and `halo-proxy` SigV4-signs Bedrock requests with its own AWS identity (IRSA, Pod Identity, instance profile, env). Developers only need their Halos token. Setup and region rules: [stack-agnostic traffic plane](https://dshakes.github.io/halos/concepts/stack-agnostic/#direct-bedrock-sigv4-in-halo-proxy). This is tested against a fake Bedrock with fixed-key signatures, **not** real AWS.

The full walkthrough, including publishing, promoting and rolling back a signed release against a local registry, is the [quickstart](https://dshakes.github.io/halos/getting-started/quickstart/).

## Who it is for

- **Platform and developer-productivity teams** running Claude Code, Codex, Gemini CLI or Copilot CLI for hundreds to thousands of engineers, especially behind Bedrock, a custom gateway, Kong, LiteLLM or Envoy.
- **Security teams** who need model allowlists, MCP allowlists, "no bypass permissions", verified config delivery and an audit trail in git.
- **Not for** a five-person team on one CLI with vendor-managed settings. Use the vendor's admin console.

## How it compares

| | Cross-harness config | Version pinning | Rings | A/B + shadow | Eval gate | GitOps + rollback | Self-hosted |
|---|---|---|---|---|---|---|---|
| Vendor admin consoles | No: one tool each | Varies | No | No | No | No | No |
| LLM gateways (LiteLLM, Portkey, Kong AI) | No: traffic only | No | Weighted routing | Routing only [a] | No | Config as code | Yes |
| Analytics (Faros, Jellyfish) | No: observe only | No | No | No | No | No | No |
| Roll your own | You build it | You build it | You build it | You build it | You build it | You build it | Yes |
| **Halos** | Yes | Yes (CLI-enforced or `halod`) | Yes | Yes | Yes | Yes | Yes |

[a] Kong OSS has no request-mirroring plugin and `ai-proxy-advanced` load balancing is Enterprise-only, which is why Halos ships `halo-shadow`. Halos complements a gateway; it does not replace one. Competitor cells summarize typical product scope and should be re-checked against each vendor before you rely on them.

## Harness capability matrix

Generated from the adapters (`halo harnesses`) and the sources cited in [`internal/harness/FACTS.md`](internal/harness/FACTS.md). "Rendered" means the adapter writes the harness's native enforcement; where it cannot, the adapter emits a warning in the release manifest instead of dropping the setting silently.

| Capability | Claude Code | Codex | Gemini CLI | Copilot CLI |
|---|---|---|---|---|
| Version pin | CLI-enforced | `halod` enforces | `halod` enforces | `halod` enforces |
| Model lock | Rendered | Rendered | Rendered | Default only (warns) |
| MCP allowlist | Rendered | Rendered | Rendered | Rendered |
| Hooks lock | Rendered | No | No | No |
| Permissions | Rendered | Rendered | Partial: `admin.secureModeEnabled` only | Rendered (`disableBypassPermissionsMode`) |
| Gateway | Rendered | Rendered | Rendered (env via `/etc/profile.d`, login shells) | Not rendered: BYOK is env-only |
| Request headers (ring stamps) | Rendered | Rendered | No | No |
| Telemetry (OTEL) | Rendered | Rendered | Rendered | Rendered (http only) |
| Instructions | Managed `CLAUDE.md` | No | No | No |

Everything above was derived from vendor documentation. **Nothing was executed against a real CLI.** Details and paths: [harness matrix reference](https://dshakes.github.io/halos/reference/harness-matrix/).

## Security posture

- **Signed releases and signed ring pointers.** A release is an immutable OCI artifact signed with ed25519 (cosign co-signing optional). Each ring has a signed pointer `{org, ring, digest, seq, issuedAt, expiresAt}`. `halod` trusts the pointer, not the mutable ring tag: it refuses a regressed `seq`, an expired pointer, or the wrong org or ring. Pointers expire after 7 days; `halo release refresh` re-signs them and must run on a schedule.
- **The signer is guarded too.** `promote`, `refresh`, `publish` and `rollback` keep a signer state file (`$XDG_STATE_HOME/halos/pointers.json`) and refuse a registry that serves an older pointer than this signer wrote, so a replay cannot be re-signed into a fresh one. `promote` follows the source ring's *signed* pointer, never its tag; `rollback --to <version>` requires the signed manifest to carry that version; `refresh` refuses expired pointers (recover with `halo rollback --to <version>`); `--expect-digest` is the stateless guard. Stateless CI must cache the state file, or the replay check is off.
- **Verified artifacts, not `curl | bash`.** CLI installs come from sha256/sha512-pinned artifacts in the signed manifest. The legacy shell-install path exists only behind `allowShellInstall: true` and is off by default.
- **Root-side hardening in `halod`.** Per-harness path allowlist (a signed manifest cannot write arbitrary files as root), 0644 mode ceiling, root-ownership and symlink checks on config, key, token and state chains, atomic writes.
- **Guardrails at validate and at release.** Overrides are a per-harness allowlist, no `bypassPermissions` / `danger-full-access` anywhere (checked again on the rendered output), no literal secrets, reserved env prefixes, strict names. See [security model](https://dshakes.github.io/halos/concepts/security-model/).
- **Identity is verified, never trusted.** The gateway checks the caller's OIDC JWT (issuer, audience, expiry, RS256/ES256/EdDSA only). Client `x-halo-*` headers are stripped. The model allowlist fails closed.
- **Key rotation without a flag day.** `halod.yaml` takes `pubkeys: [..]` (any listed key verifies) and `revokedKeys` (fingerprints never trusted). Device tokens expire after `halo-server --device-ttl` (default 90 days); `POST /api/v1/users/{id}/revoke-sessions` logs a user out everywhere; an `email` identity claim must carry `email_verified=true`.
- **Signed kill switch.** Gateways take the kill list only if it verifies against a dedicated ed25519 key (not the release key), is fresh (not older than 10 minutes, not more than 1 minute in the future) and strictly newer than the one they hold. A failed fetch keeps the last list. Gateways refuse a cleartext kill URL unless told it is in-cluster, and `halo-kong` flags a broken kill-switch config with `x-halo-killswitch: misconfigured`. Privileged actions, including kills, go to a hash-chained, fsynced audit log and fail closed if the append fails; tail truncation is not detectable from the log alone.
- **Evidence has a trust boundary.** Developer machines can post any telemetry, so the collector splits receivers: the CLI receiver drops `halo.gateway.*`, stamps `halo.source=cli` and can require per-device tokens; only the bearer-token gateway receiver (`:4319`) stamps `gateway`. The controller auto-kills only on gateway-sourced evidence; CLI-sourced rollbacks open the pause PR and wait for a human. Controller webhooks are HMAC-signed over a timestamp; receivers must verify it and reject timestamps more than 5 minutes old.
- **Human at every irreversible step.** No auto-merge, no auto-promote. Automatic rollback (the kill switch, which only returns users to control) is the only automatic direction, and the MCP server exposes no tool that publishes, retags, merges or pushes.

Full attacker models and mitigations: [threat model](https://dshakes.github.io/halos/reference/threat-model/). Report vulnerabilities per [SECURITY.md](SECURITY.md).

> **Shadowing is single-turn only.** Agentic sessions are multi-turn with side-effecting tool calls, and a shadow candidate's tool calls never execute in the developer's workspace. `halo-shadow` mirrors first-turn requests and grades them with a judge. Whole-task comparison is done with containerized **replay evals** ([ADR-0004](docs/adr/0004-shadow-single-turn-only.md)).

## Operations notes

- `halo-proxy` serves `/healthz` and `/metrics` only on an admin listener (`--admin-listen`, default `127.0.0.1:9090`; the Helm chart sets `:9090`). The public listener serves proxied model paths and `/v1/models`; everything else is 404.
- `halo-shadow --metrics-listen` (env `HALO_SHADOW_METRICS_LISTEN`, empty = off) serves an unauthenticated `GET /metrics` for Prometheus; guard it with a NetworkPolicy (the chart does).
- `halo-shadow decrypt-pairs [-pair-key-file FILE]... PAIRS.jsonl` decrypts an at-rest-encrypted pair file to plaintext JSONL on stdout (ops command; repeat the flag for retired keys).
- `halo-server --controller` runs the experiment loop and `--metrics-listen` serves its unauthenticated `halo_controller_*` metrics. Give it a dedicated policy clone (`--policy-repo-dir`); run one controller per data dir. Kills reach gateways only through `halo-server`'s `--data-dir`, and only when `--killswitch-key-file` (which requires `--data-dir`) is set; otherwise rollbacks are reported as not enforced. `halo controller run` appends to the same `audit.jsonl`, so never run it against a live server's data dir. Canonical flags are `--verdicts-file` and `--interval`; the old names still work but are deprecated.
- Signing in CI: cache `$XDG_STATE_HOME/halos/pointers.json` between `halo release refresh` runs (see `.github/workflows/refresh-pointers.yml.example`), or pass `--expect-digest`.
- `halo export` needs `--org` with `--ring` and verifies the ring's signed pointer before writing. Policy commands take `--policy-dir` (the old `--dir` and positional dir are deprecated).

## What is not verified

Reported honestly. These are implemented or written from documentation, but have not run against the real system:

- Real Kong Enterprise or Konnect, and real Kong OSS live traffic through the `kong.yml` integration template (config parses; the halo-kong compose demo does run).
- Real Amazon Bedrock. `halo-proxy`'s SigV4 signing (and its AWS-host / `signHosts` gate) is tested against the AWS test-suite vector and a fake Bedrock, never real AWS; IRSA and Pod Identity credential resolution on a real cluster is likewise unrun. Google Vertex is not supported.
- MDM pushes to real devices (Jamf, Kandji, Intune). Output formats are generated and unit-tested, not deployed.
- The PowerShell (Intune, `enroll.ps1`) and Terraform (Coder module) artifacts have not been executed. `halod` on Windows has not been run as a service; it is a console binary you wrap in a scheduled task or NSSM.
- Envoy, nginx, AWS API Gateway, LiteLLM and provider templates: config validated where a validator exists (`envoy --mode validate`, `nginx -t`, `kong config parse`); live traffic not run. AWS API Gateway and LiteLLM were not run at all.
- The Helm chart: `helm lint`/`template` and kubeconform only; never installed in a cluster (probes, ServiceMonitor and NetworkPolicy on the admin/metrics ports are unobserved). Container images are not published yet.
- Signing continuity against a real CI runner, a real GHCR/ECR registry and a real cache eviction: the state file, `--expect-digest`, expired-pointer recovery and `rollback --to <version>` are tested against a local `registry:2` and unit tests only.
- Evidence trust on a real fleet: the two-receiver collector (bearer tokens, per-device `--cli-token-file`, request caps) is validated by `otelcol-contrib validate` and `make obs-e2e` with synthetic telemetry; a real collector exposed to real developer machines and real `halo-proxy` replicas sharing a unit salt is unrun.
- Webhook signature verification: the Go and Python receiver snippets in the docs were run against the controller's signer locally, not against a real Slack-compatible or SIEM receiver.
- The Helm chart's single policy clone (init-container `git clone`, `GIT_ASKPASS` / `GIT_SSH_COMMAND`) needs an image with `git`, `gh` and `ssh`; the image is not published and the flow was never run in a cluster.
- The controller and kill switch against a live gateway and a live ClickHouse: each side is unit-tested, and `make obs-e2e` covers the evidence plane with **synthetic** telemetry only, not real harness output, real `halo-proxy` traffic at scale or a real fleet.
- The real GitHub PR flow: PRs are opened with `gh` from a dedicated clone, tested with real local git and a stubbed `gh`, not against real GitHub.
- Every harness capability claim: read from vendor docs, not executed against real CLIs.

## Roadmap

| Area | Status |
|---|---|
| Policy model, validation, guardrails, JSON Schemas, harness adapters (Claude Code, Codex, Gemini CLI, Copilot CLI) | Implemented |
| Signed releases, signed ring pointers, `halo release publish/promote/refresh`, `halo rollback` | Implemented |
| `halod` agent: verify, path allowlist, verified artifact installs, drift report | Implemented; unit-tested against a fake root (`--root`), not yet run as root on real hosts; Windows unverified |
| Traffic plane: `halo-proxy`, `halo-kong`, decK generator, `halo-shadow` | Implemented; compose demo runs |
| Portal, enrollment, device tokens, access requests opening PRs (`halo-server`) | Implemented |
| Experiments, stats (mSPRT, bootstrap), `halo eval run`, `halo exp analyze/promote` | Implemented; ClickHouse pipeline proven end to end with synthetic telemetry (`make obs-e2e`), not at fleet scale |
| Controller (`halo controller run`, `halo-server --controller`), signed kill switch, audit log, releases and device console pages | Implemented; unit-tested; not run against real GitHub or a live fleet |
| Direct Bedrock signing in `halo-proxy` | Implemented; fake-Bedrock tests only |
| MCP server and Claude Code plugin | Implemented |
| Helm chart, ClickHouse schema, Grafana dashboard | Written; not run in a cluster |
| Published container images, tagged releases (goreleaser: checksums, SBOM, cosign) | Configured, not yet run for a tag |
| Rego hook for org-specific guardrails, native Windows service | Not started |

## Documentation

[Docs site](https://dshakes.github.io/halos/): [quickstart](https://dshakes.github.io/halos/getting-started/quickstart/), [architecture](https://dshakes.github.io/halos/concepts/architecture/), [self-service portal](https://dshakes.github.io/halos/concepts/self-service-portal/), [stack-agnostic traffic plane](https://dshakes.github.io/halos/concepts/stack-agnostic/), [production deployment](https://dshakes.github.io/halos/guides/production-deployment/), [agentic operations](https://dshakes.github.io/halos/guides/agentic-operations/), [experiments and the kill switch](https://dshakes.github.io/halos/concepts/experiments/), [CLI reference](https://dshakes.github.io/halos/reference/cli/), [API reference](https://dshakes.github.io/halos/reference/api/).

## Repo layout

```
cmd/halo          CLI: init validate plan render eval exp controller release rollback export gateway telemetry keys mcp harnesses whoami
cmd/halod         fleet agent: pull, verify, apply, report (run | once | status)
cmd/halo-proxy    stack-agnostic traffic plane: verify identity, assign cohort, rewrite model, mirror, kill switch, Bedrock SigV4
cmd/halo-kong     Kong Go-PDK plugin with the same behavior
cmd/halo-shadow   sampled async mirror + response pair store
cmd/halo-server   API, console, self-service portal, experiment controller, kill-list endpoint
internal/       policy, harness adapters, bundle, delivery, gateway, identity, assign, telemetry, eval, stats, promote, mcpserver
schemas/        published JSON Schemas
features/       Dev Container Feature, Coder module
plugins/        Claude Code plugin
evals/          replay-eval tasks and suites
examples/       acme-corp example policy repo
deploy/         compose quickstart, integrations (Kong, Envoy, nginx, AWS, LiteLLM), Helm chart, observability
docs/           Astro Starlight site and ADRs
```

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). Governance is in [GOVERNANCE.md](GOVERNANCE.md); the community is bound by the [Code of Conduct](CODE_OF_CONDUCT.md). Load-bearing changes need an [ADR](docs/adr/).

## License

[Apache-2.0](LICENSE).
