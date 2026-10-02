# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/); the policy API is `halos.dev/v1alpha1` and may change until v1.

## [Unreleased]

### Fixed
- `halod` on Windows: `state.json` is written with the managed `var` directory's DACL instead of an owner-only one, so the SYSTEM scheduled task no longer rejects a state file first written by an admin during enrollment.
- GitLab template: `.halos` no longer sets a job-level `HALOS_VERSION` default that shadowed the pipeline-level pin.

### Added
- CI verifies the delivery paths on every PR: `install.ps1`, `enroll.ps1` and `halod service install` on Windows, `install.sh`, `enroll.sh` and launchd on macOS, the composite Action, the GitLab template (`gitlab-ci-local`), and the dev container and Feature (devcontainer CLI).

## [0.1.0-rc.1] - 2026-10-02

### Added
- Client-axis experiments are delivered end to end: `halo release publish` writes a signed channel per variant (`<ring>.x-<experiment>.<variant>`), the ring manifest lists the experiment, and `halod` picks its variant with the gateway's hash and pulls that channel (subject from the ring endpoint, `halod.yaml` `subject:` or the last saved one). A channel that fails verification keeps last-good. Variant profiles are checked as guardrail errors. `refresh`, `rollback` and `promote` handle channels; `GET /api/v1/fleet/ring` returns `subject`; status and reports carry `experiment`/`variant`. See [ADR-0010](https://dshakes.github.io/halos/adr/0010-release-channels-for-client-experiments/) and [A/B a CLI upgrade](https://dshakes.github.io/halos/guides/cli-upgrade-ab/).
- `halod` can poll the signed kill list (`killSwitch` in `halod.yaml`, `GET /api/v1/fleet/killswitch`); a killed client-axis experiment reverts the device to the ring release.
- Policy model: `Gateway`, `Profile`, `Ring`, `Experiment` documents, plus the root `halos.yaml` with `identity` (any OIDC IdP) and `selfService`. Strict decoding, JSON Schemas, guardrails in Go.
- Harness adapters for Claude Code, Codex, Gemini CLI and Copilot CLI; capability matrix from `halo harnesses`, sources in `internal/harness/FACTS.md`.
- `halo` CLI: `init`, `validate`, `whoami`, `render`, `plan`, `release build|publish|promote|refresh`, `rollback`, `export jamf|intune|devcontainer`, `exp list|show|start|pause|conclude|analyze|promote`, `eval run`, `gateway compile|deck`, `telemetry collector-config`, `keys generate`, `mcp serve`.
- Signed releases (ed25519, optional cosign co-signature) and **signed ring pointers** with `seq` and a 7-day expiry; `halo release refresh` and an example scheduled workflow.
- `halod` fleet agent (`run`, `once`, `status`) with verified install artifacts, per-harness path allowlist, ownership preflight, anti-rollback state and drift reporting.
- Traffic plane: `halo-proxy` (stack-agnostic; deploy modes edge, behind, standalone), `halo-kong` Kong plugin, decK generator, `halo-shadow` (policy-resolved upstreams, optional encrypted pair store).
- `halo-server` with the developer self-service portal: OIDC login, launchers, single-use enrollment tokens, per-device tokens with revocation, access requests that open PRs.
- MCP server (`halo mcp serve`) and Claude Code plugin; Codex configuration.
- Helm chart, compose demo (Kong or `halo-proxy`), integration templates (Kong, Envoy, nginx, AWS API Gateway, LiteLLM, providers), ClickHouse schema and Grafana dashboard.
- **Experiment controller** (`halo controller run`, `halo-server --controller`): evaluates running experiments from ClickHouse on a timer; on `rollback` trips the kill switch, opens a pause PR and notifies; on `promote` or `expired` opens a conclude PR and notifies. Actions happen once per experiment run (`controller-state.jsonl`); it never merges. Slack and HMAC-signed (`X-Halo-Signature`) webhook notifications; `halo_controller_*` metrics on `--metrics-listen`.
- **Signed kill switch**: `GET /api/v1/gateway/killswitch` serves an ed25519-signed kill list (dedicated key, gateway bearer token); `halo-proxy` (`--killswitch-*`) and `halo-kong` (`killswitch_url`, `killswitch_token`, `killswitch_pubkey`) poll it and treat killed experiments as not running. Admin `kill`, `unkill` and `GET /api/v1/killswitch`; kills never expire. See ADR-0009.
- `halo-server` console and API: Releases (verified ring pointers, expiry, convergence), Device detail, hash-chained Audit log with `GET /api/v1/audit`, experiment status actions that open PRs, and `GET /api/v1/capabilities`. New [API reference](https://dshakes.github.io/halos/reference/api/).
- Direct Bedrock: `halo-proxy` SigV4-signs `kind: bedrock` upstreams (optional `region`) with the AWS SDK default credential chain; other hosts stay unsigned as before.
- Evidence plane: `halo-proxy` per-request OTLP metrics (`halo.gateway.*`), event-derived `halo.api.request` and `halo.tool.call` rows, derived per-unit metrics for error rate, latency and tool error rate, and `make obs-e2e` (collector, ClickHouse, `halo exp analyze`, Grafana) with synthetic telemetry.
- **Signing continuity** (security review): `halo release promote|refresh|publish` and `halo rollback` take `--state-file` (signer state `$XDG_STATE_HOME/halos/pointers.json`, recording the last pointer written per registry repo and ring; a registry serving an older pointer is refused); `promote`, `refresh` and `rollback` take `--expect-digest sha256:<release digest>`. New `seq` is `max(served + 1, recorded + 1, unix now)`. Each signature is announced on stderr (`Signing ring X → version V (digest D, seq S)`). `ok` lines and JSON output now carry `version`; `publish --output json` carries `manifest`. See the [ADR-0008 addendum](https://dshakes.github.io/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/#addendum-2026-09-30-signer-side-continuity).
- **Evidence trust**: `halo telemetry collector-config` generates two receivers: CLI (4317/4318; drops `halo.gateway.*`, stamps `halo.source=cli`, 4 MiB request cap, optional per-device bearer tokens via `--cli-token-file`) and gateway (4319, `--gateway-endpoint`, bearer token `HALO_OTLP_GATEWAY_TOKEN`, stamps `halo.source=gateway`). `halo-proxy` takes `--telemetry-token-file` and `--telemetry-unit-salt-file`. `halo exp analyze --output json` reports `source`. The controller auto-kills only on gateway-sourced evidence (`killOutcome: not_gateway_evidence` otherwise).
- **Controller and kill-switch wiring**: `halo controller run --killswitch-served`; canonical `--verdicts-file` and `--interval` (`--verdicts`, `--controller-interval` deprecated); webhook timestamp header `X-Halo-Timestamp` with a timestamped HMAC and a 5-minute receiver tolerance (Go and Python verification snippets in the [CLI reference](https://dshakes.github.io/halos/reference/cli/#verifying-the-webhook-signature)); per-channel notification retries; a killed running experiment is held (not evaluated); `GET /api/v1/capabilities` reflects whether a kill key is configured; `halo gateway deck --killswitch-url` emits `killswitch_*` with vault references.
- **Helm**: one writable policy clone for console proposals and controller PRs, made by an init container with a real `git clone` (credentials through `GIT_ASKPASS` or `GIT_SSH_COMMAND`, never the URL); the server image must contain `git`, `gh` and, for ssh, `ssh`. `proxy.telemetry` (token and unit-salt Secrets) and `otel.gatewayToken`; automatic proxy-to-otel NetworkPolicy rules.
- Simple mode: a one-file `halos.yaml` with safety and rollout presets, and intent commands: `halo init`, `upgrade start|publish`, `model switch`, `enable`, `kill`, `status`, `explain` (prints the low-level policy it expands to) and `eject`. `halo init` picks a model each CLI can reach.
- `Rollout` kind with strategies `progressive`, `canary`, `blue-green`, `dark-launch` and `holdout`; gated steps (bake time, samples, guardrails, eval scorecard, approval). `halo rollout list|plan|status|simulate|advance`: the controller rolls back on its own, and advancing only opens a PR.
- `Toggle` kind: ring, group and percent targeting, signed toggle fragments in the release, evaluated by `halod` and the gateway, killable through the signed kill list. `halo toggle list|eval|stale|kill`; the `halo-server` console has a Toggles page (list, drawer, tester, kill/restore, propose change).
- Evals: pass@k and pass^k, LLM-judge rubrics, paired bootstrap confidence intervals, flake detection, `halo eval run --matrix` (harness x model x provider), `halo eval online` (judges `halo-shadow` pairs), `halo.eval.*` metrics, and `halo upgrade check|watch` (watch upstream CLIs and models, open eval-gated upgrade PRs; never merges).
- Providers and routing: Vertex, OpenAI, Azure OpenAI and Gemini-wire upstreams alongside Bedrock; model routes with weights, priority failover and a circuit breaker per target; `halo gateway routes`; per-alias experiment selection.
- `halo validate` checks that each harness a ring or client-axis variant delivers starts on a model whose upstream answers the harness's wire (error naming what to add; warning for orchestrator targets). The new upstream field `serves: [<wire>...]` (kind `orchestrator` only) declares what an orchestrator answers.
- Packaging and release: GoReleaser on `v*.*.*` tags (archives, deb/rpm/apk, checksums, SBOMs, cosign signatures, ghcr.io images, Homebrew/Scoop manifests, winget manifest; see RELEASING.md), `install.sh`/`install.ps1`, GitHub Action, GitLab CI template, `halod` service install, and CI on linux, macOS and Windows.
- UAT suites: `make uat-clis` (real Claude Code, Codex, Gemini and Copilot CLIs), `make uat-k8s` (kind plus Helm) and `make uat-kong` (`halo-kong` in open-source Kong 3.9.3); reports in `test/uat/`. `halo gateway deck --killswitch-allow-insecure-in-cluster`, `--allow-unverified`, `--forward-client-credentials`.
- `halo-proxy` benchmarks (`make bench`) and a load/soak test (`make load`: direct-vs-proxy latency, soak, failover and breaker, long SSE); pooled proxy copy buffers; `go_goroutines` and heap on the admin `/metrics`. Nightly provider smoke workflow (`halo-proxy` against real providers).
- `TestObsClosedLoop` in `make obs-e2e`: synthetic users through `halo-proxy` and the collector into ClickHouse; the controller kills a regressed candidate on gateway evidence (and opens a pause PR), and opens a promotion PR, never merged, for a healthy one.
- Docs: rewritten to match the code. New pages: self-service portal, stack-agnostic traffic plane, agentic operations, production deployment, threat model. ADR-0008 (signed ring pointers and verified artifacts) and ADR-0009 (signed kill switch).

### Fixed
- Guardrails on a zero control mean (the normal state of `halo.api.error_rate`) no longer return inconclusive: a significant worsening now fails, and two all-zero arms pass. Before, a 0% to 30% error-rate regression never tripped its guardrail and a healthy canary never got a promotion proposal.
- Release bundles are reproducible: the manifest `created` annotation is pinned, so republishing the same release gives the same digest instead of an immutable-tag refusal.
- `halo-kong` is secure by default: JWT callers that fail verification get 401, and client credentials (`Authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, `Proxy-Authorization`) are stripped before the upstream (opt out with `allow_unverified` / `forward_client_credentials`). `halo gateway deck` chains Kong's `nginx_main_env` correctly so the kill-switch key reaches the plugin server.
- `halo-proxy` records the served route in `halo.gateway.provider`, `target` and `failover`.

### Security
- Signer-side replay protection: `promote` takes its source from `--from-ring`'s signed pointer (never the `ring-<name>` tag); `rollback --to <version>` refuses a release whose signed manifest does not carry that version; `refresh` refuses an expired pointer (recover with `halo rollback --to <version>`); the signer state file refuses a registry that serves an older or forked pointer. A missing state file is silently empty, so stateless CI must cache it or pass `--expect-digest`.
- Evidence forgery: CLI telemetry can no longer carry `halo.gateway.*` or the `gateway` source; units are `HMAC(salt, verified subject)`; only gateway-sourced rollbacks auto-kill.
- Audit: appends are fsynced; kill, unkill, device enrollment, session and device revocation and experiment-status PRs fail (HTTP 500) when the audit append fails; kill requires a reason (HTTP 422). `halo controller run` audits through the same chain (single writer).
- Kill switch: `--killswitch-key-file` requires `--data-dir`; gateways refuse a cleartext kill URL unless `killSwitch.allowInsecureInCluster` (`halo-kong`: `killswitch_allow_insecure_in_cluster`); a misconfigured `halo-kong` sets `x-halo-killswitch: misconfigured` and logs ERROR once a minute without blocking traffic.
- Bedrock: `halo-proxy` signs only for `.amazonaws.com`, `.amazonaws.com.cn`, `.api.aws` hosts or `signHosts` (otherwise 502 `bad_upstream`) and strips every client `x-amz*` / `x-amzn*` header.
- Client-axis variant guardrails tightened (errors): hooks must be a subset of the ring's, `telemetry.otlpEndpoint` and `logPrompts` equal, `models.allowed` a subset, `permissions.mode` not more permissive, `instructions` and `env` equal.
- Kill list is signed with a key separate from the release key, domain-separated, rejected if older than 10 minutes or more than 1 minute in the future, and accepted only if strictly newer than the current list. A failed fetch keeps the last list; a gateway that never fetched one kills nothing.
- Audit log is hash-chained and verified on read. Removing the newest entries is not detectable from the log alone.
- Ring pointers are signed and carry `org`, `ring`, `seq`, `expiresAt`; `halod` trusts the pointer, not the ring tag.
- CLI installs use hash-pinned artifacts. The legacy shell `installCommand` runs only with `allowShellInstall: true`.
- Guardrails: reserved override keys and env prefixes, literal-secret detection, strict names, and a release-time backstop that parses rendered files for `bypassPermissions` and `danger-full-access`.
- Gateway verifies OIDC JWTs and fails closed on the model allowlist; `x-halo-*` headers are stripped.

### Known limitations
- Real cloud providers (Bedrock, Vertex, Azure OpenAI, OpenAI, Gemini API) are fixture-tested only.
- Signing, SBOM and image publishing have never run on a real tag; this RC is the first run.
- Homebrew and Scoop need the `HOMEBREW_TAP_TOKEN` secret and the tap and bucket repos; a prerelease tag does not push them anyway. The winget manifest is submitted by hand.
- `halod` as a Windows service, MDM-managed devices and the Helm chart on a managed cloud cluster are unverified.
- The policy API is `halos.dev/v1alpha1` and may change until v1.

### Known gaps
- This is the first tagged release: the release workflow's image push, cosign signing and SBOMs run for real for the first time here.
- UNVERIFIED against the real system: Kong Enterprise/Konnect, real AWS Bedrock (signing is tested against a test vector and a fake Bedrock), MDM pushes on real devices, PowerShell and Terraform artifacts, `halod` as root on real hosts and on Windows, the Helm chart on a managed cloud cluster (`make uat-k8s` runs it on kind), the GitHub PR flow against real GitHub, every harness capability against a real CLI.
- The controller and kill switch have not run against a live gateway plus live ClickHouse; `make obs-e2e` uses synthetic telemetry.
- The kill switch does not reach client-axis variants on machines unless `halod` has the opt-in `killSwitch` setting. `halo gateway deck --killswitch-url` does not emit `killswitch_allow_insecure_in_cluster`.
- Stateless CI has no signer state file; cache `pointers.json` or use `--expect-digest`, or the signer replay check does not run.
- Copilot CLI files are rendered but not yet in `halod`'s write allowlist.
- Gemini CLI renders `admin.secureModeEnabled` for `permissions.disableBypass` but does not declare the `permissions` capability.
