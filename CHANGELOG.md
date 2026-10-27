# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/); the policy API is `halos.dev/v1` (stable; see [Compatibility](https://dshakes.github.io/halos/reference/compatibility/)).

## [Unreleased]

### Added

- Console: a **Rollouts** page (step timeline, per-gate status, bake countdown, halt and rollback events, ring-to-release pointers) and a **Cost & budgets** page (spend against limit per scope, window, warn/enforce mode and `alertAt` thresholds); Fleet gains per-ring compliance, a drift count per device and an "in sync" filter; Device lists the drifted settings; Overview links to both new pages. Read-only; no server API changes.

## [0.3.0] - 2026-10-23

### Added
- Vendor admin sync (ADR-0025): `halos.yaml` `vendorAdmin` drives the vendors' cloud admin consoles from the GA ring's profile. `halo admin plan` diffs Gemini Code Assist (logging, release channel) and GitHub Copilot (content exclusion, CLI policy) against the live consoles and exits 2 on drift. `halo admin apply` writes the settings that have a public API, after confirmation, and never loosens a control. `halo admin export` writes Claude server-managed settings, Codex requirements and config, and a Cursor model list, with manual steps for consoles that have no write API. The MCP tool `admin_plan` is read-only.
- Telemetry: the collector normalises Copilot CLI metrics into `halo.*` (`github.copilot.tool.call.count` becomes `halo.tool.calls`; its `gen_ai.client.*` metrics are stamped `halo.harness=copilot-cli` by `service.name`, where they used to be mislabelled as Gemini CLI). Cursor CLI and OpenCode emit no usable OTel and are documented as unmapped, with halo-proxy `gen_ai.*` metrics as their per-request source.
- README, landing page, docs and diagrams cover all six harnesses and the enterprise controls.
- High-availability halo-server on Postgres (ADR-0021): `--database-url-file` runs several replicas behind one load balancer, with advisory-lock migrations and a fenced leader lease for the rollout controller. Gateway budget counters (atomic batch dedupe), the workload-token replay cache, the SCIM directory (deprovisioning holds on every replica), SIEM export cursors (one forwarder per sink under a lease), pending-request uniqueness and verdicts are shared across replicas. Failed-auth limiters stay per replica (up to N× the limit). `halo audit verify --database-url-file`; Helm `server.gatewayTokens` for per-capability gateway tokens.
- Agent identity and delegation (ADR-0024): `POST /api/v1/token/exchange` with `actor_id` mints short-lived delegated agent credentials (RFC 8693 `act` chain, root principal as subject, down-only model scope, depth/cycle/TTL limits, audited). halo-proxy and halo-kong route them as the root, enforce `agents.*` per call and stamp `x-halo-actor`. `agents.remote` is an A2A allowlist with pinned AgentCard digests, checked by `halo agents verify` and `POST /api/v1/agents/egress`.
- **Multi-turn agent shadowing** ([ADR-0014](https://dshakes.github.io/halos/adr/0014-step-level-multi-turn-shadow/), amends ADR-0004). A shadow experiment with `turns: all` mirrors every step of a sampled session, not only the first turn. Each step replays the real prefix (developer prompt, production's actions, real tool results and terminal output) to both arms, and nothing either arm returns is executed. `halo eval online` reads each step without a judge across Anthropic, Bedrock (invoke and Converse), OpenAI Responses and Gemini:
  - tool and argument agreement with the control;
  - **fidelity** to the action production actually took, recovered from the session's next mirrored step and prefix-checked so subagent and compacted conversations are skipped (the control's fidelity is the measured noise floor);
  - invalid tool calls (a tool the request did not offer, or a missing required argument);
  - premature stops;
  - divergence rate and first divergent step;
  - agreement by depth.
- `halo.eval.agent.fidelity` and `halo.eval.agent.invalid_call_rate` are registered metrics, one sample per hashed session and arm, usable as shadow-experiment guardrails in `halo exp analyze` and the controller. Shadow evidence still never promotes.
- `stats.ClusterBootstrapMean` / `PairedClusterBootstrap`.
- **Session-to-eval harvesting** ([ADR-0020](https://dshakes.github.io/halos/adr/0020-harvest-shadow-sessions-into-replay-evals/)). `halo eval harvest` turns shadow steps into redacted step-level regression cases. It selects steps where the candidate diverged, made an invalid call, stopped early or lost on judge score, plus a depth-stratified sample. Cases are written 0600 with hashed sessions; redaction is mandatory and fail-closed. `halo eval steps run` replays them against a model route and grades the next action with session-clustered CIs. MCP: `eval_harvest` (preview without `--allow-writes`).
- **Role-based access control for halo-server** ([ADR-0015](https://dshakes.github.io/halos/adr/0015-rbac-roles-for-halo-server/)).
  - `identity.roles` maps IdP groups to `viewer`, `operator`, `approver`, `auditor` and `admin`. `adminGroups` still grants admin.
  - Every console and API route is enforced from one deny-by-default permission table, and every denial is audited as `authz.deny`.
  - `/api/v1/me` and `/api/v1/capabilities` report the caller's roles and permissions, and the console hides actions accordingly. New `--dev-insecure-roles` for demos.
- **Audit export to SIEM** ([ADR-0016](https://dshakes.github.io/halos/adr/0016-audit-export-to-siem/)).
  - `--audit-config` forwards every audit entry at least once and in order to Splunk HEC, an HMAC-signed HTTPS webhook (Datadog-ready) or RFC 5424 syslog over TLS.
  - Formats are native (hash-verifiable) or OCSF API Activity.
  - Each sink has its own cursor and backoff, and chain checks halt export on tampering. Metrics: `halo_server_audit_forward_*`.
  - The audit log rotates by size or age into segments the hash chain runs across. `GET /api/v1/audit` streams instead of loading the log into memory, and `halo audit verify --data-dir` checks every segment. Helm: `server.audit`.
- **Org hierarchy** ([ADR-0018](https://dshakes.github.io/halos/adr/0018-org-hierarchy-and-delegated-policy/)).
  - The new `Unit` kind covers business units and teams with delegated owners, member selectors and overlays.
  - Enforced security fields can only be tightened, and `halo validate` reports each loosening with its field path.
  - New `halo units codeowners`, and `halo explain --user`, which shows the effective config with the layer that set each field.
  - Unit files ship inside the signed release, and `halod` applies them.
- **Cost budgets and quotas at the gateway** ([ADR-0017](https://dshakes.github.io/halos/adr/0017-gateway-cost-budgets/)).
  - Optional `gateway.pricing` and `gateway.budgets`: user, group, ring or org scope; day, week, month or rolling window; USD and/or tokens; `warn` or `enforce`, with `alertAt`.
  - halo-proxy meters streamed usage and answers 429 with `Retry-After` in each CLI's wire format.
  - halo-server holds the counters (`POST /api/v1/gateway/budget/{check,usage}`, and `GET /api/v1/budgets`, which needs the read role). `budgets.failMode` is `open` or `closed`.
  - New `halo budget status`, and `halo_proxy_budget_*` metrics.
- **SCIM 2.0 provisioning** ([ADR-0022](https://dshakes.github.io/halos/adr/0022-scim-provisioning/)).
  - halo-server serves `/scim/v2` for Okta and Entra ID.
  - Deactivating, deleting or renaming a user immediately revokes their sessions, device tokens and pending enrollments, audited as actor `scim`.
  - `--scim-authoritative` makes directory groups decide rings, toggles and roles.
  - halo-proxy `directory.url` and halo-kong `directory_url` make the directory authoritative at the gateway too; deprovisioned users get default routing.
- **Workload identity federation for CI and cloud agents** ([ADR-0023](https://dshakes.github.io/halos/adr/0023-workload-identity-federation/)).
  - New `workloads` policy section.
  - halo-server `POST /api/v1/token/exchange` (RFC 8693) trades a GitHub Actions, GitLab, Buildkite, CircleCI or cloud OIDC token for an ed25519-signed gateway credential that lasts at most 1h. Exchanges are audited, and a token's `jti` cannot be replayed.
  - halo-proxy reads `identity.workloadPubkeyFile` and halo-kong reads `workload_pubkey` to accept these credentials.
  - New `halo ci token` and `halo ci config`. Workloads are excluded from experiments by default.
  - Examples in `examples/ci-agents`.
- **Agent extension governance.** Profiles can govern `extensions.{marketplaces,blockedMarketplaces,plugins,skills,subagents,outputStyle,statusLine}` and `login`.
  - These render only where the vendor documents a key (Claude Code, Codex, Gemini CLI, Copilot CLI) and warn in the release manifest everywhere else.
  - `mcp.denied` now renders for Gemini (`mcp.excluded`) and Copilot (`deniedMcpServers`). For Copilot, `mcp.managedOnly` with no servers renders `allowedMcpServers: []`.
  - The harness matrix gains an `extensions` capability.
- **OpenTelemetry GenAI semantic conventions** (semconv v1.40.0, Development stability).
  - halo-proxy exports `gen_ai.client.token.usage`, `gen_ai.client.operation.duration` and `gen_ai.server.time_to_first_token` alongside the unchanged `halo.gateway.*` series, on by default.
  - Opt-in `telemetry.genai.traces` sends one content-free `chat {model}` span per call.
  - `halo telemetry collector-config` gains a `traces/gateway` pipeline.

### Security
- Bump golang.org/x/text to v0.41.0 (GO-2026-6629, GO-2026-5970, reachable via the Postgres store); halo-server closes its data-dir files when startup fails part way.
- Workload token exchange matches a rule before recording the subject token's `jti`, so tokens anyone can mint from a shared CI issuer can no longer fill the replay cache and refuse every tenant; `workload.token.denied` is audited at most once per issuer and client IP per minute, the rest counted in `halo_server_workload_denied_audit_suppressed_total`.
- A login right after a session revocation is stamped a whole second past the revocation epoch, so credentials delegated from it are no longer refused as revoked; sessions issued before the revocation stay dead.
- A workload rule removed by a refused policy stays in place as a deny tombstone, so its tokens never fall through to a broader rule below it.
- `halo admin` vendor API clients never follow redirects (net/http would resend `Authorization` over http or to a subdomain); a 3xx is an error.
- Units can no longer set any `GIT_*` env key except commit identity, nor `CC`, `CXX`, `CGO_*`, Go module sources (`GOPROXY`, `GOSUMDB`, `GONOSUMDB`, `GONOSUMCHECK`, `GOINSECURE`, `GOPRIVATE`, `GONOPROXY`), `GOENV`, `GOTOOLCHAIN`, `PIP_*`, `UV_*`, `YARN_*`, `BUNDLE_*`, `GEM_*`, `MAVEN_OPTS`, `GRADLE_OPTS`, `JAVA_OPTS`, `CLASSPATH`, `GCONV_PATH`, `LUA_INIT*`, `PHPRC`, `PHP_INI_SCAN_DIR`, `SUDO_ASKPASS`, `BROWSER`, `MAKEFLAGS`, `MAKEFILES` or `DOCKER_HOST`.
- Gateway tokens must look random: hex or base64/base64url only, at least 32 characters and 128 bits, no long repeated or consecutive runs; passphrases are refused at startup (use `openssl rand -hex 32`).
- Cached OIDC JWKS key sets are refetched after 24 hours, so a withdrawn key stops verifying; requests from a blocked IP never trigger a fetch, and a stale set keeps serving through an issuer outage.
- A full gateway directory cache evicts active entries only, so fail open can no longer re-admit a deactivated user after the cache fills.
- HA (ADR-0021, amended): cluster locks and claims are owned and expire on the database clock; a SCIM mutation that can't take the lock answers 503, and a userName is provisioned once across replicas.
- HA: the leader fence check is race-free (`FOR SHARE`, `clock_timestamp()`); the controller records a fenced intent before every kill, PR and notification; a new leader finds an existing PR by its `halos-intent` marker, and webhook notifications carry `X-Halo-Event-Id`.
- HA: budget buckets are pruned by age on the database clock, never by a replica's policy; session revocations and enrollment voids are padded for clock skew; an enrollment racing a deprovisioning is undone.
- HA: catch-ups are coalesced and the audit tail is paged; new `--database-max-conns`; a non-loopback database URL must use `sslmode=verify-full` unless `--database-insecure-tls`; migrations declare `min-binary-schema` so a binary rollback works across additive migrations; `halo-server import` is transactional.
- Helm: the chart refuses HA with NetworkPolicy but no `databaseEgress.to`; new optional `server.database.migrateJob` hook, so the serving role needs only DML.
- Vendor admin sync (ADR-0025, amended): `halo admin apply` re-reads every console before writing and aborts with nothing written if it changed since the confirmed plan; Copilot writes are also conditional on GitHub's ETag when one is returned.
- Copilot content exclusion keeps object rules (`{"if-any-match": [...]}`) under `"*"`; a path string the policy lacks is a loosening that apply refuses.
- The Claude console export no longer contains machine config (`apiKeyHelper`, hooks, `env.ANTHROPIC_*`, ring stamps); each removed key is warned, and the Claude and Codex steps reconcile rather than paste.
- MCP `admin_plan` renders from policy only unless `halo mcp serve --admin-read`, which reads `HALO_MCP_ADMIN_<VENDOR>_TOKEN`.
- `vendorAdmin` org, project and location are strictly validated; plan output and STEPS.md strip control characters; API base URLs must be https (http only to loopback).
- `halo admin plan --offline` exits 3; manual vendors report `not checked (manual)`; the apply record has a result per change; Gemini rebinding and an unspecified-to-experimental channel change count as loosenings, and a conflicting Gemini binding blocks apply.
- Gateway directory: fails open only on transport errors or 5xx. Any other non-200 refuses the caller (403), a cached inactive entry stays refused through an outage, and halo-server answers an oversized subject as inactive instead of 400.
- halo-server refuses to start with a gateway token (shared or per capability) under 32 characters or 128 bits of estimated entropy; generate one with `openssl rand -hex 32`.
- Workload exchange: a known issuer's non-tenant `tenantClaim` (e.g. GitHub `ref`) is ignored at runtime as well as refused by validation.
- Workload exchange: only malformed, unknown-issuer or bad-signature tokens count toward the per-IP limit. A signed token passes even from a blocked IP, verified from cached keys only, so a blocked IP never makes halo-server fetch an issuer's JWKS. Delegation uses its own budget (`agentFails`).
- A refused policy still applies workload rule removals (`halo_server_policy_tightened_total`), on the API and on the HA controller's path.
- `halo_server_workload_rules_skipped_total` is replaced by the gauge `halo_server_workload_rules_skipped`, set per policy load.
- Public endpoints (readyz, login, token exchange, agent egress) no longer return policy load errors; they are logged.
- Policy snapshots with null entries are refused; halo-kong recovers panics in the Access phase and answers 500.
- Budget estimates charge the server-state input floor for remote files, `item_reference`, server tools and `background` requests, and at least the thinking budget (else the output cap) when reasoning is enabled.
- Per-user budgets are keyed by the canonical user id shared with halo-server; lookalike characters such as the Kelvin sign are no longer folded into ASCII.
- Units can no longer set `OTEL_*`, shell hooks (`BASH_FUNC_*`, `PROMPT_COMMAND`, `PS4`, `ZDOTDIR`, `HOME`, `XDG_CONFIG_HOME`), pagers or editors, git wrappers (`GIT_SSH`, `GIT_ASKPASS`, `SSH_ASKPASS*`, `GIT_PROXY_COMMAND`, `GIT_TEMPLATE_DIR`, `GIT_SSL_*`), compiler and runtime hooks (`GOFLAGS`, `RUSTC*`, `CARGO_*`, `PERL5LIB`, `RUBYLIB`, `JDK_JAVA_OPTIONS`, `DOTNET_STARTUP_HOOKS`, `ELECTRON_RUN_AS_NODE`) or harness config dirs (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GEMINI_*`).
- Delegated agents' `deniedTools` can no longer be bypassed by deep JSON nesting, Gemini `function_declarations`, Bedrock Converse tools, or hosted tools (web search, code execution, MCP servers). When `deniedTools` is set, gateways refuse agent calls whose tools they cannot read. A hosted tool counts by its type (prefix match), and an MCP server as `mcp:<server>`.
- Gateways and the egress decision re-check every agent in a delegation chain (groups, models) and enforce the root's profile and unit `maxDepth`. Egress refuses agents whose human root's sessions were revoked, and never returns an allow without its audit record.
- Agent delegation and egress have their own failed-auth rate limit. Policy refusals no longer count, and neither do expired agent credentials at egress. Refused parents are audited as `agent.token.denied`, and `halo_server_audit_append_errors_total` counts failed audit appends.
- Actor labels are limited to `[A-Za-z0-9._:-]`, and an oversized `expires_in` is a 400. AgentCard digests reject invalid UTF-8 and lone surrogates, and card fields are read by exact key. Remote agents at NAT64, 6to4, Teredo or IPv4-compatible addresses are refused, and `halo agents verify` escapes control characters.
- SCIM deprovisioning revokes sessions whatever the case of the user id, and gateway posture matches device owners case-insensitively.
- Gateways with a SCIM directory refuse (403) a verified caller who is deactivated or not provisioned, instead of routing them anonymously. Workload credentials skip the directory, and human identities cannot start with `workload:`.
- SCIM memberships are indexed: lookups and member changes are linear.
- New optional `--gateway-{killswitch,posture,budget,directory}-token-file` flags give each gateway capability its own token.
- Workload rules must pin an exact tenant claim. Issuers Halos doesn't know must set `issuers[].tenantClaim`, so AWS, AKS and self-managed GitLab issuers fail `halo validate` until they do.
- A unit that adds hooks, env keys, MCP servers or extensions is loosening policy, unless the org delegates it (`delegation.allowHooks`, `delegation.envKeys`, `selfService.catalog`). Provider, proxy and runtime-injection env keys are refused even when delegated. Top-level units select groups only, and their files belong to the root owners.
- Aborted or compressed metered responses are charged (new `estimated` outcome, replacing `no_usage`), so a successful call is never free. GenAI telemetry and budgets share one usage parser.
- During a directory outage gateways keep the verified caller (no groups) instead of routing them anonymously; `directory.failMode: closed` returns 503 instead. halo-server's failed-auth lockout is per endpoint class, so public endpoints cannot lock out the gateways.
- halo-server and the gateways refuse a policy with security validation errors (unpinned workload rules, undelegated unit loosenings) at load time and keep the last good one (`halo_{server,proxy}_policy_refused_total`).
- Interrupted streams are estimated from generated text, capped at `max_tokens` or `budgets.maxEstimatedOutputTokens`; Responses calls that reuse server-side state are charged at least `budgets.serverStateInputTokens` when usage is missing.
- User ids compare by one canonical form everywhere, including access-request self-approval. More env keys can never be set by a unit (`PATH`, `BASH_ENV`, `CLAUDE_CODE_*`, `AWS_*`, `GIT_SSH_COMMAND`, CA-bundle overrides).

### Changed
- `halo eval online` intervals, the judge-score delta included, now resample sessions instead of pairs: steps of one session are correlated, and per-pair intervals were falsely narrow on multi-turn data. With one pair per session the result is identical to before.
- `halo.eval.judge.score` analysis samples use unit = hashed session instead of pair id. Pairs from one session are correlated, so per-pair units made `halo exp analyze` intervals too narrow.
- The judge now sees the head and the **tail** of long requests. It previously saw only the first 24 KiB, which on long agent sessions cut the latest tool results the graded step answers.

## [0.2.1] - 2026-10-11

### Fixed
- halo-server's JSON request bodies (experiment status, kill switch, portal enrollment, access requests, toggles) now reject any bytes after the JSON value. The decoder stopped at the end of the first value, so a body larger than the size cap was accepted whenever its JSON ended before the cap. Found by the nightly `FuzzAPIJSONDecoders` run; the crasher is kept as a regression seed.

## [0.2.0] - 2026-10-11

### Added
- **Your own API gateway** (`Gateway.engine: external`, simple mode `gatewayEngine: external`, `halo onboard local --gateway-engine external`, `halo onboard company --gateway-kind external`): for a company whose model traffic already goes through its own gateway (Kong, an auth gateway, an orchestrator, Bedrock). Halos runs no data plane there, so Claude Code, Codex and Gemini CLI are rendered with each alias's provider model id instead of the alias, routes need no Halos upstream (simple mode generates none, so a provider's Halos-side requirements such as a Vertex project do not apply), Claude Code's built-in fallback tiers are pinned to the default model when `models.enforce` is set (nothing behind an external gateway rejects an unlisted model), and validation warns that the gateway-side posture and version gates, kill switch and model-axis experiment metrics do not apply. `halo onboard company` now also records `kong` in the generated policy.

### Changed
- The nightly soak's p99 gate is armed: `test/load/baseline.json` is the result of a green 60-minute run on `ubuntu-latest` (run 37253557695: 0 errors at ~1245 rps, p99 53.4 ms, all SSE streams intact, no heap or goroutine growth).

### Fixed
- Claude Code: a profile may set `ANTHROPIC_CUSTOM_HEADERS` (the one `ANTHROPIC_*` variable the reserved-env guardrail now allows), and those headers (e.g. a tenant or routing header a company gateway requires) are no longer overwritten by Halos's `x-halo-ring` / `x-halo-release` headers: they are kept, with Halos's appended, and CR or `x-halo-*` lines in them are rejected.
- The `.halos-backup` of a replaced managed file keeps the original's permissions; it was root-only, so a manual restore left Claude Code unable to read the file.
- `halo onboard local` stops with explicit next steps (compare in a scratch root, deliver through MDM, or point at your own gateway) when a managed file on the machine was not written by Halos.
- `halo onboard install --apply` replaced a managed config file it had not written (for example a Claude Code `managed-settings.json` an MDM had pushed), keeping only a `.halos-backup` and previewing it as a plain `update`. Such a file is now planned as `foreign` and `--apply` refuses and writes nothing unless `--replace-existing` is set; the MCP `local_install` tool never replaces one. Halos records the hash of each file it writes at `<file>.halos-sha256` to tell its own files from rewritten ones, on every install (an earlier `.halos-backup` does not count as ownership), and a second replacement keeps the earlier backup and writes a timestamped one. A file with no hash is never adopted silently, even one that matches the render (an MDM push can match): files installed by `halo` 0.1.1 or earlier report as foreign on the next change; confirm they are yours and re-run with `--replace-existing`, which also records the hash of matching files.
- The nightly soak's load tool minted a one-hour JWT for a 60-minute soak, so the first scheduled run (3 Oct) ended in 401s at t+58 m with every other gate green; the token now outlives the run.
- CI's released-`halo` jobs validate `examples/acme-corp` again; the `test/ci/policy-v1alpha1` fixture is gone.

## [0.1.1] - 2026-10-03

### Fixed
- Homebrew and Scoop publishing. GoReleaser accepts a tap or bucket token only as `{{ .Env.NAME }}`; the `index .Env` form passed `goreleaser check` and every prerelease (which skip the tap and bucket) and failed on the first final tag. `v0.1.0`'s release job stopped at that step: its GitHub release assets, signed checksums and `0.1.0` images were published, but it has no Homebrew formula, no Scoop manifest and no provenance attestation. `v0.1.1` is otherwise identical and is the release the installers and docs point at.

## [0.1.0] - 2026-10-02

The first general-availability release. Everything in this section and in the two release candidates ships here. Verified in CI on every change, and run end to end before this tag: Linux, macOS and Windows builds; the installers, `halod` as a launchd daemon and as a Windows SYSTEM scheduled task; the GitHub Action, the GitLab template and the dev container Feature; Helm on a kind cluster with pod-kill, rolling-upgrade and eviction fault injection under load; `halo-kong` in open-source Kong 3.9.3; the real pinned Claude Code, Codex, Gemini CLI and Copilot CLI driven headlessly through `halo-proxy`; `halo-proxy` against the real Anthropic and OpenAI APIs nightly; a headless browser click-through of every console page.

**GA scope.** Linux and macOS hosts, dev containers, the four CLIs' managed configuration, `halo-proxy` with Anthropic and OpenAI upstreams, and `halo-kong` on open-source Kong are GA. Windows hosts, MDM-delivered laptops (Jamf, Kandji, Intune), Codespaces and Coder, the Codex and Copilot CLI onboarding entry points, and the Bedrock, Vertex and Azure OpenAI upstreams are **supported but not yet field-verified**: each is built, unit- and fixture-tested, and exercised in CI as far as a hosted runner can, but has not run against a real tenant, device fleet or cloud account. See *Known gaps*.

### Added
- **Device posture gate** (`Ring.posture: off|warn|enforce`, default `warn`): `halo-proxy` and `halo-kong` ask `halo-server` (`GET /api/v1/gateway/posture`, gateway token, rate-limited) whether the calling device's `halod` reported it stale, drifted or off its ring's release, and refuse model calls in `enforce`. Verdicts are cached (1 m) and the last verdict serves for a 15 m grace window when `halo-server` is unreachable, after which requests pass and are counted `outcome="unknown"`. `halo_proxy_gate_total` metrics. [ADR-0011](https://dshakes.github.io/halos/adr/0011-gateway-enforced-posture-and-version/).
- **CLI version gate** (`Ring.versionGate: off|warn|enforce`, default `warn`): the gateway reads the CLI version from the `User-Agent` and compares it with the ring's pinned versions (ring profile and the variant profiles of running client-axis experiments). This covers Codex, Gemini CLI and Copilot CLI, which do not enforce a pin themselves. User-Agent formats come from recorded headers and vendor source, cited in ADR-0011.
- **Immutable managed files**: `halod.yaml` `immutable: true` sets `chflags schg` (macOS) / `chattr +i` (Linux) after each atomic write and clears it before a rewrite; a missing tool or permission is logged once and skipped.
- **Policy API v1**: `apiVersion: halos.dev/v1` is the stable document version; every kind and field is frozen as it was in v1alpha1. `halo migrate --policy-dir DIR [--dry-run]` rewrites v1alpha1 documents in place, keeping comments and formatting (idempotent). `halo init` and the intent commands write v1; `schemas/*.schema.json` describe v1 and `schemas/v1alpha1/` keeps the old ones. [Compatibility](https://dshakes.github.io/halos/reference/compatibility/) states the v1 guarantees, the deprecation policy and the supported version skew across `halo`, `halod`, `halo-server` and `halo-proxy`. [ADR-0012](https://dshakes.github.io/halos/adr/0012-policy-api-v1/).
- **Agentic onboarding** from whichever AI CLI you have. `halo quickstart` brings up the demo and prints a tour. `halo doctor` reports installed CLIs and versions, tools, which credential variables are set (never their values), policy validity and gateway reachability, with a fix per problem. `halo onboard local|install|proxy|verify` takes a machine from nothing to a validated `halos.yaml`, a dry-run (then `--apply`) install of the managed config, an optional loopback `halo-proxy`, and a real `claude -p` / `codex exec` / `gemini -p` / `copilot -p` round trip. `halo onboard company` interviews an admin (IdP, gateway, provider, delivery) and generates the policy repo, Helm values, OIDC client, enrollment config, CI workflow and smoke eval, then stops before anything outward. All `--output json`, idempotent, dry-run by default. MCP tools of the same names plus an `onboard` prompt; entry points for Claude Code (`/halos:halo-onboard`), Codex (`$halos-onboard`), Gemini CLI (extension) and Copilot CLI (`.github/mcp.json`). New [Start here](https://dshakes.github.io/halos/getting-started/start-here/) page.
- **Helm HA**: `halo-proxy` runs with probes, a PodDisruptionBudget, topology spread, an optional HPA, a hardened `securityContext` and an optional NetworkPolicy; `values.schema.json` pins `halo-server` and `halo-shadow` to one replica because each is a single writer over local JSONL files (documented in the chart). `make uat-k8s` now kills a proxy pod mid-traffic, performs a rolling upgrade and tests the PDB under 200 rps with zero client-visible errors required.
- **Operations docs**: [Operations](https://dshakes.github.io/halos/guides/operations/) (HA model, SLOs, Prometheus alert rules on the real metric names, backup and restore of every `--data-dir` file and key, runbook for killing a change, rolling back a ring, rotating release and kill-switch keys, a lost signer state file, gateway or server down) and [Support policy](https://dshakes.github.io/halos/reference/support-policy/) (SemVer scope per surface, supported versions, upgrade order `halo-server → halo-shadow → halo-proxy/kong → halod → halo`, EOL).
- **Nightly soak** (`soak.yml`): 60 minutes of `test/load` against a real `halo-proxy`, failing on errors, cut SSE streams, goroutine or heap growth, and p99 regression against a committed baseline (records only until `test/load/baseline.json` is committed).
- **Fuzzing**: 16 native Go fuzz targets over every parser of untrusted input (policy YAML, JWTs, ring pointers, bundle tar and manifest, kill lists, SSE, identity headers, webhook signatures, server JSON, audit chain, shadow replay, `halod` paths and `halod.yaml`), run briefly on every PR and for 10 minutes per target nightly. An OpenSSF Scorecard workflow and a `SECURITY.md` with the disclosure process and supported versions.
- **Security model, bound to tests**: every claim in the [security model](https://dshakes.github.io/halos/concepts/security-model/) names the test that proves it, and `TestSecurityModelClaimsBound` fails if a named test disappears.
- **CI verifies every delivery path on every PR**: `install.ps1`, `enroll.ps1` and `halod service install` on Windows; `install.sh`, `enroll.sh` and launchd on macOS; the composite Action on three OSes; the GitLab template under `gitlab-ci-local`; the dev container and the Feature under the devcontainer CLI; Playwright clicks through every console page and button (`make demo-e2e`).
- **One-command releases**: `scripts/release.sh [--dry-run] [--yes] <tag>` runs the preflight (main, clean, HEAD == origin/main, SemVer, CHANGELOG section, green CI, `go test`, `goreleaser check`) and pushes the tag; `release.yml` gates, builds, attests provenance and then *verifies* the published artifacts (cosign bundle, checksums, attestation, image signatures, `install.sh`, tap and bucket); `release-drift.yml` fails daily if the tap or bucket drift from the latest release. [RELEASING.md](https://github.com/dshakes/halos/blob/main/RELEASING.md).
- **Demo kiosk**: `make demo` serves a pinned `halod` with its checksum and configures every launcher, so "Set up my laptop" and the dev container launcher work end to end locally. Unconfigured launchers never show a raw server error: `GET /api/v1/capabilities` reports each launcher's availability, the kiosk shows only usable ones, and admins see what to set. Harness cards list only the model aliases that harness can use (the same wire check as `halo validate`).
- `halo eval online` reports per-arm error rate, mean latency and output tokens over every shadow pair, errored ones included, and exports `halo.eval.shadow.*` (ADR-0004: regressions in refusal rate, latency and cost are now caught, not only judge scores).
- Guardrails `guardSandboxEgress` (a ring profile with `permissions.sandboxRequired` must set a non-empty `egress.allowedDomains`) and `guardGARing` (a default ring that ships hooks must make them managed-only); `guardNoBypass` now also scans profile `env` and harness overrides. `ExtraGuardrails` lets an org add checks that can only add issues. `halo release publish` refuses a ring pinned to a different `release:` digest. Every ADR 0001–0010 carries an *Implementation status* table mapping each commitment to code and a test, with dated addenda where a decision was superseded.
- `halo plan` no longer requires `--against`: a first release has no baseline.

### Changed
- `halo init` and the intent commands write `halos.dev/v1`.
- Release candidates are published as GitHub prereleases and never move the `:latest` image tag or the Homebrew and Scoop manifests; only a final `vX.Y.Z` tag does.
- The Scoop manifest is `halo.json`; the Homebrew formula lives in the tap's `Formula/` directory.

### Deprecated
- `apiVersion: halos.dev/v1alpha1` still loads with identical semantics and a validation warning per file. It is removed only in `halos.dev/v2`.

### Fixed
- `halod` on Windows: `state.json` is written with the managed `var` directory's DACL instead of an owner-only one, so the SYSTEM scheduled task no longer rejects a state file first written by an admin during enrollment.
- GitLab template: `.halos` no longer sets a job-level `HALOS_VERSION` default that shadowed the pipeline-level pin.
- `halo exp analyze` could fail with `json: unsupported value: -Inf` when a guardrail's two arms had no variance yet; the sequential guardrail now reports the exact estimate instead of an unbounded interval.
- `halo-proxy` no longer logs a spurious export error when a telemetry flush is cut short by shutdown.
- `test/load` paces requests with `-rps`; an unthrottled run exhausted the kind ingress's ephemeral ports and reported harness 502s as chart failures.

### Security
Each finding below has a regression test; none changed an invariant.
- Policy: `bypassPermissions` / `danger-full-access` in profile `env` or harness overrides is now a `halo validate` error, not only a release-build backstop.
- Bundles: `halo release build` refuses any rendered file carrying a literal credential (Anthropic, GitHub, AWS keys, private keys), without echoing it.
- `halod` archive extraction accepts only regular files and no entry larger than the tar itself (PAX/GNU sparse bombs and symlink or hardlink entries are refused); managed files owned by another user, group- or world-writable, or with a loose DACL are replaced rather than adopted; Windows paths are normalised and DOS device names refused.
- Gateway: JSON bodies are re-encoded with duplicate and case-variant `"model"` keys dropped (an alias could otherwise be smuggled past the allowlist); request trailers are not forwarded; upstream event-stream chunks are compacted and event names with line breaks refused; `halo-kong` handles Kong's header-list cap.
- `halo-shadow` and the kill-switch fetch never follow redirects.
- `halo-server`: login and enrollment are rate-limited; CSRF checks no longer rely on `Origin` alone; promotion branch names are validated; invalid UTF-8 no longer breaks the audit chain.
- Docker base images are pinned by digest.

### Known gaps
- Not field-verified (built and tested, never run against the real thing): Jamf, Kandji and Intune tenants; real Codespaces and Coder; Codex and Copilot CLI onboarding entry points (their formats follow the vendors' docs); Bedrock, Vertex, Azure OpenAI and Kong Enterprise/Konnect; the Helm chart on a managed cloud cluster (it runs on kind); kill-switch key rotation on a live cluster (the runbook is derived from code).
- The nightly fuzz, Scorecard and soak workflows ship here; at tag time none had had a scheduled run (the fuzz and soak workflows first ran on 3 Oct, see Unreleased). The soak's p99 gate arms once a reviewed `test/load/baseline.json` is committed.
- `halod` on Windows is a SYSTEM scheduled task, not an SCM service (ADR-0006 addendum). The immutable-file flag has no Windows equivalent.
- The posture gate has no hardware attestation and the version gate trusts a client-controlled `User-Agent`; both are honest-client controls, documented in ADR-0011.
- The support window in the support policy is a stated commitment, not something the code enforces.
- The CI jobs that install a released `halo` validate a v1alpha1 copy of the example policy (`test/ci/policy-v1alpha1`) because the previous release predates `halos.dev/v1`; they return to `examples/acme-corp` with the first release after this one.

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
- **Controller and kill-switch wiring**: `halo controller run --killswitch-served`; canonical `--verdicts-file` and `--interval` (`--verdicts`, `--controller-interval` deprecated); webhook timestamp header `X-Halo-Timestamp` with a timestamped HMAC and a 5-minute receiver tolerance (Go and Python verification snippets in the [CLI reference](https://dshakes.github.io/halos/reference/binaries/#verifying-the-webhook-signature)); per-channel notification retries; a killed running experiment is held (not evaluated); `GET /api/v1/capabilities` reflects whether a kill key is configured; `halo gateway deck --killswitch-url` emits `killswitch_*` with vault references.
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
