---
title: Components
description: Each Halos binary, the MCP server and the Claude Code plugin, covering inputs, outputs, internal packages, state, trust boundary, config, ports and the tests that cover them.
---

Halos ships six binaries from `cmd/`. Two more surfaces run inside one of them or next to it: the MCP server and the Claude Code plugin. Every claim on this page links to the code it comes from. Defaults are the values in the flag definitions.

| Component | Plane | Runs where | Listens on (default) |
| --- | --- | --- | --- |
| [`halo`](#halo) | Policy / release | Laptop, CI | None (the MCP server uses stdio) |
| [`halod`](#halod) | Client | Every managed machine, as root | None (outbound only) |
| [`halo-proxy`](#halo-proxy) | Traffic | Cluster or VM | `:8088` traffic, `127.0.0.1:9090` admin |
| [`halo-kong`](#halo-kong) | Traffic | Inside Kong | Kong's own listeners |
| [`halo-shadow`](#halo-shadow) | Evidence | Cluster | `127.0.0.1:8090` |
| [`halo-server`](#halo-server) | Control / evidence | Cluster | `127.0.0.1:8080` |
| [MCP server](#mcp-server) | Agents | Agent host | stdio |
| [Claude Code plugin](#claude-code-plugin) | Agents | Claude Code | n/a |

## halo

**Purpose:** the operator CLI. It validates policy, builds and publishes signed releases, moves ring pointers, drives experiments, rollouts and toggles, runs evals, and serves MCP.

- **Inputs:**
  - a policy repo directory, loaded by [`policy.Load`](https://github.com/dshakes/halos/blob/main/internal/policy/load.go#L111-L177)
  - a signing key: `--key` (a PEM file) or `--key-uri` (`file://`, `awskms://` or `exec://`), ed25519 or ECDSA P-256 ([`cmd/halo/cmd_release.go:111-147`](https://github.com/dshakes/halos/blob/main/cmd/halo/cmd_release.go#L111-L147), [`internal/signer/signer.go:1-16`](https://github.com/dshakes/halos/blob/main/internal/signer/signer.go#L1-L16))
  - an OCI registry
  - ClickHouse, for `exp analyze` and `mcp serve --clickhouse`
- **Outputs:**
  - release tarballs (`release build`)
  - OCI artifacts and signed pointers (`release publish`, [`cmd/halo/cmd_release.go:214-284`](https://github.com/dshakes/halos/blob/main/cmd/halo/cmd_release.go#L214-L284))
  - git branches and pull requests
  - JSON (`--output json`)
- **Key internal packages:**
  - `internal/policy`: types, strict loader, validation and the default guardrails.
  - `internal/release`: renders every harness for every OS into a content-addressed tar.
  - `internal/bundle`: OCI push and pull, ed25519, ECDSA P-256 and cosign signing, signed ring pointers.
  - `internal/signer`: opens the signing key by URI (file, AWS KMS, or an external signer such as an HSM).
  - `internal/harness/*`: adapters for Claude Code, Codex, Gemini CLI, Copilot CLI, Cursor CLI and OpenCode.
  - `internal/promote`, `internal/rollout`, `internal/controller`: verdicts, rollout state and PRs.
  - `internal/mcpserver`: `halo mcp serve`.
  - `internal/eval`, `internal/stats`: replay evals, scorecards and statistics.
- **State and storage:** the signer's pointer state file, `$XDG_STATE_HOME/halos/pointers.json` (`~/.local/state/halos/pointers.json` when unset) ([`internal/bundle/state.go:36-48`](https://github.com/dshakes/halos/blob/main/internal/bundle/state.go#L36-L48)). It refuses replayed or forked pointers on later writes.
- **Trust boundary:**
  - `halo` holds the release private key, or the right to use it in KMS or an external signer.
  - Publishing refuses a primary signer that is not ed25519 or ECDSA P-256, the two algorithms halod verifies, so cosign can only co-sign ([`internal/bundle/pointer.go:86-101`](https://github.com/dshakes/halos/blob/main/internal/bundle/pointer.go#L86-L101)).
  - A policy with validation errors is refused before any build ([`cmd/halo/root.go:231-253`](https://github.com/dshakes/halos/blob/main/cmd/halo/root.go#L231-L253)).
- **Config:** flags only. See the [CLI reference](/halos/reference/cli/).
- **Ports:** none. `halo mcp serve` speaks MCP over stdio ([`cmd/halo/mcp.go:39`](https://github.com/dshakes/halos/blob/main/cmd/halo/mcp.go#L39)).
- **Tests:**
  - unit tests: `cmd/halo/*_test.go`, `internal/{policy,release,bundle,harness/...}/*_test.go`
  - e2e: `TestPolicyReleaseDelivery`, `TestSimpleMode`, `TestRollout`, `TestRolloutSimpleModeCompletion`, `TestToggles` and `TestObsEvidencePlane` in [`test/e2e`](https://github.com/dshakes/halos/tree/main/test/e2e)
  - UAT: `TestK8sUAT`

## halod

**Purpose:** the fleet agent. It runs as root on each machine, pulls the ring's signed release, verifies it, and applies it atomically to an allowlisted set of paths.

- **Inputs:**
  - `halod.yaml` ([`cmd/halod/config.go:17-62`](https://github.com/dshakes/halos/blob/main/cmd/halod/config.go#L17-L62))
  - the OCI registry, read-only
  - the ring endpoint `GET /api/v1/fleet/ring`
  - the signed kill list `GET /api/v1/fleet/killswitch`
- **Outputs:**
  - harness config files under each adapter's managed directories
  - verified CLI installs
  - one JSON status line per cycle on stdout, also POSTed to `reportURL` ([`cmd/halod/agent.go:685-717`](https://github.com/dshakes/halos/blob/main/cmd/halod/agent.go#L685-L717))
- **Key internal packages:**
  - `internal/bundle`: `PullRing` verifies the pointer and the release.
  - `internal/release`: manifest and blobs.
  - `internal/policy`: `ResolveVariant` for client-axis experiments.
  - `internal/gateway`: `KillSwitch`, the same verifier the gateways use.
  - `internal/toggle`: client toggle evaluation.
  - `internal/harness/all`: managed paths come from the adapters.
  - `internal/fsutil`: atomic writes.
- **State and storage:**
  - Fixed root-owned layout per OS ([`cmd/halod/paths.go:25-38`](https://github.com/dshakes/halos/blob/main/cmd/halod/paths.go#L25-L38)). On Linux that is `/etc/halos/halod.yaml`, `/var/lib/halos/state.json`, `/usr/local/lib/halos/{bin,npm}` and shims in `/usr/local/bin`.
  - `state.json` holds the applied digest, the files it owns, the last pointer `seq` and digest per ring and channel (anti-rollback), installed artifacts, and the last accepted kill list ([`cmd/halod/agent.go:81-98`](https://github.com/dshakes/halos/blob/main/cmd/halod/agent.go#L81-L98)).
- **Trust boundary:**
  - Trusts only releases signed by a configured ed25519 or ECDSA P-256 key that has not been revoked ([`cmd/halod/keys.go:25-50`](https://github.com/dshakes/halos/blob/main/cmd/halod/keys.go#L25-L50)).
  - Refuses to start if its own binary, its config or a parent directory could be modified by a non-root user ([`cmd/halod/main.go:110-122`](https://github.com/dshakes/halos/blob/main/cmd/halod/main.go#L110-L122)).
  - Writes only inside the per-harness allowlist, with mode at most `0644`, under root-owned and symlink-safe parent directories ([`cmd/halod/agent.go:562-572`](https://github.com/dshakes/halos/blob/main/cmd/halod/agent.go#L562-L572)).
  - Authenticates to `halo-server` with a device token ([`cmd/halod/agent.go:720-724`](https://github.com/dshakes/halos/blob/main/cmd/halod/agent.go#L720-L724)).
- **Config:**
  - `registry`, `org`, `ring` or `ringEndpoint`
  - `pubkey` / `pubkeys` / `revokedKeys`
  - `interval` (default `15m`, [`cmd/halod/config.go:233-242`](https://github.com/dshakes/halos/blob/main/cmd/halod/config.go#L233-L242))
  - `reportURL`, `deviceTokenFile`, `subject`, `maxBundleBytes`, `allowShellInstall` (default false)
  - `killSwitch.{url,pubkey,interval}` (interval default `60s`, [`cmd/halod/config.go:70-71`](https://github.com/dshakes/halos/blob/main/cmd/halod/config.go#L70-L71))
  - Flags: `--config`, `--state`, `--install` (default true), `--log-level` ([`cmd/halod/main.go:77-82`](https://github.com/dshakes/halos/blob/main/cmd/halod/main.go#L77-L82)).
- **Ports:** none. halod makes outbound calls only.
- **Tests:**
  - unit tests: `cmd/halod/*_test.go` (among them `keys_ecdsa_test.go`, `hardening_test.go` and `fuzz_test.go`), plus `trust_windows_test.go` on Windows
  - e2e: `TestPolicyReleaseDelivery`, `TestClientAxisExperiment`, `TestPortalEnrollment`, `TestToggles`
  - UAT: `TestCLIs` (installs through the Dev Container Feature; [`test/uat/clis_env_test.go`](https://github.com/dshakes/halos/blob/main/test/uat/clis_env_test.go))

## halo-proxy

**Purpose:** the standalone gateway. It verifies the caller, decides ring, toggle and experiment per model alias, and routes to the provider with failover. It can also mirror requests to `halo-shadow` and export `halo.gateway.*` metrics. Every step is shown on the [low-level design](/halos/architecture/low-level-design/#request-path-inside-halo-proxy) page.

- **Inputs:**
  - model API calls (Anthropic Messages, Bedrock invoke, OpenAI Responses, Gemini)
  - the compiled policy snapshot, hot-reloaded ([`internal/gateway/snapshot.go:35-71`](https://github.com/dshakes/halos/blob/main/internal/gateway/snapshot.go#L35-L71))
  - the signed kill list
  - the issuer's JWKS
  - optionally, halo-server's gateway endpoints for device posture, the SCIM directory, budget checks and DLP events, each enabled by its own `--*-url` flag ([`cmd/halo-proxy/config.go:192-200`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/config.go#L192-L200))
- **Outputs:**
  - upstream requests carrying the gateway's own credential
  - streamed responses
  - `x-halo-ring|release|experiment|variant` headers set on the upstream request
  - shadow jobs
  - OTLP metrics to the collector's gateway receiver
  - Prometheus text on `/metrics`
- **Key internal packages:**
  - `internal/identity`: JWT via OIDC, trusted proxy header, or none.
  - `internal/gateway`: `PrepareVerified`, `Decide`, `RouteOrder`, `Breaker`, `KillSwitch`, `BuildOutbound`.
  - `internal/gateway/upstreamauth`: SigV4, Vertex tokens and API keys.
  - `internal/shadow`: the mirror queue.
  - `internal/telemetry/gwmetrics`: the OTLP exporter.
  - `internal/bundle`: kill-list key parsing.
- **State and storage:** none on disk. In memory it keeps the policy snapshot, the last accepted kill list, breaker state and per-target token caches.
- **Trust boundary:**
  - Cohort comes only from the verified subject.
  - Every client `x-halo-*` header and the identity and groups headers are dropped ([`cmd/halo-proxy/proxy.go:447-452`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/proxy.go#L447-L452)).
  - Client credentials are stripped unless `--forward-auth` is set ([`cmd/halo-proxy/proxy.go:463-470`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/proxy.go#L463-L470)).
  - Provider credentials come only from the gateway host, never from the client ([`cmd/halo-proxy/route.go:233-253`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/route.go#L233-L253)). Vertex, Azure OpenAI, and OpenAI or Gemini upstreams with a policy `credential` get the gateway's credential. Bedrock is SigV4-signed. Anthropic and orchestrator upstreams get only the operator's `upstreamHeaders` (YAML, `${ENV}`-expanded), or the caller's own credential with `--forward-auth`.
  - SigV4 signs only for AWS hosts or a `signHosts` allowlist ([`cmd/halo-proxy/route.go:77-89`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/route.go#L77-L89)).
- **Config:** precedence is defaults, then YAML (`--config`, or env `HALO_PROXY_CONFIG`), then `HALO_PROXY_<FLAG>` env vars, then flags ([`cmd/halo-proxy/config.go:133-254`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/config.go#L133-L254)). Some keys are YAML only: `signHosts`, `upstreamHosts`, `allowInsecureUpstreams`, `upstreamHeaders`, `route.*` and `shadow.maxBytes`. The flags ([`cmd/halo-proxy/config.go:160-217`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/config.go#L160-L217)), including:
  - `--policy`
  - `--identity-mode jwt|trusted_header|none`, `--issuer`, `--audience`, `--allow-anonymous`
  - `--killswitch-{url,token-file,pubkey-file,interval}` (interval default 10s)
  - `--posture-*`, `--directory-*`, `--budget-*`, `--dlp-*` (halo-server gateway endpoints), `--workload-pubkey-file`
  - `--halo-shadow-{url,token}`
  - `--telemetry-{otlp-endpoint,token-file,interval,unit-salt-file}`
  - `--max-body-bytes` (32 MiB)
  - `--upstream-header-timeout` (10m)
  - Routing defaults: 3 attempts, breaker opens after 5 failures, 30 s cooldown ([`cmd/halo-proxy/config.go:128`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/config.go#L128)).
- **Ports:**
  - `:8088`: model traffic only. Plain HTTP, so terminate TLS in front of it. No write timeout, so long SSE streams are not cut ([`cmd/halo-proxy/main.go:36-40`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/main.go#L36-L40)).
  - `127.0.0.1:9090`: `/healthz`, `/readyz` and `/metrics`, unauthenticated ([`cmd/halo-proxy/proxy.go:217-243`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/proxy.go#L217-L243)).
- **Tests:**
  - unit tests: `cmd/halo-proxy/*_test.go`, `internal/gateway/*_test.go`, `internal/gateway/upstreamauth/*_test.go`
  - e2e: `TestGatewayTrafficPlane`, `TestGatewayEnforcement`, `TestRoutes`, `TestGeminiWire`, `TestToggles`
  - UAT: `TestCLIs` (real CLIs behind halo-proxy) and `TestK8sUAT` (Helm)

## halo-kong

**Purpose:** the same gateway decision, packaged as a Kong Go plugin for the Access phase. It is a thin adapter over `internal/gateway`. Plugin version `0.1.0`, priority `900` ([`cmd/halo-kong/main.go:72-75`](https://github.com/dshakes/halos/blob/main/cmd/halo-kong/main.go#L72-L75)).

- **Inputs:** the request via the Kong PDK (headers capped at 1000, path, raw body, peer IP) ([`cmd/halo-kong/main.go:507-517`](https://github.com/dshakes/halos/blob/main/cmd/halo-kong/main.go#L507-L517)), the policy snapshot at `policy_path`, and the kill list.
- **Outputs:**
  - The service request is rewritten: headers, scheme, target, path and body.
  - Or the request is answered with `kong.response.exit` and the rejection's status (for example 401, 400, 404 or 413).
  - Shadow jobs.
- **Key internal packages:** `internal/gateway`, `internal/identity`, `internal/policy`, `internal/shadow`, and `internal/bundle` (key parsing).
- **State and storage:** none. Snapshots are cached in memory per `policy_path` ([`cmd/halo-kong/main.go:154-165`](https://github.com/dshakes/halos/blob/main/cmd/halo-kong/main.go#L154-L165)).
- **Trust boundary:** the same rules as halo-proxy.
  - JWT mode answers 401 to unverified model calls unless `allow_unverified` is set.
  - Trusted-header mode honours headers only from `trusted_proxy_cidrs`.
  - Caller credentials are removed unless `forward_client_credentials` is set ([`cmd/halo-kong/main.go:1-45`](https://github.com/dshakes/halos/blob/main/cmd/halo-kong/main.go#L1-L45)).
  - Multi-target routes (weights, failover) are halo-proxy only. Kong uses each route's first target ([`internal/policy/types.go:178`](https://github.com/dshakes/halos/blob/main/internal/policy/types.go#L178)).
- **Config:** plugin JSON fields, among them `policy_path`, `identity_mode`, `issuer`, `audience`, `trusted_proxy_cidrs`, `shadow_url` / `shadow_token`, `killswitch_url` / `killswitch_token` / `killswitch_pubkey`, and `posture_url` / `posture_token`. Secrets can be `{vault://env/NAME}` references ([`cmd/halo-kong/main.go:78-124`](https://github.com/dshakes/halos/blob/main/cmd/halo-kong/main.go#L78-L124)).
- **Ports:** none of its own. It runs as a Kong plugin server process ([`cmd/halo-kong/main.go:577`](https://github.com/dshakes/halos/blob/main/cmd/halo-kong/main.go#L577)).
- **Tests:**
  - unit tests: `cmd/halo-kong/*_test.go`, `internal/gateway/kong`
  - UAT: `TestKong` with subtests `routing`, `identity`, `experiments`, `limits`, `killswitch`, `latency` and `kong`, run inside real Kong OSS 3.9 ([`test/uat/kong/kong_test.go:327-637`](https://github.com/dshakes/halos/blob/main/test/uat/kong/kong_test.go#L327-L637), `make uat-kong`)

## halo-shadow

**Purpose:** receives mirrored requests (first turns, or every step of a sampled session with `turns: all`), replays each against control and candidate, and stores the pairs for the LLM judge.

- **Inputs:** `POST` mirror jobs from halo-proxy or halo-kong, carrying a shared bearer token, and the compiled policy snapshot.
- **Outputs:** `pairs.jsonl`, mode `0600`, optionally AES-256-GCM encrypted (`--pair-key-file`), and counters.
- **Key internal packages:** `internal/shadow` (queue, workers, replay, budget) and `internal/gateway` (snapshot).
- **State and storage:**
  - `--out pairs.jsonl`
  - `--retention 720h` (30 days)
  - `--budget-usd` stops intake at the estimated spend
- **Trust boundary:**
  - A job carries no URL or model. halo-shadow resolves both upstreams from its own policy, so the token only lets a caller spend, within the budget, on upstreams the policy already names.
  - Credentials are per upstream (`--upstream-headers`), and redirects are not followed ([`cmd/halo-shadow/main.go:1-9`](https://github.com/dshakes/halos/blob/main/cmd/halo-shadow/main.go#L1-L9)).
  - `HALO_SHADOW_TOKEN` is required ([`cmd/halo-shadow/main.go:88`](https://github.com/dshakes/halos/blob/main/cmd/halo-shadow/main.go#L88)).
- **Config:** flags with `HALO_SHADOW_*` env defaults ([`cmd/halo-shadow/main.go:63-78`](https://github.com/dshakes/halos/blob/main/cmd/halo-shadow/main.go#L63-L78)):
  - `--policy`, `--upstream-headers`, `--out`, `--pair-key-file`, `--retention`
  - `--queue 64`, `--workers 4`
  - `--budget-usd`, `--price-in 3`, `--price-out 15`
  - `--database-url-file`, `--budget-scope`: with Postgres, replicas share one spend budget
- **Ports:**
  - `127.0.0.1:8090`
  - optional `--metrics-listen`, which serves `/metrics` without the token
- **Tests:**
  - unit tests: `cmd/halo-shadow/{main,ha}_test.go`, `internal/shadow/*_test.go`
  - e2e: `TestGatewayTrafficPlane` (mirror path)

## halo-server

**Purpose:** the control plane. It serves the console and the API, enrollment, the fleet ring and report endpoints, the signed kill list and the gateway endpoints (posture, directory, budget, DLP events). With `--controller` it also runs the automated experiment and rollout loop.

- **Inputs:**
  - the served policy directory, reloaded on `SIGHUP` ([`cmd/halo-server/main.go:703-716`](https://github.com/dshakes/halos/blob/main/cmd/halo-server/main.go#L703-L716))
  - console logins: OIDC, SAML 2.0 when `--saml-*` is set (ADR-0039, since v0.6.0), and the break-glass account when enabled
  - service-account API tokens (ADR-0036), SCIM 2.0 provisioning at `/scim/v2` (ADR-0022), and CI/cloud OIDC tokens at `POST /api/v1/token/exchange` (ADR-0023)
  - halod reports, and gateway calls carrying the gateway token
  - ClickHouse evidence, when `--controller` is set
- **Outputs:**
  - JSON API (routes in [`internal/server/server.go:443-550`](https://github.com/dshakes/halos/blob/main/internal/server/server.go#L443-L550); the OpenAPI description is served at `GET /api/v1/openapi.yaml`)
  - signed kill lists
  - policy PRs, from the portal writer and the controller
  - Slack and webhook notifications
  - audit log export to a SIEM (`--audit-config`, ADR-0016)
  - `/metrics` on `--metrics-listen`
- **Key internal packages:**
  - `internal/server`: HTTP handlers, OIDC and SAML login, sessions, RBAC, devices, service tokens, SCIM, audit and portal.
  - `internal/controller`: the loop, the kill store and the state log.
  - `internal/promote`: verdicts, ClickHouse source and PRs.
  - `internal/rollout`: rollout evaluation and hash-chained state.
  - `internal/storage`, `internal/pgstore`: the record-log seam and its Postgres backend (ADR-0021).
  - `internal/signer`: the kill-list key by URI.
  - `web`: the console, embedded with `-tags=webdist`.
    - Operator pages (read role): Fleet (per-ring compliance, a drift count per device and an "in sync" filter; the device page lists the drifted settings from halod's last report), Releases, **Rollouts** (`#/rollouts[/name]`: step timeline with the live step, per-gate status, bake countdown, halt and rollback events, and the ring-to-release pointers; the controller state is shown only when `halo-server --controller` keeps it in the data dir) and **Cost & budgets** (`#/budgets`, see [cost budgets](/halos/guides/cost-budgets/)).
- **State and storage:** either append-only JSONL logs under `--data-dir`, or Postgres with `--database-url-file` for several replicas (the two are exclusive; [`cmd/halo-server/main.go:214-241`](https://github.com/dshakes/halos/blob/main/cmd/halo-server/main.go#L214-L241)). The data dir holds, among others:
  - `reports.jsonl`, `devices.jsonl`, `audit.jsonl`, `requests.jsonl`, `approvals.jsonl`, `session-revocations.jsonl`, `service-tokens.jsonl`, `scim.jsonl`
  - `killswitch.jsonl`, append-only and fsynced ([`internal/controller/killstore.go:138-183`](https://github.com/dshakes/halos/blob/main/internal/controller/killstore.go#L138-L183))
  - `controller-state.jsonl`
  - `rollouts/<name>.json`, hash-chained ([`internal/rollout/state.go:155-194`](https://github.com/dshakes/halos/blob/main/internal/rollout/state.go#L155-L194))
  - With neither, reports are kept in memory only. The kill switch, the controller, `--audit-config` and SCIM refuse to start without durable state ([`cmd/halo-server/main.go:214-241`](https://github.com/dshakes/halos/blob/main/cmd/halo-server/main.go#L214-L241)).
- **Trust boundary:**
  - Console users: OIDC login with state and nonce checks ([`internal/server/auth.go:424-560`](https://github.com/dshakes/halos/blob/main/internal/server/auth.go#L424-L560)), or a signed SAML response at `POST /auth/saml/acs` ([`internal/server/saml.go:463`](https://github.com/dshakes/halos/blob/main/internal/server/saml.go#L463)). Every cookie-authenticated route needs the permission `routePerms` names; a route missing from it is denied to everyone ([`internal/server/rbac.go:49-53`](https://github.com/dshakes/halos/blob/main/internal/server/rbac.go#L49-L53), [`internal/server/rbac.go:180-201`](https://github.com/dshakes/halos/blob/main/internal/server/rbac.go#L180-L201)).
  - Break-glass: a local admin, off unless `--breakglass-enabled`, with a PBKDF2-SHA256 password hash, optional source CIDRs and a short session that never slides (ADR-0036).
  - Service accounts: bearer tokens stored as SHA-256 hashes, compared in constant time, revocable ([`internal/server/servicetokens.go:310-340`](https://github.com/dshakes/halos/blob/main/internal/server/servicetokens.go#L310-L340)).
  - Devices: per-device tokens minted at enrollment and stored hashed ([`internal/server/devices.go:163-196`](https://github.com/dshakes/halos/blob/main/internal/server/devices.go#L163-L196)), or the shared fleet token for MDM and devcontainer fleets ([`internal/server/server.go:636-640`](https://github.com/dshakes/halos/blob/main/internal/server/server.go#L636-L640)).
  - Gateways: the gateway token, or a per-capability token, compared as SHA-256 in constant time ([`internal/server/killswitch.go:210-225`](https://github.com/dshakes/halos/blob/main/internal/server/killswitch.go#L210-L225)).
  - SCIM: bearer tokens checked against `--scim-token-sha256-file`.
  - Failed attempts are rate limited per IP.
  - halo-server holds the kill-list private key (`--killswitch-key-file`, or `--killswitch-key-uri` for AWS KMS or an external signer) and never the release key.
- **Config:** flags ([`cmd/halo-server/main.go:104-163`](https://github.com/dshakes/halos/blob/main/cmd/halo-server/main.go#L104-L163), SAML in [`cmd/halo-server/saml.go`](https://github.com/dshakes/halos/blob/main/cmd/halo-server/saml.go)):
  - `--policy-dir`, `--token-file`, `--data-dir` or `--database-url-file`
  - `--portal-config`, `--audit-config`
  - `--killswitch-key-file` or `--killswitch-key-uri`, together with `--gateway-token-file` (or `--gateway-killswitch-token-file`); optional per-capability `--gateway-{killswitch,posture,budget,directory,dlp}-token-file`
  - `--controller`, `--interval` (5m, minimum 1m)
  - `--clickhouse-*`
  - `--notify-*`
  - `--policy-repo-*`, `--forge`, `--forge-base-url`
  - `--saml-*`, `--breakglass-*`, `--scim-*`, `--session-ttl`, `--session-idle-timeout`, `--service-token-max-ttl`
  - `--device-ttl`, `--trusted-proxy-cidrs`
  - `--dev-insecure-user` (demo only)
- **Ports:**
  - `127.0.0.1:8080`
  - optional `--metrics-listen` for `/metrics` (audit export, controller, leader lease and database)
- **Tests:**
  - unit tests: `cmd/halo-server/*_test.go` (among them `saml_test.go` and `ha_test.go`), `internal/server/*_test.go`, `internal/controller/*_test.go`
  - e2e: `TestPortalEnrollment`, `TestClientAxisExperiment`, `TestRollout`, `TestToggles`, `TestGatewayEnforcement`
  - UAT: `TestK8sUAT`

### Controller

This is the same loop as `halo controller run`. Every `--interval` it evaluates each running experiment and active rollout against ClickHouse. When the evidence says rollback, it trips the kill switch, but only on gateway-sourced evidence. It then opens a PR and notifies. It never merges. See the [controller loop](/halos/architecture/low-level-design/#controller-loop).

### Console

`web/` is a React, Vite and TypeScript SPA ([tech stack](/halos/architecture/tech-stack/#web-console)), served by `halo-server` at `/` ([`internal/server/server.go:548`](https://github.com/dshakes/halos/blob/main/internal/server/server.go#L548)). Session routes are registered through `s.route(...)`, which checks the permission `routePerms` gives the route; roles grant permissions ([`internal/server/rbac.go:12-53`](https://github.com/dshakes/halos/blob/main/internal/server/rbac.go#L12-L53)).

## MCP server

**Purpose:** lets coding agents read and propose Halos changes. It is `halo mcp serve`, not a separate binary.

- **Inputs:** `--policy-dir`, and optionally `--clickhouse` (enables `analyze_experiment`), `--server` with `HALO_TOKEN` or `HALO_SESSION` (fleet, kill-switch, audit and session-ledger reads), `--admin-read` and `--roi-identities` ([`cmd/halo/mcp.go:42-49`](https://github.com/dshakes/halos/blob/main/cmd/halo/mcp.go#L42-L49)).
- **Outputs:** tool results, `halos://` resources and prompts. Every tool answers with `next_steps`. With `--allow-writes`, it can also create local git branches, open PRs and post to halo-server's reversible kill list.
- **Tools** ([`internal/mcpserver/server.go:101-110`](https://github.com/dshakes/halos/blob/main/internal/mcpserver/server.go#L101-L110)):
  - **Read**, always registered: `validate`, `plan`, `render_preview`, `whoami`, `list_rings`, `list_experiments`, `show_experiment`, `harness_matrix`, `explain_release_diff`, `eval_scorecard` ([`internal/mcpserver/tools_read.go:109-126`](https://github.com/dshakes/halos/blob/main/internal/mcpserver/tools_read.go#L109-L126)), plus `status`, `release_build`, `wait_for`, `list_rollouts`, `rollout_status`, `list_toggles`, `evaluate_toggle`, `eval_matrix`, `upgrade_candidates`, `policy_test`, `admin_plan`, `roi_report` and the halo-server reads.
  - **Onboarding** and **copilot** tools: `doctor`, `detect_harnesses`, `init_policy`, `local_install`, `local_proxy`, `verify_harness`, `onboard_company`; `copilot_draft`, `copilot_experiment`, `copilot_explain`, `copilot_next`. Those with a side effect preview by default and write only with `--allow-writes`.
  - **Write**, only with `--allow-writes`: `start_experiment`, `pause_experiment`, `conclude_experiment`, `propose_promotion`, `propose_rollback` ([`internal/mcpserver/tools_write.go:66-82`](https://github.com/dshakes/halos/blob/main/internal/mcpserver/tools_write.go#L66-L82)), `propose_toggle_change`, `propose_rollout_advance`, `propose_rollout_rollback`. `kill_switch`, `eval_run` and `eval_harvest` are always registered but only preview without it. Each defaults to `dry_run` and requires a `reason`. None of them publishes, pushes to main or merges.
- **Key internal packages:** `internal/mcpserver`, `internal/policy`, `internal/release`, `internal/promote`, `internal/rollout`, `internal/toggle`, `internal/eval`, `internal/upgrade`, `internal/copilot`, `internal/onboard`.
- **State:** none. Ports: none (stdio).
- **Tests:** unit tests in `internal/mcpserver/*_test.go`; e2e `TestMCPServe` and `TestAutopilotLifecycle`.

## Claude Code plugin

**Purpose:** packages the MCP server and Halos workflows for Claude Code.

[`plugins/claude-code`](https://github.com/dshakes/halos/tree/main/plugins/claude-code) contains:

- `.mcp.json`, which runs `halo mcp serve --policy-dir ${HALOS_POLICY_DIR:-.}` without `--allow-writes`.
- Skills: `halos-author-policy`, `halos-autopilot`, `halos-onboard`, `halos-rollout`, `halos-triage`.
- Commands: `/halos:halo-onboard`, `/halos:halo-autopilot`, `/halos:halo-rollout`, `/halos:halo-status`.
- Agent: `halos-release-manager`, which proposes but never publishes, retags, merges or pushes.
- No hooks.

The plugin has no code of its own, so it has no tests. `TestMCPServe` covers the server it starts.

## Package dependency map

Every package under `cmd/` and `internal/`, with its direct, non-test imports of other Halos packages. The graph is built from `go list` across `GOOS=linux`, `darwin` and `windows`. Rows and columns are in dependency order: a dot in row *r*, column *c* means *r* imports *c*. Because Go forbids import cycles, every dot falls below the diagonal.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/package-deps-light.svg" alt="Dependency structure matrix of the 69 Halos packages under cmd and internal, ordered by layer; every import falls below the diagonal." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/package-deps-dark.svg" alt="Dependency structure matrix of the 69 Halos packages under cmd and internal, ordered by layer; every import falls below the diagonal." width="760" />

The data is in [`assets/src/pkgdeps.json`](https://github.com/dshakes/halos/blob/main/assets/src/pkgdeps.json). `TestPackageGraph` fails when that file no longer matches `go list`. To regenerate it and the diagram:

```sh
go test ./internal/docgen -run TestPackageGraph -update
python3 assets/src/build.py
```
