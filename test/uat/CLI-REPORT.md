# Real-CLI UAT report

`make uat-clis` (`scripts/uat-clis.sh` -> `go test -tags uat -run TestCLIs ./test/uat/`) drives the
**real** AI CLIs at the versions pinned in `examples/acme-corp` against mock upstreams. There are
no API keys. Latest run: 2026-10-01, Docker Desktop 28.0.1 (linuxkit 6.10.14, arm64), **86 s**
warm (a cold run adds about a minute for the Feature install downloading the pinned CLIs). Result:
**58 PASS, 2 FAIL (known, environmental: no Landlock), 2 UNVERIFIED, 0 unexpected**. The generated table with full evidence is
`test/uat/cli-results.md` (rewritten on every run).

| CLI | version tested | installed by |
|---|---|---|
| Claude Code | `2.1.280` | Feature -> halod (native artifact from downloads.claude.ai, sha-verified) |
| Codex CLI | `0.99.0` (was 0.58.0) | Feature -> halod (npm tgz, integrity-verified) |
| Gemini CLI | `0.34.0` (was 0.12.0) | Feature -> halod (npm tgz) |
| Copilot CLI | `1.0.90` | Feature -> halod (npm tgz). acme pins no Copilot, so UAT pins 1.0.90 |

## What runs

All of it runs on one Docker network (`test/uat/clis_env_test.go`):

1. **Release.** The UAT policy is `examples/acme-corp` (same org, ring `ring3-ga`, same pins and
   per-harness models) with the issuer, gateway, MCP servers and OTLP endpoint pointed at the mock,
   plus a running traffic experiment (`uat-route`, routing `sonnet`, `codex-default` and
   `gemini-default`) so a variant is stamped. `halo release publish` pins the vendor artifacts, signs
   the release and pushes it to `registry:2` over TLS.
2. **Feature.** `features/halos/install.sh` runs as root in `node:22-bookworm-slim` with its options
   as upper-case env (as the devcontainer CLI runs it): sha-pinned halod download, `halod.yaml`,
   pubkey, `halod once --install`. The devcontainer CLI wiring itself is covered by
   `make feature-test`.
3. **halo-proxy** runs on `localhost:8088` with `halo gateway compile` output and verifies RS256 JWTs
   from the mock issuer. The JWT comes from `gateway.auth.helperCommand`: Claude's `apiKeyHelper`,
   codex's `HALO_GATEWAY_TOKEN`, gemini's profile.d `GEMINI_API_KEY`.
4. **Mock** (`test/uat/mock`): OIDC issuer, Anthropic Messages (SSE, tool_use), OpenAI Responses
   (SSE, `exec_command`/`shell` calls), Chat Completions, Gemini `generateContent`/
   `streamGenerateContent`, streamable-HTTP MCP servers, and a signal-agnostic OTLP/HTTP sink. It
   records every request; markers in the user turn script a real tool loop.
5. **Eval.** `halo eval run` uses the DockerRunner (`evals/images` at the pins) with the real
   `claude` and `codex` drivers: 2 tasks x 2 repeats x 3 arms (`claude`/sonnet control, `claude-b`/
   opus, `codex`). The mock solves `uat-pass` for everyone, never solves `uat-fail` for codex, and
   solves it for each Claude model on every other attempt (flaky by construction). A `--matrix` run
   follows.

## Results

PASS = observed with the real CLI. FAIL (known) = recorded with evidence; it does not fail the run,
but a known gap that starts passing does. UNVERIFIED = not observable here, with the reason.

| Harness | Assertion | Result | Evidence |
|---|---|---|---|
| all four | Feature installs the pinned version | PASS | claude 2.1.280, codex 0.99.0, gemini 0.34.0, copilot 1.0.90; halod `drift: []` |
| all four | halod applied == `halo render` (byte-identical) | PASS | includes the new `/etc/profile.d/halos-{codex,gemini,copilot-cli}.sh` |
| claude-code | version window: below min / above max refused; `--version` not gated | PASS | rc=1 with the org min/max messages |
| claude-code | `claude doctor` shows managed env | PASS | "Auto-updates: disabled (set by env: DISABLE_AUTOUPDATER)" |
| claude-code | answer via halo-proxy; ring/variant stamped; JWT not forwarded; alias rewritten | PASS | sonnet -> claude-uat-sonnet-upstream, ring3-ga |
| claude-code | OTEL carries halo.ring/halo.release/halo.harness | PASS | `halo.harness=claude-code, halo.release=uat.1, halo.ring=ring3-ga` |
| claude-code | deny `Read(./.env)`; model lock; MCP allowlist; bypassPermissions refused | PASS | see cli-results.md |
| claude-code | disallowed `--model`: fallback goes to a gateway alias | **PASS** | the CLI drops `--model my-rogue-model` silently and dispatches its built-in `claude-opus-5-5[1m]`; the adapter's `modelOverrides` sends it as `opus` (upstream `claude-uat-opus-upstream`, answered). Before that it got the gateway's 400 on the first attempt with our message (verified, then superseded) |
| codex | managed_config.toml loads with the per-harness model | PASS | banner "model: codex-default / provider: halos" (G7) |
| codex | answer via halo-proxy; ring/variant stamped; JWT not forwarded; alias rewritten | PASS | codex-default -> gpt-uat-upstream |
| codex | OTEL carries halo.ring/halo.release/halo.harness | **PASS** (was FAIL, G3) | logs resource `halo.harness=codex, halo.release=uat.1, halo.ring=ring3-ga, service.name=codex_exec` |
| codex | requirements: `-s danger-full-access` and `approval_policy=never` fall back; user MCP not connected | PASS | "falling back to required value OnRequest", "sandbox: read-only" |
| codex | model not permitted: gateway message shown, not retried | **PASS** (G5) | rc=1 in 0 s, no reconnect: `ERROR: {"error":{"code":"model_not_allowed","message":"model \"my-rogue-model\" is not permitted ..."}}` |
| gemini-cli | gateway URL + `GEMINI_API_KEY` (JWT) from profile.d; enforced auth type; `mcp.allowed` | PASS | GOOGLE_GEMINI_BASE_URL=http://localhost:8088 |
| gemini-cli | answer via halo-proxy; ring/variant stamped; x-goog-api-key and `?key=` stripped | PASS | gemini-default -> gemini-uat-upstream (G7) |
| gemini-cli | unlisted alias refused, not forwarded | PASS | proxy 400 INVALID_ARGUMENT, nothing forwarded |
| gemini-cli | model not permitted: gateway message shown | **PASS** (G5) | rc=1 in 2 s, no retry; stderr `Error when talking to Gemini API ... ApiError: {"error":{"code":400,"message":"model \"my-rogue-model\" is not permitted ..."}}`, then gemini's own "[object Object]" |
| gemini-cli | OTEL carries halo.ring/halo.release/halo.harness | **PASS** (was FAIL, G3) | `halo.harness=gemini-cli` on 0.34.0's `/v1/{signal}` exports |
| gemini-cli | `--yolo` refused | **PASS** (was FAIL, G2) | rc=52 "YOLO mode is disabled by your administrator" |
| copilot | runs without GitHub login; allowedMcpServers holds | PASS | BYOK env to the mock; /mcp/rogue 0 hits |
| copilot | OTEL carries halo.ring/halo.release/halo.harness | **PASS** (was FAIL, G3) | `halo.harness=copilot-cli` |
| copilot | traffic through halo-proxy | UNVERIFIED | by design: BYOK is env-only, the adapter renders no gateway (warns); halo-proxy has no chat-completions route |
| copilot | `disableBypassPermissionsMode` | UNVERIFIED | `--allow-all` still starts; tool approval not exercised (mock emits no chat tool calls) |
| eval | real claude + codex drivers ran all 12 trials | PASS | |
| eval | claude and claude-b: pass@1 3/4, pass@2 1, pass^2 0.5 | PASS | uat-pass 2/2, uat-fail 1/2 |
| eval | flake handling | PASS | `gate.flaky=[uat-fail]`, excluded from the claude-b gate |
| eval | verdicts follow the data | PASS | claude-b ship; overall hold (codex arm unmeasurable) |
| eval | Markdown report + `--matrix` render | PASS | |
| eval | codex sandbox probe (`codex sandbox linux --full-auto true` under the runner's isolation flags) exits 0 | FAIL (known, environmental) | rc=101 `Sandbox(LandlockRestrict)` on linuxkit 6.10.14 |
| eval | codex: pass@1 2/4 | FAIL (known, environmental) | no Landlock on Docker Desktop's linuxkit kernel; the DockerRunner's preflight (evals workstream) marks codex trials "sandbox unavailable (Landlock)" -> unmeasurable, hence hold. Needs a Landlock-capable host (Linux CI) |

## Fixed this round (each with a regression test)

### G1/G2: pins and gemini YOLO lock

- **Codex 0.99.0** in every example (acme `engineering-next`: 0.100.0), eval image and
  `package-check.sh`. 0.77.0 is the first version with `allowed_sandbox_modes`; 0.77.0-0.98.0
  hard-fail `codex exec` under on-request-only requirements (bisected with the real CLI); 0.99.0
  falls back. The adapter always lists `read-only` in `allowed_sandbox_modes` (otherwise codex
  refuses to start) and warns below 0.77 and for 0.77-0.98.
- **Gemini 0.34.0** in acme (`engineering-next`: 0.35.0), eval image and `package-check.sh`. It is
  ≥0.24 as asked and also the first version that POSTs OTLP/HTTP to `/v1/{traces,logs,metrics}`.
- **`admin.secureModeEnabled` does not work from the system settings file on any version**: absent
  before 0.24.0, and from 0.24.0 the `admin` block comes only from Google's remote admin controls.
  `--yolo` still ran on 0.34.0 with it set. `security.disableYoloMode` (present since at least 0.12.0)
  is honored, so the adapter renders that for `permissions.disableBypass`, and the build-time
  security backstop (`internal/release/check.go`) now requires it. Tests:
  `TestNoGatewayNoEnforcedAuthAndDisableYolo`, release `TestCheckRendered`/`TestBuildBackstop`.
- `halo validate` passes on all 8 examples.

### G3: OTEL resource attributes for codex, gemini-cli, copilot-cli

None of the three has a config key for resource attributes; all three honor
`OTEL_RESOURCE_ATTRIBUTES`. On Linux each adapter renders `/etc/profile.d/halos-<harness>.sh` with a
shell wrapper, `codex() { OTEL_RESOURCE_ATTRIBUTES='…' command codex "$@"; }`, exported to bash
children. Attributes: profile attributes, `halo.harness`, `halo.ring`, `halo.release`, and
`halo.experiment`/`halo.variant` on a variant release. It is a function rather than an exported
variable because each CLI's `halo.harness` differs, so one global variable would mislabel the others.
Shared helpers `hutil.OTELResourceAttributes` (Claude's managed env uses it too; output unchanged) and
`hutil.OTELShellWrapper`. halod's write allowlist gained exactly `/etc/profile.d/halos-codex.sh` and
`/etc/profile.d/halos-copilot-cli.sh` (Meta.ManagedFiles). Off Linux the adapters warn.
Test: `TestExperimentAttribution` (all four adapters, spoof and ring-release cases), plus goldens.

**Limit:** login shells and their bash children only. An exec that skips the shell (`timeout codex`,
`env codex`, IDEs that don't start a login shell) runs unlabeled. The UAT runs the CLIs via
`bash -c` for that reason.

### G7: per-harness default model

- New field `harnesses.<h>.model` (`policy.HarnessSpec.Model`, `schemas/profile.schema.json`,
  regenerated reference docs) replaces `models.default` for that harness in all four adapters
  (`hutil.Model`). Validation: it must be a `gateway.models` alias, and in `models.allowed` when
  `enforce` is set; it survives `extends`. A typed field rather than an `overrides.model` entry, so it
  is checked against the gateway like `models.default`.
- acme `engineering`: `codex: codex-default`, `gemini-cli: gemini-default`.
- Tests: `TestValidate` (two cases), `TestHarnessModelValidAndInherited`, codex `TestHarnessModel`.
- **Found along the way:** acme's `orchestrator-responses` upstream URL was `https://…/v1/responses`.
  halo-proxy treats an upstream URL as a base and appends the request path, so codex traffic went to
  `/v1/responses/v1/responses` (404) once codex actually used `codex-default`. The example now uses
  the base URL.
- **`examples/simple`** (intent-layer workstream): simple-mode `tools:` entries accept
  `{version, model}`, expanding to `HarnessSpec.Model`. The example's codex now renders
  `model = 'codex'` (verified with `halo render`); `halo validate` passes.
  `halo init --tools codex@...` still starts codex on `default` unless a model is added.

## Earlier fixes (still covered)

1. Claude resolves aliases before sending, so in gateway mode the adapter pins
   `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL` to the gateway aliases (`TestGatewayAliasesPinned`).
2. Codex needs an `otel.exporter.*.headers` table or refuses to start, and its OTLP/HTTP endpoint
   needs `/v1/logs` appended (`TestOTLPHeadersAndRequirementsVersion`, `TestOTLPHTTPProtocol`).
3. With a gateway, gemini gets `security.auth.enforcedType: gemini-api-key`, so a Google login cannot
   bypass it (`TestGolden`).
4. The eval codex driver passes `--skip-git-repo-check` (`TestCodexDriver`); the DockerRunner accepts
   settings in symlinked suite dirs (`TestDockerSettingsSymlinkedSuiteDir`).
5. Silent no-ops warn (invariant 2): codex <0.77 / 0.77-0.98, gemini OTLP/HTTP <0.34
   (`hutil.VersionBefore`).

`internal/harness/FACTS.md` has a **[UAT]** section per CLI with the observed behavior.

## Still open

- **G5 (closed).** halo-proxy now refuses a model outside policy with a 400 on every wire
  (s4-providers). All three CLIs stop on the first attempt and show the gateway's message (rows
  above); Claude previously retried 11 times over about 2 minutes. Claude's client-side fallback for a disallowed `--model` (its built-in `claude-opus-5-5[1m]`,
  ignoring every env pin) is now mapped to the `opus` alias by a rendered `modelOverrides`, so it is
  served instead of refused. Known CLI limitation: `--model` is dropped silently and no setting makes
  it refuse locally (FACTS.md); the built-in IDs are per-generation, so a new Claude default ID shows
  up as the UAT fallback row failing.
- **G6** Codex evals need Landlock; the runner now reports this honestly (above). Codex 0.99.0's
  `--json` emits no item for an `exec_command` the sandbox denied (only the model sees it, in the
  `function_call_output`: helper exit 101, `Sandbox(LandlockRestrict)`); a command that runs and
  exits non-zero is an `item.completed` `command_execution` with `status: failed`. Raw transcripts for
  the evals workstream: `internal/eval/testdata/codex/` (tool-success, command-failed, sandbox-denied).
- `x-gemini-api-privileged-user-id` (a per-install client id) is forwarded to the provider; decide
  whether the gateway should drop it. Gemini sends no session header, so sticky routing has no key.
- Cosmetic: Claude prints `[claude-code:unrecognized_model] {"model":"sonnet",...}` once per run when
  aliases are pinned.

## CI (Linux, Landlock)

The `uat-clis` job in `.github/workflows/ci.yml` runs `make uat-clis` on `ubuntu-latest` with
`UAT_REQUIRE_LANDLOCK=1`. That turns the two Landlock known gaps (the probe row and the codex eval
arm) into hard failures, so on CI they must PASS. Locally, `UAT_REQUIRE_LANDLOCK=1 make uat-clis`
fails exactly those rows (plus "ran every trial"), which shows the gate works. This file and
`cli-results.md` are uploaded as the `uat-clis-report` artifact. **UNVERIFIED until it runs on GitHub**:
whether the runner kernel plus Docker's default seccomp profile let codex apply Landlock inside the
eval container. The two Copilot UNVERIFIED rows are by design and stay UNVERIFIED on Linux too.

## Reproduce

```sh
make uat-clis                 # or: scripts/uat-clis.sh
KEEP=1 make uat-clis          # keep containers + scratch (/var/folders/.../halos-uat-clis-*) for debugging
```

Needs Docker and network access (npm, downloads.claude.ai). Everything is labelled
`halos-uat-clis=<run id>` and removed on exit.
