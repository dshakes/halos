# Harness facts (verified 2026-09-30)

Every claim was read from the cited source. Claims marked **[UAT]** were observed
with the real CLI at the acme-corp pins (claude-code 2.1.280, codex 0.99.0 (was 0.58.0),
gemini-cli 0.34.0 (was 0.12.0), copilot 1.0.90) by `make uat-clis` (test/uat, CLI-REPORT.md);
they override the docs where they disagree.

## Claude Code
- **[UAT]** Managed `model: sonnet` is resolved by the CLI before sending (2.1.280 sends `claude-sonnet-5`; `opus` -> `claude-opus-5-5`), so a gateway that allowlists policy aliases rejects it. `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL=<alias>` makes it send the alias (it then prints a harmless `[claude-code:unrecognized_model]` line); the adapter sets these for every Claude alias the gateway routes.
- **[UAT]** A model outside `availableModels` with `enforceAvailableModels` is never sent, but `--model` is dropped **silently** (no notice, not even in `--debug`) and the CLI uses its tier default as a built-in ID (`claude-opus-5-5[1m]` on 2.1.280), not the managed `model`; `--model default` does the same. That path ignores `ANTHROPIC_DEFAULT_*_MODEL`, `ANTHROPIC_DEFAULT_MODEL` and `ANTHROPIC_MODEL` (process or managed env); `CLAUDE_CODE_NO_MODEL_FALLBACK` only governs Fable substitution; dropping `opus` from `availableModels` just moves it to `claude-sonnet-5`. No setting makes `--model` refuse locally (only the interactive `/model` says "Your organization restricts model selection"). **`modelOverrides` is applied to it** ("policy-mapped"): `{"claude-opus-5-5": "opus"}` sends the fallback as `opus` (the `[1m]` suffix is stripped before lookup). The adapter renders `modelOverrides` built-in ID -> alias for each Claude alias the gateway routes (IDs verified on 2.1.280: `claude-opus-5-5`, `claude-sonnet-5`, `claude-haiku-4-5-20251001`). A gateway refusal (400 since G5) is not retried; a 403 was retried 11 times.
- **[UAT]** `requiredMinimumVersion`/`requiredMaximumVersion` stop `claude -p` at startup ("...older than the minimum version required by your organization"); `claude --version` is not gated. `permissions.deny` `Read(./.env)` returns "File is in a directory that is denied by your permission settings" to the model. `allowManagedMcpServersOnly` hides a user-added server from `claude mcp list` and it is never contacted. OTLP resource attributes from `OTEL_RESOURCE_ATTRIBUTES` in managed `env` arrive on logs and metrics.

## Codex
Sources: M = https://learn.chatgpt.com/docs/enterprise/managed-configuration,
R = https://learn.chatgpt.com/docs/config-file/config-reference,
S = https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json,
X = https://raw.githubusercontent.com/openai/codex/main/codex-rs/exec/src/cli.rs (+ utils/cli/src/shared_options.rs, exec/src/exec_events.rs).

- requirements.toml: `/etc/codex/requirements.toml` (Linux+macOS), `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows). macOS MDM: domain `com.openai.codex`, key `requirements_toml_base64` (M). MDM is not rendered.
- managed_config.toml (legacy managed defaults): `/etc/codex/managed_config.toml` (Unix); Windows/non-Unix is `~/.codex/managed_config.toml`, i.e. no system-wide path, so we render nothing for it on Windows (M). MDM key `config_toml_base64`.
- Requirements keys: `allowed_approval_policies`, `allowed_sandbox_modes` (M, R); `mcp_servers.<id>.identity.{command|url}` allowlist, name and identity must both match, others disabled (R). `command` = exact string or `{executable, args=[{match=exact|prefix|regex, value}]}`; `url` = exact string or matcher table.
- `approval_policy` values: `on-request | never | {granular=...}`; `untrusted` unsupported, `on-failure` deprecated (R, S). `sandbox_mode`: `read-only | workspace-write | danger-full-access` (S).
- `[otel]`: `environment`, `log_user_prompt`, `exporter = {otlp-grpc={endpoint,headers}}` or `{otlp-http={endpoint, protocol="binary"|"json"}}` (protocol required for http) (S, R).
- **[UAT]** codex 0.58.0 refuses to start without `headers` in the exporter table ("missing field `headers` in `otel.exporter`"); the adapter always renders an empty one. OTLP/HTTP logs are POSTed to `endpoint` verbatim, so the adapter appends `/v1/logs`. The resource carries `env=<otel.environment>`, `service.name=codex_exec`; there is no config key for other resource attributes (the `OTEL_RESOURCE_ATTRIBUTES` env var is honored).
- **[UAT]** codex 0.58.0 reads no `requirements.toml` at all (`-s danger-full-access`, `approval_policy=never` and a user MCP server all run). `allowed_approval_policies` exists in 0.76.0, `allowed_sandbox_modes` from 0.77.0 (binary strings, openai/codex#8298). The adapter warns for pins below 0.77.0.
- **[UAT]** codex >= 0.77.0 refuses to start unless `allowed_sandbox_modes` includes `read-only` ("must include 'read-only' to allow any SandboxPolicy"); the adapter always lists it (stricter than any rendered mode). `codex exec` forces `approval_policy=never`: on 0.77.0-0.98.0 that is a hard error under `allowed_approval_policies = ['on-request']` ("`Never` is not in the allowed set [OnRequest]"), so headless codex/CI/evals cannot run; from 0.99.0 it falls back to the allowed value with a warning (bisected 0.77, 0.90, 0.95-0.100, 0.105, 0.110, 0.130, 0.145, 0.159.3). The adapter warns for 0.77-0.98; the example pins are 0.99.0. On 0.99.0 `-s danger-full-access` falls back to `read-only`, and a non-allowlisted user MCP server is not connected (codex still fetches its `/.well-known/oauth-authorization-server`).
- **[UAT]** codex 0.99.0 offers `exec_command {cmd}` instead of `shell {command[]}`, and `codex exec --json` emits no item for a failed `exec_command`, so the eval driver cannot count those tool errors.
- **[UAT]** `codex exec` in a non-git workdir exits 1 "Not inside a trusted directory" without `--skip-git-repo-check` (the eval driver passes it). The `workspace-write` sandbox is Landlock: on a kernel without it (Docker Desktop linuxkit 6.10.14) every shell call exits 101 "error running landlock".
- Model provider: `base_url, env_key, http_headers, wire_api, name` (S).
- `codex exec`: `--json`, `--sandbox/-s`, `-m/--model`, `--skip-git-repo-check`, `-` reads prompt from stdin (X). JSONL events `thread.started`, `turn.completed{usage.input_tokens,output_tokens}`, `turn.failed{error.message}`, `error`, `item.completed{item.type=command_execution, exit_code}` (exec_events.rs).
- npm package `@openai/codex` (registry latest 0.159.2).

## Gemini CLI
Sources: E = https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/enterprise.md,
C = .../docs/reference/configuration.md, H = .../docs/cli/headless.md, packages/core/src/output/types.ts, packages/core/src/telemetry/uiTelemetry.ts.

- System settings: Linux `/etc/gemini-cli/settings.json`, Windows `C:\ProgramData\gemini-cli\settings.json`, macOS `/Library/Application Support/GeminiCli/settings.json`; override `GEMINI_CLI_SYSTEM_SETTINGS_PATH` (E, C).
- Keys: `model.name` (string), `mcp.allowed`/`mcp.excluded` (arrays), `tools.core` (allowlist), `tools.exclude`, `tools.allowed`, `admin.secureModeEnabled` (disallows YOLO/"Always allow"; **remote admin controls only**, see [UAT] below), `security.disableYoloMode`, `admin.mcp.*`; `mcpServers.<n>.{command,args,url,httpUrl,headers}`; `telemetry.{enabled,target=local|gcp,otlpEndpoint,otlpProtocol=grpc|http,logPrompts}` (C). We render `security.disableYoloMode` for `permissions.disableBypass`.
- `GOOGLE_GEMINI_BASE_URL`: only honored with gemini-api-key auth; HTTPS or localhost only (C).
- **[UAT]** gemini-cli 0.12.0 and 0.34.0 honor `security.auth.enforcedType` ("The enforced authentication type is 'gemini-api-key', but the current type is 'oauth-personal'"); with a gateway the adapter renders `gemini-api-key` so a Google login cannot bypass it. `mcp.allowed` keeps a user-added server from connecting. **`admin.secureModeEnabled` in the system settings file is ignored** (absent before 0.24.0; from 0.24.0 the `admin` block is taken from Google's remote admin controls only), so `--yolo` ran on both pins. `security.disableYoloMode` (present since at least 0.12.0) is honored on 0.34.0: "YOLO mode is disabled by your administrator", exit 52. The adapter renders it for `permissions.disableBypass`, and the release check requires it. OTLP/HTTP: before 0.34.0 every signal is POSTed to `otlpEndpoint` verbatim; 0.34.0 POSTs to `/v1/{traces,logs,metrics}` (adapter warns below 0.34.0). Model calls carry the API key as `x-goog-api-key`; no session header is sent; `x-gemini-api-privileged-user-id` is sent.
- **[UAT]** codex 0.99.0, gemini-cli 0.34.0 and copilot 1.0.90 have no config key for OTEL resource attributes but honor `OTEL_RESOURCE_ATTRIBUTES`. On Linux each adapter renders `/etc/profile.d/halos-<harness>.sh` with a shell function (`codex() { OTEL_RESOURCE_ATTRIBUTES=... command codex "$@"; }`, exported to bash children) carrying `halo.harness/ring/release` (+ experiment/variant): verified on logs, metrics and traces. It is a function, not an export, because each CLI's `halo.harness` differs; an exec that bypasses the shell (`timeout codex`, `env`, IDEs that skip login shells) runs unlabeled.
- Headless: `-p`, `--output-format json|stream-json`, `-m` (C, H). JSON: `{response, stats, error?}`; stats `models.<m>.tokens.total`, `tools.totalFail` (types.ts, uiTelemetry.ts). Exit codes 0/1/42/53 (H).
- npm package `@google/gemini-cli` (latest 0.62.0).

## Copilot CLI
Sources: https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/use-managed-settings/deploy-managed-settings,
https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings,
https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models,
https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/configure-copilot-cli.

- File-based managed settings `managed-settings.json`: macOS `/Library/Application Support/GitHubCopilot/`, Windows `%Program Files%\GitHubCopilot\`, Linux `/etc/github-copilot/`. On macOS/Linux CLI requires a regular, root-owned, non-group/world-writable, non-symlink file. Precedence: MDM > server-managed (.github-private/copilot/managed-settings.json) > file > user. MDM is macOS/Windows only.
- Keys rendered: `model` (default only, users may override), `permissions.disableBypassPermissionsMode="disable"`, `allowedMcpServers=[{serverUrl}|{serverCommand:[...]}]`, `telemetry{enabled,endpoint,protocol=http/json|http/protobuf,captureContent,lockCaptureContent}` (no grpc).
- User config: `~/.copilot/config.json`, override dir `COPILOT_HOME`.
- BYOK is env-only: `COPILOT_PROVIDER_BASE_URL`, `_TYPE` (openai|azure|anthropic), `_API_KEY`, `_BEARER_TOKEN`, `_WIRE_API`, `COPILOT_MODEL`. Not settable via managed settings, so gateway is not rendered (warning emitted).
- npm package `@github/copilot` (latest 1.0.89).
- **[UAT]** copilot 1.0.90 runs headless (`-p`) with BYOK env and no GitHub login, over `/v1/chat/completions` by default. The managed `telemetry` endpoint is honored (POSTs to `<endpoint>/v1/{metrics,traces}`), with no resource-attribute key (`OTEL_RESOURCE_ATTRIBUTES` env is honored). `allowedMcpServers` blocks a user server outside the list while an allowed one connects.

## Still UNVERIFIED
- Copilot `permissions.disableBypassPermissionsMode`: `copilot -p --allow-all` still starts (UAT); whether tool calls then require approval was not exercised. `model` (a default) was not observed.
- Copilot `sandbox` sub-keys were not mapped (permissions.sandbox is warned, not rendered).
