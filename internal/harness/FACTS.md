# Harness facts (verified 2026-09-30)

Every claim was read from the cited source. Not run against real CLIs.

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
- Model provider: `base_url, env_key, http_headers, wire_api, name` (S).
- `codex exec`: `--json`, `--sandbox/-s`, `-m/--model`, `--skip-git-repo-check`, `-` reads prompt from stdin (X). JSONL events `thread.started`, `turn.completed{usage.input_tokens,output_tokens}`, `turn.failed{error.message}`, `error`, `item.completed{item.type=command_execution, exit_code}` (exec_events.rs).
- npm package `@openai/codex` (registry latest 0.159.2).

## Gemini CLI
Sources: E = https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/enterprise.md,
C = .../docs/reference/configuration.md, H = .../docs/cli/headless.md, packages/core/src/output/types.ts, packages/core/src/telemetry/uiTelemetry.ts.

- System settings: Linux `/etc/gemini-cli/settings.json`, Windows `C:\ProgramData\gemini-cli\settings.json`, macOS `/Library/Application Support/GeminiCli/settings.json`; override `GEMINI_CLI_SYSTEM_SETTINGS_PATH` (E, C).
- Keys: `model.name` (string), `mcp.allowed`/`mcp.excluded` (arrays), `tools.core` (allowlist), `tools.exclude`, `tools.allowed`, `admin.secureModeEnabled` (disallows YOLO/"Always allow"), `admin.mcp.*`; `mcpServers.<n>.{command,args,url,httpUrl,headers}`; `telemetry.{enabled,target=local|gcp,otlpEndpoint,otlpProtocol=grpc|http,logPrompts}` (C). We now render `admin.secureModeEnabled` for `permissions.disableBypass`.
- `GOOGLE_GEMINI_BASE_URL`: only honored with gemini-api-key auth; HTTPS or localhost only (C).
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

## Still UNVERIFIED
- Which managed-settings.json keys Copilot CLI (vs VS Code/app) honors: the support matrix columns were not readable in the fetched text. Telemetry, `permissions.disableBypassPermissionsMode`, and sandbox are stated to cover the CLI; `allowedMcpServers`/`model` CLI support is assumed.
- Copilot `sandbox` sub-keys were not mapped (permissions.sandbox is warned, not rendered).
- Nothing was executed against real CLIs; codex `--sandbox workspace-write` on an unmanaged (non-git) workdir may need `--skip-git-repo-check`.
