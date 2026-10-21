---
title: Harness matrix
description: What each harness adapter renders, what Halos enforces instead, and where the files land. Generated from halo harnesses and internal/harness/FACTS.md.
---

The capability sets below are what `halo harnesses` prints (from each adapter's `Capabilities()`); the mechanisms and paths come from [`internal/harness/FACTS.md`](https://github.com/dshakes/halos/blob/main/internal/harness/FACTS.md), which cites the vendor page for every claim. Facts for the first four harnesses were last verified against vendor documentation on 2026-09-30; OpenCode and Cursor CLI on 2026-10-21 (see [ADR-0019](/halos/adr/0019-harness-coverage-beyond-the-big-four/)).

:::note[What was executed]
`make uat-clis` runs the real Claude Code 2.1.280, Codex 0.99.0, Gemini CLI 0.34.0 and Copilot CLI 1.0.90 against `halod`-applied config on every PR (`test/uat/CLI-REPORT.md`). Cells marked UNVERIFIED there, for example Copilot `disableBypassPermissionsMode` and Copilot gateway routing, are documentation-sourced only. Golden tests check the *rendered bytes*, not the CLI's behavior.

OpenCode 1.19.3 and Cursor CLI 2026.10.19 are **not** in `make uat-clis`. Their rows come from vendor docs, from the CLIs' own source or binaries, and from one-off runs of the real binaries (a recording server as the model endpoint for OpenCode; `--version` and `--help` for Cursor, which needs a login to run an agent). `internal/harness/FACTS.md` marks each claim and lists what is still UNVERIFIED.
:::

Legend: **Rendered** = the adapter writes the harness's native enforcement. **`halod`** = the CLI cannot enforce it, so Halos's agent installs the pinned version and reports drift. Root can stop `halod`, but on rings with `posture: enforce` the device then loses gateway access, and `versionGate: enforce` refuses CLI versions the ring does not pin (see [gateway gates](/halos/concepts/delivery/#gateway-gates)). **No** = not rendered; the adapter emits a warning in the release manifest rather than dropping the setting silently.

```bash
halo harnesses                 # table
halo harnesses --output json   # machine-readable
```

| Capability | Claude Code | Codex | Gemini CLI | Copilot CLI | Cursor CLI | OpenCode |
|---|---|---|---|---|---|---|
| Version pin | Rendered (`requiredMinimumVersion` / `requiredMaximumVersion`; the CLI refuses to start outside the range) | `halod` | `halod` | `halod` | `halod`, but its installer cannot pin a version, so `halod` cannot install it (warns) | `halod`; `autoupdate: false` is rendered so the CLI does not drift |
| Model lock | Rendered (`availableModels`, `enforceAvailableModels`; with a gateway, `modelOverrides` maps the built-in fallback for a disallowed `--model` to an alias. The CLI drops a disallowed `--model` silently, with no setting to refuse it) | Rendered | Rendered (`model.name`) | No: `models.default` only, users may override (warns) | No: dashboard (warns) | Rendered as a provider and model allowlist (`enabled_providers`, `provider.halos.models`) |
| MCP allowlist | Rendered (`allowManagedMcpServersOnly`) | Rendered (`requirements.toml` `mcp_servers.<id>.identity`; verified against OpenAI docs and schema) | Rendered (`mcp.allowed`) | Rendered (`allowedMcpServers`) | No: dashboard (warns) | No: OpenCode has no allowlist; `mcp.denied` disables by name and `mcp.servers` are rendered (warns) |
| Hooks lock | Rendered (`allowManagedHooksOnly`) | No | No | No | No: system `hooks.json` is rendered but runs alongside user and project hooks (warns) | No: hooks are plugins (warns) |
| Permissions | Rendered (`disableBypassPermissionsMode` plus rules) | Rendered (`allowed_approval_policies`, `allowed_sandbox_modes`) | Partial: `security.disableYoloMode` for `disableBypass`; not a declared capability in `halo harnesses` | Rendered (`permissions.disableBypassPermissionsMode: "disable"`); `permissions.mode` and `sandbox` are not (warns) | No: no system-wide location (warns) | Rendered (`permission` per tool, deny last; a global allow is never rendered). `disableBypass`, `mode` and `sandbox` are not (warns) |
| Gateway | Rendered (`ANTHROPIC_BASE_URL` / Bedrock env) | Rendered (`model_providers.<id>`) | Rendered as env via `/etc/profile.d` (login shells only) | **No**: BYOK is env-only and managed settings cannot set env (warns) | **No**: no base-URL override is documented (warns) | Rendered (`provider.halos.options.baseURL`; `anthropic-messages` or `openai-responses`) |
| Request headers (ring stamps) | Rendered (`ANTHROPIC_CUSTOM_HEADERS`) | Rendered (`http_headers`) | No | No | No | Rendered (`provider.halos.options.headers`) |
| Telemetry (OTEL) | Rendered | Rendered (`[otel]`) | Rendered | Rendered (`http/json`, `http/protobuf`; `grpc` warns and is not rendered) | No: dashboard (warns) | No (warns) |
| Instructions | Managed `CLAUDE.md` | No | No | No | No: team rules are dashboard-side (warns) | Rendered (`instructions` plus a managed file) |
| MCP denylist (`mcp.denied`) | Rendered (`deniedMcpServers`; by URL, a name warns) | No: `requirements.toml` has no denylist, so the allowlist is the control (warns) | Rendered (`mcp.excluded`, names only; a URL warns and is skipped) | Rendered (`deniedMcpServers`; by URL, a name warns) | No (warns) | Partial: each `mcp.denied` name is rendered as `enabled: false`; by name only, so a renamed server is not matched (warns) |
| Plugin marketplace allowlist (`extensions.marketplaces`) | Rendered (`strictKnownMarketplaces`) | Rendered (`requirements.toml` `[marketplaces]`; `github` and `git` become git rules, `hostPattern` a `host_pattern` rule; a `url` source warns) | No (warns) | Rendered (`strictKnownMarketplaces`) | No (warns) | No (warns) |
| Blocked marketplaces | Rendered (`blockedMarketplaces`) | No (warns) | No (warns) | No (warns) | No (warns) | No (warns) |
| Plugin pins (`extensions.plugins`) | Rendered (`enabledPlugins`; a managed `false` blocks install at every scope) | Partial: `plugins.<name>.enabled` in `managed_config.toml` is a default a trusted project can override (warns) | No (warns) | Rendered (`enabledPlugins`) | No (warns) | No (warns) |
| Skills deny | Rendered (`permissions.deny` `Skill(skill:NAME)`) | No (warns) | Rendered (`skills.disabled`) | No (warns) | No (warns) | No (warns) |
| Subagents deny | Rendered (`permissions.deny` `Agent(NAME)`) | No (warns) | Rendered (`agents.overrides.<name>.enabled: false`) | No (warns) | No (warns) | No (warns) |
| Skills / subagents plugin-only | Rendered (`strictPluginOnlyCustomization`) | No (warns) | No (warns) | No (warns) | No (warns) | No (warns) |
| Output style, status line | Rendered (`outputStyle`, `statusLine`) | No (warns) | No (warns) | No (warns) | No (warns) | No (warns) |
| Login restriction (`login`) | Rendered (`forceLoginMethod`: `claudeai` / `console`) | Rendered (`requirements.toml` `allowed_login_methods`: `chatgpt` / `api`) | Rendered (`security.auth.enforcedType`; `subscription` is not honored with a gateway, which needs `gemini-api-key`) | No (warns) | No (warns) | No (warns) |

Fields the adapters cannot render are listed by `halo render` and `halo release build` with warnings such as `gemini-cli: profile field "hooks.items" is not supported and was not rendered`.

## Where the files land

| Harness | macOS | Linux | Windows |
|---|---|---|---|
| Claude Code | `/Library/Application Support/ClaudeCode/` | `/etc/claude-code/` | `C:\Program Files\ClaudeCode\` |
| Codex | `/etc/codex/{requirements,managed_config}.toml` | `/etc/codex/` | `C:\ProgramData\OpenAI\Codex\requirements.toml` |
| Gemini CLI | `/Library/Application Support/GeminiCli/settings.json` | `/etc/gemini-cli/settings.json` | `C:\ProgramData\gemini-cli\settings.json` |
| Copilot CLI | `/Library/Application Support/GitHubCopilot/managed-settings.json` | `/etc/github-copilot/managed-settings.json` | `C:\Program Files\GitHubCopilot\managed-settings.json` |
| Cursor CLI | `/Library/Application Support/Cursor/hooks.json` | `/etc/cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` |
| OpenCode | `/Library/Application Support/opencode/{opencode.json,halos-instructions.md}` | `/etc/opencode/` | `C:\ProgramData\opencode\` |

`halod` writes only under these directories per harness (see [delivery](/halos/concepts/delivery/)). Copilot CLI is in the allowlist too (from its adapter's `harness.Meta`). On Linux, codex, gemini-cli and copilot-cli each also own one `/etc/profile.d/halos-<harness>.sh`. The first four were installed and applied by `halod` against the real CLIs in `make uat-clis`; Cursor CLI and OpenCode are not part of that run yet.

## Claude Code

| | |
|---|---|
| Server-managed settings | **Not fetched with Bedrock or a custom `ANTHROPIC_BASE_URL`.** Hence file, MDM or environment delivery |
| Files rendered | `managed-settings.json`, `managed-mcp.json`, `CLAUDE.md` |
| MDM | `com.anthropic.claudecode` plist, `HKLM\SOFTWARE\Policies\ClaudeCode` (used by `halo export jamf` and `intune`) |
| Sandbox | Does not run on native Windows; the adapter warns that sandbox and egress settings are not enforced there (use WSL2). `read-only` has no equivalent and renders as workspace-write; `off` is overridden when `egress.allowedDomains` is set |
| Telemetry | Eight OTEL metrics (for example `claude_code.cost.usage`, `claude_code.token.usage`, `claude_code.code_edit_tool.decision`) plus events; `OTEL_RESOURCE_ATTRIBUTES` carries `halo.ring`, `halo.release`, `halo.harness` |
| Headless (evals) | `claude -p --restricted --output-format stream-json --max-budget-usd` |
| Also | `mcp.denied` is matched by name only, which a user can bypass by renaming the server: deny by URL (warns) |

## Codex

| | |
|---|---|
| Requirements | `/etc/codex/requirements.toml` (Linux, macOS), `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows). Keys: `allowed_approval_policies`, `allowed_sandbox_modes`, `mcp_servers.<id>.identity.{command\|url}` (name and identity must both match; others are disabled) |
| Managed defaults | `/etc/codex/managed_config.toml` on Unix. **Windows has no system-wide path** (only `~/.codex`), so the adapter renders only `requirements.toml` there and warns that model, gateway, telemetry and MCP definitions are not rendered |
| Gateway | `model_providers.<id>` with `base_url`, `env_key`, `http_headers`. Codex speaks only the Responses wire API, so the gateway must too |
| Permissions | `approval_policy`: `on-request`, `never`, or granular; `untrusted` is unsupported and `on-failure` deprecated. `sandbox_mode` never renders `danger-full-access`; `off` maps to `workspace-write` (warns). A `permissions.mode` with no Codex equivalent maps to `on-request` (warns) |
| Telemetry | `[otel]` with `otlp-grpc` or `otlp-http` (protocol required for http; logs go to `<endpoint>/v1/logs`). No resource-attribute key, so on Linux `/etc/profile.d/halos-codex.sh` wraps `codex` with `OTEL_RESOURCE_ATTRIBUTES` (`halo.ring`, `halo.release`, `halo.harness`; login shells) |
| MDM | macOS domain `com.openai.codex` (`requirements_toml_base64`); **not rendered** by Halos |
| Headless (evals) | `codex exec --json` (JSONL events) |
| Version pin | None in the CLI; `halod` enforces (warns at render). requirements.toml is enforced from 0.77.0, and `codex exec` runs under it from 0.99.0 (warns below) |

## Gemini CLI

| | |
|---|---|
| Settings | System `settings.json`; override path with `GEMINI_CLI_SYSTEM_SETTINGS_PATH` |
| Keys | `model.name`, `mcp.allowed`, `telemetry.{enabled,target,otlpEndpoint,otlpProtocol,logPrompts}`, `security.disableYoloMode` (refuses YOLO), `security.auth.enforcedType: gemini-api-key` with a gateway. `admin.secureModeEnabled` in the system file is ignored (the admin block is remote-only) |
| Gateway | `GOOGLE_GEMINI_BASE_URL`, honored **only with gemini-api-key auth** and only over HTTPS or localhost. Settings cannot set env, so the adapter writes `/etc/profile.d/halos-gemini.sh` (login shells only: `GOOGLE_GEMINI_BASE_URL`, `GEMINI_API_KEY` from `gateway.auth.helperCommand`, and a `gemini` wrapper setting `OTEL_RESOURCE_ATTRIBUTES`) and warns |
| Headers | Not supported (warns) |
| Headless (evals) | `gemini -p` with `--output-format json` |
| Version pin | None in the CLI; `halod` enforces |

## Copilot CLI

| | |
|---|---|
| File | `managed-settings.json` (regular, root-owned, not group or world writable, non-symlink on macOS and Linux). Precedence: MDM over server-managed over file over user |
| Keys rendered | `model` (default only), `permissions.disableBypassPermissionsMode`, `allowedMcpServers`, `telemetry`. On Linux `/etc/profile.d/halos-copilot-cli.sh` wraps `copilot` with `OTEL_RESOURCE_ATTRIBUTES` |
| Gateway | Not rendered: BYOK (`COPILOT_PROVIDER_BASE_URL`, `COPILOT_PROVIDER_API_KEY`, `COPILOT_MODEL`) is env-only. Traffic is not routed through Halos |
| Verified (`make uat-clis`, 1.0.90) | `telemetry` endpoint and `allowedMcpServers` are honored by the CLI. **UNVERIFIED:** whether `disableBypassPermissionsMode` changes tool approval (`--allow-all` still starts); `model`; sandbox sub-keys are not mapped |
| `halod` delivery | Verified against the real Copilot CLI in `make uat-clis` |

## OpenCode

| | |
|---|---|
| File | `opencode.json` in the system managed directory, loaded at the highest precedence (above project config and `OPENCODE_CONFIG_CONTENT`). macOS MDM (`ai.opencode.managed`) is not rendered |
| Keys rendered | `provider.halos` (`npm`, `options.{baseURL,apiKey,headers}`, `models`), `enabled_providers: ["halos"]`, `model`, `permission` (`bash`, `read`, `edit`, `glob`, `grep`, `task`, `external_directory`), `mcp` (servers, and `enabled: false` for `mcp.denied`), `instructions`, `autoupdate: false` when the profile pins a version |
| Gateway | `@ai-sdk/anthropic` (`/v1/messages`) or `@ai-sdk/openai` (`/v1/responses`), chosen by `gateway.protocols.opencode` (default `anthropic-messages`); `bedrock-invoke` and `gemini` are refused. The credential is `{env:HALO_GATEWAY_TOKEN}` |
| Permissions | `bash` and `edit` start from `ask` once they have a rule; order is allow, ask, deny, last match wins. Home and absolute paths go to `external_directory`. A global allow is never rendered, and the release check rejects it |
| Not enforceable | **`OPENCODE_PERMISSION` (an environment variable) overrides the managed permission block**, and `--auto` approves every ask (explicit deny still holds). OpenCode has no MCP allowlist: user servers still load. Both warn |
| User-Agent | `opencode/<version> ai-sdk/...`: the gateway's UA map and version gate recognise it |
| Headless (verify) | `opencode run "<message>"` |

## Cursor CLI

| | |
|---|---|
| File | System `hooks.json` (the CLI's enterprise hooks path) with `preToolUse`, `postToolUse`, `sessionStart`, `stop` and `beforeSubmitPrompt` hooks from `hooks.items`. Claude-style tool matchers map to Cursor's (`Bash` to `Shell`, `Edit` to `Write`); a tool with no Cursor type skips that hook and warns |
| Not rendered | Permissions (`~/.cursor/cli-config.json`, project `.cursor/cli.json`), MCP (`mcp.json`), models, rules, telemetry: per-user files or dashboard settings with no root-owned location. Gateway: the CLI documents no base-URL override. All warn |
| Install | `https://cursor.com/install` takes no version argument, so `halod` cannot install a pinned version; `halo doctor` still detects `cursor-agent` and its version |
| User-Agent | None documented, so the gateway cannot map it |
| Headless (verify) | `cursor-agent -p "<message>"` (never `--force`, `--yolo` or `--trust`) |

## Kong notes

- `ai-proxy` supports `llm_format: anthropic` passthrough.
- `ai-proxy-advanced` (load balancing) is Enterprise-only.
- OSS Kong has no request-mirroring plugin; `halo-shadow` fills the gap.
