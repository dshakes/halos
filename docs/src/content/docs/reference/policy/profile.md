---
title: "Profile"
description: "Desired harness behaviour, independent of any one CLI. Supports inheritance via extends."
---

Desired harness behaviour, independent of any one CLI. Supports inheritance via extends.

Generated from `schemas/profile.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1 |  | Document version. |
| `egress` | object |  |  |  |  | Egress policy. |
| `egress.allowedDomains` | array of string |  |  |  |  | Only egress permitted from managed environments; must include the gateway host when non-empty. |
| `egress.allowedDomains[]` | string |  |  |  |  |  |
| `env` | object |  |  |  |  | Extra environment applied to every harness. |
| `env.*` | string |  |  |  |  |  |
| `extends` | string |  |  |  |  | Parent profile. Scalars: child wins; lists: child replaces; maps: merged. |
| `harnesses` | object |  |  |  |  | Enabled harnesses keyed by adapter name (claude-code, codex, gemini-cli, copilot-cli). |
| `harnesses.*` | object |  |  |  |  | Harness settings. |
| `harnesses.*.model` | string |  |  |  |  | This harness's default model alias, replacing models.default for it (e.g. codex-default). Must be a gateway.models alias, and in models.allowed when enforce is set. |
| `harnesses.*.overrides` | object |  |  |  |  | Raw harness-native keys merged last (escape hatch; guardrails still apply). |
| `harnesses.*.version` | string | yes |  |  |  | Exact CLI version pin such as 2.1.280 (no ranges or latest); required for profiles used by rings. |
| `hooks` | object |  |  |  |  | Hook policy. |
| `hooks.items` | array of object |  |  |  |  | Managed hooks. |
| `hooks.items[]` | object |  |  |  |  | A managed hook. |
| `hooks.items[].command` | string | yes |  |  |  | Command to run. |
| `hooks.items[].event` | string | yes |  | PreToolUse, PostToolUse, SessionStart, Stop, UserPromptSubmit |  | Hook event. |
| `hooks.items[].matcher` | string |  |  |  |  | Tool matcher. |
| `hooks.managedOnly` | boolean |  |  |  |  | Only managed hooks may run. |
| `instructions` | string |  |  |  |  | Org-wide memory rendered as managed CLAUDE.md / AGENTS.md / GEMINI.md. |
| `kind` | string | yes |  | const Profile |  | Document kind. |
| `labels` | object |  |  |  |  | Free-form labels. |
| `labels.*` | string |  |  |  |  |  |
| `mcp` | object |  |  |  |  | MCP policy. |
| `mcp.denied` | array of string |  |  |  |  | Denied server names. |
| `mcp.denied[]` | string |  |  |  |  |  |
| `mcp.managedOnly` | boolean |  |  |  |  | Block every server not listed. |
| `mcp.servers` | array of object |  |  |  |  | Allowed MCP servers. |
| `mcp.servers[]` | object |  |  |  |  | An allowed MCP server. |
| `mcp.servers[].command` | array of string |  |  |  |  | stdio command line (exclusive with url). |
| `mcp.servers[].command[]` | string |  |  |  |  |  |
| `mcp.servers[].headers` | object |  |  |  |  | HTTP headers. |
| `mcp.servers[].headers.*` | string |  |  |  |  |  |
| `mcp.servers[].name` | string | yes |  |  |  | Server name. |
| `mcp.servers[].url` | string |  |  |  | format uri | https URL (exclusive with command). |
| `models` | object |  |  |  |  | Model policy. |
| `models.allowed` | array of string |  |  |  |  | Allowed model aliases. |
| `models.allowed[]` | string |  |  |  |  |  |
| `models.default` | string |  |  |  |  | Default model alias (a gateway.models key). |
| `models.enforce` | boolean |  |  |  |  | Reject models outside allowed rather than only hiding them; default must then be in allowed. |
| `name` | string | yes |  |  | pattern ^[a-z0-9][a-zA-Z0-9._-]*$ | Unique name within its kind. |
| `permissions` | object |  |  |  |  | Permission policy. |
| `permissions.allow` | array of string |  |  |  |  | Allow rules. |
| `permissions.allow[]` | string |  |  |  |  |  |
| `permissions.ask` | array of string |  |  |  |  | Ask rules. |
| `permissions.ask[]` | string |  |  |  |  |  |
| `permissions.deny` | array of string |  |  |  |  | Deny rules. |
| `permissions.deny[]` | string |  |  |  |  |  |
| `permissions.disableBypass` | boolean |  |  |  |  | Disable the harness's bypass-permissions mode. |
| `permissions.mode` | string |  |  | default, acceptEdits, plan, auto |  | Default permission mode. |
| `permissions.sandbox` | string |  |  | off, workspace-write, read-only |  | Harness sandbox policy. |
| `permissions.sandboxRequired` | boolean |  |  |  |  | Fail closed: the harness refuses to run (Claude: sandbox.failIfUnavailable) instead of running unsandboxed when its sandbox dependencies are missing. |
| `telemetry` | object |  |  |  |  | Telemetry policy. |
| `telemetry.attributes` | object |  |  |  |  | Extra resource attributes. |
| `telemetry.attributes.*` | string |  |  |  |  |  |
| `telemetry.enabled` | boolean |  |  |  |  | Emit OTEL telemetry. Must be true for profiles used by rings. |
| `telemetry.logPrompts` | boolean |  |  |  |  | Include prompt text in telemetry. |
| `telemetry.otlpEndpoint` | string |  |  |  |  | OTLP endpoint URL. |
| `telemetry.protocol` | string |  |  | grpc, http/protobuf |  | OTLP protocol. |
