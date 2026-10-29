---
title: "Unit"
description: "A business unit or team in the org hierarchy (ADR-0018): delegated owners, a member selector and an overlay applied on top of the ring profile. Enforced security fields may only be tightened."
---

A business unit or team in the org hierarchy (ADR-0018): delegated owners, a member selector and an overlay applied on top of the ring profile. Enforced security fields may only be tightened.

Generated from `schemas/unit.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1 |  | Document version. |
| `description` | string |  |  |  |  | What the unit is. |
| `kind` | string | yes |  | const Unit |  | Document kind. |
| `labels` | object |  |  |  |  | Free-form labels. |
| `labels.*` | string |  |  |  |  |  |
| `members` | object | yes |  |  |  | Selects the unit's users from its parent's (any listed group or user matches). |
| `members.groups` | array of string |  |  |  |  | IdP groups. |
| `members.groups[]` | string |  |  |  |  |  |
| `members.users` | array of string |  |  |  |  | User ids. |
| `members.users[]` | string |  |  |  |  |  |
| `name` | string | yes |  |  | pattern ^[a-z0-9][a-zA-Z0-9._-]*$ | Unique name within its kind. |
| `overlay` | object |  |  |  |  | Profile settings the unit changes on top of the baseline. Lists in permissions.deny, mcp.denied and hooks.items union; mcp.servers are added; other lists replace; env and telemetry.attributes merge per key. |
| `overlay.agents` | object |  |  |  |  | Bounds delegated agents for this profile's members (ADR-0024). A unit overlay may only lower maxDepth and narrow remote. |
| `overlay.agents.maxDepth` | integer |  |  |  | minimum 1; maximum 5 | Lowers agents.maxDepth for these members. |
| `overlay.agents.remote` | array of string |  |  |  |  | agents.remote names these members may call; empty = every entry whose rings or units admit them. |
| `overlay.agents.remote[]` | string |  |  |  | minLength 1 |  |
| `overlay.egress` | object |  |  |  |  | Network egress for the agent's shell and fetch tools (ADR-0032). A deny rule wins over an allow rule; unmatched hosts take the default. Rendered natively per harness; what a harness cannot hold is a release warning. |
| `overlay.egress.allowedDomains` | array of string |  |  |  |  | Allowlist: exact hosts or *.domain (subdomains only, not the apex). Must allow the gateway host. Replaces the parent's list. |
| `overlay.egress.allowedDomains[]` | string |  |  |  | pattern ^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$ |  |
| `overlay.egress.default` | string |  |  | allow, deny |  | For hosts no rule matches. Unset: deny when allowedDomains or presets allow anything, else allow. allow with an allowlist is an error. |
| `overlay.egress.deniedDomains` | array of string |  |  |  |  | Always denied, even when an allow rule matches. Unions down an extends chain and across units. |
| `overlay.egress.deniedDomains[]` | string |  |  |  | pattern ^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$ |  |
| `overlay.egress.presets` | array of string |  |  |  |  | Named domain sets added to the allowlist (see the egress and sandbox guide for each set's hosts). |
| `overlay.egress.presets[]` | string |  |  | package-registries, vcs, model-providers |  |  |
| `overlay.env` | object |  |  |  |  | Extra environment; may add keys, never change an inherited one. |
| `overlay.env.*` | string |  |  |  |  |  |
| `overlay.hooks` | object |  |  |  |  | Hook policy. |
| `overlay.hooks.items` | array of object |  |  |  |  | Managed hooks. |
| `overlay.hooks.items[]` | object |  |  |  |  | A managed hook. |
| `overlay.hooks.items[].command` | string | yes |  |  |  | Command to run. |
| `overlay.hooks.items[].event` | string | yes |  | PreToolUse, PostToolUse, SessionStart, Stop, UserPromptSubmit |  | Hook event. |
| `overlay.hooks.items[].matcher` | string |  |  |  |  | Tool matcher. |
| `overlay.hooks.managedOnly` | boolean |  |  |  |  | Only managed hooks may run. |
| `overlay.instructions` | string |  |  |  |  | Appended to the inherited instructions (managed CLAUDE.md / AGENTS.md / GEMINI.md). |
| `overlay.mcp` | object |  |  |  |  | MCP policy. |
| `overlay.mcp.denied` | array of string |  |  |  |  | Denied server names. |
| `overlay.mcp.denied[]` | string |  |  |  |  |  |
| `overlay.mcp.managedOnly` | boolean |  |  |  |  | Block every server not listed. |
| `overlay.mcp.servers` | array of object |  |  |  |  | Allowed MCP servers. |
| `overlay.mcp.servers[]` | object |  |  |  |  | An allowed MCP server. |
| `overlay.mcp.servers[].auth` | object |  |  |  |  | How clients authorize to a remote server (ADR-0029). |
| `overlay.mcp.servers[].auth.clientID` | string |  |  |  |  | Pre-registered OAuth client id (oauth, enterprise). |
| `overlay.mcp.servers[].auth.clientIDMetadataURL` | string |  |  |  | format uri; pattern ^https:// | https URL of an org-hosted Client ID Metadata Document (oauth); the URL is the client id. |
| `overlay.mcp.servers[].auth.issuer` | string |  |  |  | format uri; pattern ^https:// | Authorization server issuer (oauth, enterprise). |
| `overlay.mcp.servers[].auth.mode` | string |  |  | none, oauth, enterprise, halos |  | none (default) \| oauth (the server's authorization server) \| enterprise (Enterprise-Managed Authorization: an ID-JAG from identity.issuer) \| halos (halo-server mints audience-bound tokens). |
| `overlay.mcp.servers[].auth.scopes` | array of string |  |  |  |  | Scopes to request (oauth, enterprise). |
| `overlay.mcp.servers[].auth.scopes[]` | string |  |  |  | pattern ^\S+$ |  |
| `overlay.mcp.servers[].command` | array of string |  |  |  |  | stdio command line (exclusive with url). |
| `overlay.mcp.servers[].command[]` | string |  |  |  |  |  |
| `overlay.mcp.servers[].headers` | object |  |  |  |  | HTTP headers. |
| `overlay.mcp.servers[].headers.*` | string |  |  |  |  |  |
| `overlay.mcp.servers[].name` | string | yes |  |  |  | Server name. |
| `overlay.mcp.servers[].tools` | object |  |  |  |  | Narrows the server's tools (ADR-0029). deny wins over allow; empty allow = every tool. |
| `overlay.mcp.servers[].tools.allow` | array of string |  |  |  |  | Only these tools (where the harness supports an allowlist; else a manifest warning). |
| `overlay.mcp.servers[].tools.allow[]` | string |  |  |  | pattern ^[A-Za-z0-9_.-]&#123;1,128}$ |  |
| `overlay.mcp.servers[].tools.deny` | array of string |  |  |  |  | Never these tools. |
| `overlay.mcp.servers[].tools.deny[]` | string |  |  |  | pattern ^[A-Za-z0-9_.-]&#123;1,128}$ |  |
| `overlay.mcp.servers[].url` | string |  |  |  | format uri | https URL (exclusive with command). |
| `overlay.models` | object |  |  |  |  | Model policy. |
| `overlay.models.allowed` | array of string |  |  |  |  | Allowed model aliases. |
| `overlay.models.allowed[]` | string |  |  |  |  |  |
| `overlay.models.default` | string |  |  |  |  | Default model alias (a gateway.models key). |
| `overlay.models.enforce` | boolean |  |  |  |  | Reject models outside allowed rather than only hiding them; default must then be in allowed. |
| `overlay.permissions` | object |  |  |  |  | Permission policy. |
| `overlay.permissions.allow` | array of string |  |  |  |  | Allow rules. |
| `overlay.permissions.allow[]` | string |  |  |  |  |  |
| `overlay.permissions.ask` | array of string |  |  |  |  | Ask rules. |
| `overlay.permissions.ask[]` | string |  |  |  |  |  |
| `overlay.permissions.deny` | array of string |  |  |  |  | Deny rules. |
| `overlay.permissions.deny[]` | string |  |  |  |  |  |
| `overlay.permissions.disableBypass` | boolean |  |  |  |  | Disable the harness's bypass-permissions mode. |
| `overlay.permissions.mode` | string |  |  | default, acceptEdits, plan, auto |  | Default permission mode. |
| `overlay.permissions.sandbox` | string |  |  | off, workspace-write, read-only |  | Harness sandbox policy. |
| `overlay.permissions.sandboxRequired` | boolean |  |  |  |  | Fail closed: the harness refuses to run (Claude: sandbox.failIfUnavailable) instead of running unsandboxed when its sandbox dependencies are missing. |
| `overlay.sandbox` | object |  |  |  |  | Agent sandbox (ADR-0032): mode, extra writable roots and paths the agent may never read or write. |
| `overlay.sandbox.mode` | string |  |  | off, workspace-write, read-only |  | Same setting as permissions.sandbox (set either; both must agree). off is an error while egress or sandbox paths are set. |
| `overlay.sandbox.protectedPaths` | array of string |  |  |  |  | Never read or written by the agent: absolute, ~/ or workspace-relative globs such as .env*. Unions down an extends chain and across units. |
| `overlay.sandbox.protectedPaths[]` | string |  |  |  | minLength 1 |  |
| `overlay.sandbox.writableRoots` | array of string |  |  |  |  | Absolute or ~/ directories writable beyond the workspace (no globs, not / or ~, not over a protected path). Replaces the parent's list; a unit adding one is a loosening. |
| `overlay.sandbox.writableRoots[]` | string |  |  |  | pattern ^(/\|~/) |  |
| `overlay.telemetry` | object |  |  |  |  | Telemetry policy. |
| `overlay.telemetry.attributes` | object |  |  |  |  | Extra resource attributes. |
| `overlay.telemetry.attributes.*` | string |  |  |  |  |  |
| `overlay.telemetry.enabled` | boolean |  |  |  |  | Emit OTEL telemetry. Must be true for profiles used by rings. |
| `overlay.telemetry.logPrompts` | boolean |  |  |  |  | Include prompt text in telemetry. |
| `overlay.telemetry.otlpEndpoint` | string |  |  |  |  | OTLP endpoint URL. |
| `overlay.telemetry.protocol` | string |  |  | grpc, http/protobuf |  | OTLP protocol. |
| `owners` | array of string | yes |  |  | minItems 1 | CODEOWNERS owners of the unit directory: @org/team, @user or an email. |
| `owners[]` | string |  |  |  | pattern ^(@[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)?\|[^@\s]+@[^@\s]+\.[^@\s]+)$ |  |
| `parent` | string |  |  |  |  | Enclosing unit; empty for a top-level unit. |
