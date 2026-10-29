---
title: "Profile"
description: "Desired harness behaviour, independent of any one CLI. Supports inheritance via extends."
---

Desired harness behaviour, independent of any one CLI. Supports inheritance via extends.

Generated from `schemas/profile.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `agents` | object |  |  |  |  | Bounds delegated agents for this profile's members (ADR-0024). A unit overlay may only lower maxDepth and narrow remote. |
| `agents.maxDepth` | integer |  |  |  | minimum 1; maximum 5 | Lowers agents.maxDepth for these members. |
| `agents.remote` | array of string |  |  |  |  | agents.remote names these members may call; empty = every entry whose rings or units admit them. |
| `agents.remote[]` | string |  |  |  | minLength 1 |  |
| `apiVersion` | string | yes |  | const halos.dev/v1 |  | Document version. |
| `egress` | object |  |  |  |  | Network egress for the agent's shell and fetch tools (ADR-0032). A deny rule wins over an allow rule; unmatched hosts take the default. Rendered natively per harness; what a harness cannot hold is a release warning. |
| `egress.allowedDomains` | array of string |  |  |  |  | Allowlist: exact hosts or *.domain (subdomains only, not the apex). Must allow the gateway host. Replaces the parent's list. |
| `egress.allowedDomains[]` | string |  |  |  | pattern ^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$ |  |
| `egress.default` | string |  |  | allow, deny |  | For hosts no rule matches. Unset: deny when allowedDomains or presets allow anything, else allow. allow with an allowlist is an error. |
| `egress.deniedDomains` | array of string |  |  |  |  | Always denied, even when an allow rule matches. Unions down an extends chain and across units. |
| `egress.deniedDomains[]` | string |  |  |  | pattern ^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$ |  |
| `egress.presets` | array of string |  |  |  |  | Named domain sets added to the allowlist (see the egress and sandbox guide for each set's hosts). |
| `egress.presets[]` | string |  |  | package-registries, vcs, model-providers |  |  |
| `env` | object |  |  |  |  | Extra environment applied to every harness. |
| `env.*` | string |  |  |  |  |  |
| `extends` | string |  |  |  |  | Parent profile. Scalars: child wins; lists: child replaces; maps: merged. |
| `extensions` | object |  |  |  |  | Plugin, skill, subagent, output style and status line governance. Unset means unrestricted; each adapter renders what its harness can enforce and warns about the rest. |
| `extensions.artifacts` | array of string |  |  |  |  | Supply-chain artifacts (halos.yaml supplyChain.artifacts names) this profile delivers (ADR-0028). Claude Code places skills, agents, commands and hooks in its managed directory; other adapters warn. |
| `extensions.artifacts[]` | string |  |  |  | minLength 1 |  |
| `extensions.blockedMarketplaces` | array of object |  |  |  |  | Marketplace sources users may never use (Claude Code blockedMarketplaces). Unions down an extends chain. |
| `extensions.blockedMarketplaces[]` | object |  |  |  |  | A plugin marketplace source. |
| `extensions.blockedMarketplaces[].hostPattern` | string |  |  |  |  | Regular expression over marketplace hosts (source hostPattern). |
| `extensions.blockedMarketplaces[].ref` | string |  |  |  |  | Branch or tag (sources github and git). |
| `extensions.blockedMarketplaces[].repo` | string |  |  |  | pattern ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ | OWNER/REPO (source github). |
| `extensions.blockedMarketplaces[].source` | string | yes |  | github, git, url, hostPattern |  | Source kind. |
| `extensions.blockedMarketplaces[].url` | string |  |  |  | format uri | Repository or marketplace.json URL (sources git and url). |
| `extensions.marketplaces` | array of object |  |  |  |  | Allowlist of plugin marketplace sources (Claude Code strictKnownMarketplaces, Codex marketplaces.allowed_sources, Copilot strictKnownMarketplaces); empty means any. The vendor's own marketplace is blocked unless listed. |
| `extensions.marketplaces[]` | object |  |  |  |  | A plugin marketplace source. |
| `extensions.marketplaces[].hostPattern` | string |  |  |  |  | Regular expression over marketplace hosts (source hostPattern). |
| `extensions.marketplaces[].ref` | string |  |  |  |  | Branch or tag (sources github and git). |
| `extensions.marketplaces[].repo` | string |  |  |  | pattern ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ | OWNER/REPO (source github). |
| `extensions.marketplaces[].source` | string | yes |  | github, git, url, hostPattern |  | Source kind. |
| `extensions.marketplaces[].url` | string |  |  |  | format uri | Repository or marketplace.json URL (sources git and url). |
| `extensions.outputStyle` | string |  |  |  |  | Output style name (Claude Code outputStyle). |
| `extensions.plugins` | object |  |  |  |  | Individual plugin pins, keyed PLUGIN@MARKETPLACE. |
| `extensions.plugins.blocked` | array of string |  |  |  |  | Plugins required off. Unions down an extends chain. |
| `extensions.plugins.blocked[]` | string |  |  |  | pattern ^[^@\s]+@[^@\s]+$ |  |
| `extensions.plugins.enabled` | array of string |  |  |  |  | Plugins required on. |
| `extensions.plugins.enabled[]` | string |  |  |  | pattern ^[^@\s]+@[^@\s]+$ |  |
| `extensions.skills` | object |  |  |  |  | Governance for a user-authored extension kind. |
| `extensions.skills.deny` | array of string |  |  |  |  | Names that must not load. Unions down an extends chain. |
| `extensions.skills.deny[]` | string |  |  |  |  |  |
| `extensions.skills.pluginOnly` | boolean |  |  |  |  | Allow only extensions delivered by plugins or managed settings; user and project sources are blocked (Claude Code strictPluginOnlyCustomization). |
| `extensions.statusLine` | object |  |  |  |  | Managed status-line command (Claude Code statusLine). |
| `extensions.statusLine.command` | string |  |  |  |  | Command that renders the status line. |
| `extensions.statusLine.padding` | integer |  |  |  | minimum 0 | Horizontal padding in characters; requires command. |
| `extensions.subagents` | object |  |  |  |  | Governance for a user-authored extension kind. |
| `extensions.subagents.deny` | array of string |  |  |  |  | Names that must not load. Unions down an extends chain. |
| `extensions.subagents.deny[]` | string |  |  |  |  |  |
| `extensions.subagents.pluginOnly` | boolean |  |  |  |  | Allow only extensions delivered by plugins or managed settings; user and project sources are blocked (Claude Code strictPluginOnlyCustomization). |
| `harnesses` | object |  |  |  |  | Enabled harnesses keyed by adapter name (claude-code, codex, gemini-cli, copilot-cli, cursor-agent, opencode). |
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
| `login` | string |  |  | subscription, api |  | Restrict how users authenticate: subscription (claude.ai, ChatGPT or Google login) or api (API key or gateway credential). Unset means unrestricted. |
| `mcp` | object |  |  |  |  | MCP policy. |
| `mcp.denied` | array of string |  |  |  |  | Denied server names. |
| `mcp.denied[]` | string |  |  |  |  |  |
| `mcp.managedOnly` | boolean |  |  |  |  | Block every server not listed. |
| `mcp.servers` | array of object |  |  |  |  | Allowed MCP servers. |
| `mcp.servers[]` | object |  |  |  |  | An allowed MCP server. |
| `mcp.servers[].auth` | object |  |  |  |  | How clients authorize to a remote server (ADR-0029). |
| `mcp.servers[].auth.clientID` | string |  |  |  |  | Pre-registered OAuth client id (oauth, enterprise). |
| `mcp.servers[].auth.clientIDMetadataURL` | string |  |  |  | format uri; pattern ^https:// | https URL of an org-hosted Client ID Metadata Document (oauth); the URL is the client id. |
| `mcp.servers[].auth.issuer` | string |  |  |  | format uri; pattern ^https:// | Authorization server issuer (oauth, enterprise). |
| `mcp.servers[].auth.mode` | string |  |  | none, oauth, enterprise, halos |  | none (default) \| oauth (the server's authorization server) \| enterprise (Enterprise-Managed Authorization: an ID-JAG from identity.issuer) \| halos (halo-server mints audience-bound tokens). |
| `mcp.servers[].auth.scopes` | array of string |  |  |  |  | Scopes to request (oauth, enterprise). |
| `mcp.servers[].auth.scopes[]` | string |  |  |  | pattern ^\S+$ |  |
| `mcp.servers[].command` | array of string |  |  |  |  | stdio command line (exclusive with url). |
| `mcp.servers[].command[]` | string |  |  |  |  |  |
| `mcp.servers[].headers` | object |  |  |  |  | HTTP headers. |
| `mcp.servers[].headers.*` | string |  |  |  |  |  |
| `mcp.servers[].name` | string | yes |  |  |  | Server name. |
| `mcp.servers[].tools` | object |  |  |  |  | Narrows the server's tools (ADR-0029). deny wins over allow; empty allow = every tool. |
| `mcp.servers[].tools.allow` | array of string |  |  |  |  | Only these tools (where the harness supports an allowlist; else a manifest warning). |
| `mcp.servers[].tools.allow[]` | string |  |  |  | pattern ^[A-Za-z0-9_.-]&#123;1,128}$ |  |
| `mcp.servers[].tools.deny` | array of string |  |  |  |  | Never these tools. |
| `mcp.servers[].tools.deny[]` | string |  |  |  | pattern ^[A-Za-z0-9_.-]&#123;1,128}$ |  |
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
| `sandbox` | object |  |  |  |  | Agent sandbox (ADR-0032): mode, extra writable roots and paths the agent may never read or write. |
| `sandbox.mode` | string |  |  | off, workspace-write, read-only |  | Same setting as permissions.sandbox (set either; both must agree). off is an error while egress or sandbox paths are set. |
| `sandbox.protectedPaths` | array of string |  |  |  |  | Never read or written by the agent: absolute, ~/ or workspace-relative globs such as .env*. Unions down an extends chain and across units. |
| `sandbox.protectedPaths[]` | string |  |  |  | minLength 1 |  |
| `sandbox.writableRoots` | array of string |  |  |  |  | Absolute or ~/ directories writable beyond the workspace (no globs, not / or ~, not over a protected path). Replaces the parent's list; a unit adding one is a loosening. |
| `sandbox.writableRoots[]` | string |  |  |  | pattern ^(/\|~/) |  |
| `telemetry` | object |  |  |  |  | Telemetry policy. |
| `telemetry.attributes` | object |  |  |  |  | Extra resource attributes. |
| `telemetry.attributes.*` | string |  |  |  |  |  |
| `telemetry.enabled` | boolean |  |  |  |  | Emit OTEL telemetry. Must be true for profiles used by rings. |
| `telemetry.logPrompts` | boolean |  |  |  |  | Include prompt text in telemetry. |
| `telemetry.otlpEndpoint` | string |  |  |  |  | OTLP endpoint URL. |
| `telemetry.protocol` | string |  |  | grpc, http/protobuf |  | OTLP protocol. |
