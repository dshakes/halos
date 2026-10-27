---
title: "ADR-0029: MCP registry and authorization"
description: halos.yaml lists the MCP servers the org approves, pinned to a URL or an exact package version, with tool lists, an authorization mode and the rings and units that get each. Releases render the registry into every harness's native MCP settings; halod reports unapproved and drifted servers; halo-server mints audience-bound tokens for servers whose authorization server is Halos.
status: accepted
date: 2026-10-27
---

# ADR-0029: MCP registry and authorization

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

Profiles already list MCP servers (`mcp.servers`) and every adapter renders them, but nothing says which servers the org approves, at which version, with which tools, or how a client authenticates to a remote one. A server added by hand in `~/.claude.json` runs unseen, `npx some-mcp` floats to whatever `latest` is today, and the usual way to authenticate a remote server is a long-lived personal token pasted into a header.

Can Halos hold one registry of approved servers, deliver it to all six harnesses through their own mechanisms, notice when a machine strays from it, and give remote servers short-lived credentials bound to that one server?

## Vendor research (checked 2026-10-27)

Primary sources only, recorded in [`internal/harness/FACTS.md`](https://github.com/dshakes/halos/blob/main/internal/harness/FACTS.md) under "MCP registry (ADR-0029)". Not exercised against a running CLI in this change: UNVERIFIED beyond the documents.

| Harness | Server allowlist | Tool allow / deny | OAuth client | Per-connection credential helper |
|---|---|---|---|---|
| Claude Code | `allowManagedMcpServersOnly` + `allowedMcpServers` (URL/command), fail-closed[^c1] | deny: permission rule `mcp__<server>__<tool>`; no allowlist (a deny always wins)[^c2] | `oauth.clientId`, `oauth.scopes` in `managed-mcp.json`[^c1] | `headersHelper`, run for managed servers with the user's environment[^c1] |
| Codex | `requirements.toml` `mcp_servers.<id>.identity` (name and URL/command must match)[^o1] | `enabled_tools`, `disabled_tools`[^o2] | `oauth`, `scopes`, `auth = "ema_auth"` in the schema; `mcp_servers` rejects unknown keys, so not rendered[^o2] | `http_headers_helper` in the schema; not rendered (same reason) |
| Gemini CLI | `mcp.allowed` / `mcp.excluded` by name only[^g1] | `includeTools`, `excludeTools`; exclude wins; inclusions intersect and exclusions union across settings files[^g2] | `oauth.enabled`, `clientId`, `issuer`, `scopes`[^g2] | none (static `headers`) |
| Copilot CLI | `allowedMcpServers` / `deniedMcpServers` (serverUrl/serverCommand), intersected across sources, fail-closed[^h1] | none in managed settings | none in managed settings (definitions are per-user) | none |
| Cursor CLI | dashboard only; no root-owned file[^u1] | `Mcp(server:tool)` in per-user `cli-config.json` only | none | none |
| OpenCode | none: a managed `enabled: false` disables by name; unlisted user servers still start | `tools.<server>_<tool>: false` (documented; the schema marks `tools` deprecated)[^p1] | `oauth.clientId`, `oauth.scope`[^p1] | none (`{env:VAR}` headers are fixed per process) |

The MCP specification's authorization (OAuth 2.1, RFC 9728 protected-resource metadata, RFC 8707 resource indicators, Client ID Metadata Documents) and the Enterprise-Managed Authorization extension (an ID-JAG from the org IdP) are client features. None of the six CLIs documents a setting for an org-hosted Client ID Metadata Document or for Enterprise-Managed Authorization; Codex's schema has `auth = "ema_auth"` with no documentation of what it reads.

## Decision drivers

- Invariant 1: nothing rendered here touches permission modes.
- Invariant 2: a tool list or auth mode a harness cannot express warns in the manifest, per server; `TestNoSilentDrop` covers `mcp.tools.allow`, `mcp.tools.deny` and `mcp.auth`.
- Invariant 6: the registry is policy; releases stay immutable and content-addressed. A registry change is a new release.
- Fail closed where the vendor can: allowlists match URL or the exact pinned command line, so a drifted version is blocked, not just reported.
- No token passthrough: a Halos credential is never sent to an MCP server, and a token minted for one server is useless at another and at the gateway.
- No new dependencies; `halo mcp registry import` only reads.

## Considered options

1. **A registry in `halos.yaml`, rendered through the adapters, with drift in halod and tokens from halo-server.** Chosen.
2. **Proxy every MCP connection through a Halos MCP gateway.** Rejected for now: stdio servers run on the laptop, five of six CLIs can already enforce an allowlist locally, and a proxy is a new always-on hop holding every tool result.
3. **Profiles only, no registry.** Rejected: profiles and units cannot express "approved but not enabled here", and nothing pins versions.

## Decision outcome

### Policy

```yaml
mcp:
  mode: allowlist            # default; warn = render, block nothing else, report drift
  servers:
    - id: wiki               # name in every harness; no '_' or '.' (harnesses join it into tool names)
      url: https://mcp-wiki.internal.acme.example/mcp
      rings: [ring0-harness-team, ring1-canary]
      units: [payments]      # members of these units, and units below them
      tools: {allow: [search, fetch], deny: [delete_page]}
      auth: {mode: halos}    # none | oauth | enterprise | halos
    - id: playwright
      registryName: io.github.microsoft/playwright-mcp
      version: 0.0.82
      package: {type: npm, identifier: "@playwright/mcp", version: 0.0.82}
      rings: [ring0-harness-team]
```

Exactly one transport: `url` (https), `package` (`npm` and `pypi` need an exact version, never a range or `latest`; `oci` needs the image digest; the command line is derived: `npx -y pkg@ver`, `uvx pkg==ver`, `docker run -i --rm image@sha256:...`), or `command` with a `binary` package and its digest. A bare `command` warns that it is unpinned. Header values must be `${VAR}` references, never literal secrets. Rings and units both empty means approved but delivered by nobody (a toggle may deliver it).

In `allowlist` mode, profiles, unit overlays and toggles may only name registry servers, and a toggle must carry the registry's own URL or command. A profile may not redefine a registry server. An unknown mode fails closed (treated as allowlist, and an error). Errors under `mcp` are security issues: halo-server and the gateways refuse to load such a policy.

`halo mcp registry import <name|https-url|file>` reads the official MCP Registry `server.json` (a name is fetched read-only from `/v0/servers/<name>/versions/latest`) and prints a pinned entry, with notes for what it does not carry (arguments, required environment, headers, rings).

### Rendering

`release.Build` adds the servers a ring gets to the ring profile before rendering, and each unit's servers to that unit's profile; in allowlist mode it also sets `mcp.managedOnly`. The adapters then render as in the table above. What a harness cannot express warns, per server: Claude Code `tools.allow`; Codex auth and, on Windows, every server definition; Gemini auth modes other than oauth; Copilot tool lists and auth; Cursor everything; OpenCode `tools.allow`, issuer, Client ID Metadata Documents, enterprise and halos auth.

The manifest carries `mcpMode` and the pinned servers (`mcpServers`: id, URL or command, package, and the units a unit-limited server is for), signed with the release.

### Drift

`halod` reads the console user's own configs for the harnesses the release ships (`~/.claude.json` including `projects.*`, `~/.codex/config.toml`, `~/.gemini/settings.json`, `~/.copilot/mcp-config.json`, `~/.cursor/mcp.json`, `~/.config/opencode/opencode.json`) and reports in its status `mcpDrift`: **unapproved** (no pin for this device's ring or unit chain matches the name or the definition) and **version-drift** (the name matches a pin, the URL or command line does not), each with a fix hint. It never edits user files. Disabled servers are skipped. Project `.mcp.json` files are not scanned (halod does not know the user's projects).

### Authorization

| `auth.mode` | Meaning | Rendered |
|---|---|---|
| `none` | no client authorization (or `${VAR}` headers) | headers only |
| `oauth` | the server's own authorization server; `clientID` pre-registered, or `clientIDMetadataURL` (an org-hosted Client ID Metadata Document, the URL is the client id); `issuer`, `scopes` | Claude Code, Gemini CLI, OpenCode client id and scopes (Gemini also issuer); the rest warn |
| `enterprise` | Enterprise-Managed Authorization: an ID-JAG from `identity.issuer` traded at the server's authorization server; needs `identity.issuer` | warns everywhere: no CLI documents a client for it (UNVERIFIED for Codex's `ema_auth`) |
| `halos` | halo-server is the server's authorization server | Claude Code `headersHelper: halo mcp token --resource <url> --format headers`; the rest warn |

For mode `halos`, `POST /api/v1/token/exchange` with `resource=<server URL>` and a Halos credential (a `halo_session`, a workload credential from ADR-0023, or a delegated agent credential from ADR-0024) as `subject_token` mints a `halo-mcp+jwt`: EdDSA with the workload key, `aud` the server's canonical URL (RFC 8707: https, lowercase host, no default port, query, fragment or trailing slash), `sub` and `groups` of the root principal, `actors` of the delegation chain, `mcp_server` the registry id, at most 5 minutes and never past the subject token. It is minted only when the server is in the registry with mode `halos` and enabled for the caller's ring or unit (from the verified credential, never from the request), and both outcomes are audited (`mcp.token.exchange`, `mcp.token.denied`). An `actor_id` is refused: an agent asks with its own delegated credential. Failed authentications share the delegation limiter.

Gateways never accept the token (its `typ` is neither workload nor delegated), and the caller's credential goes only to halo-server: no passthrough. A Go MCP server verifies with `identity.VerifyMCPToken(keys, token, itsOwnURL, now)` against halo-server's workload public key (the PEM gateways already trust); other servers check the same claims. Halos does not publish RFC 9728 metadata for the server or a JWKS endpoint: the server's operator configures the key.

### What was not built

- Gateway enforcement of `tools.deny` on model calls (the tool names are client-qualified: `mcp__<server>__<tool>` in Claude Code, `<server>_<tool>` elsewhere). The harness renders are the control; a gateway check is a follow-up.
- A Halos MCP proxy (option 2).
- Rendering Enterprise-Managed Authorization or Client ID Metadata Documents into any CLI: no documented setting.

## Consequences

- Good: one place approves MCP servers and pins their versions; five of six harnesses block what is not in it on machines that apply the release (Cursor is dashboard-only and warns).
- Good: remote servers can use 5-minute, single-audience tokens instead of personal access tokens, attributed to the person and agent chain, revocable by revoking the session.
- Bad: Gemini CLI and OpenCode cannot run a credential helper, so `auth: halos` works only in Claude Code today. Codex's schema suggests `http_headers_helper` and `ema_auth`; rendering them waits for a pinned version that is verified to accept the keys.
- Bad: drift is reported, not repaired; and project-scoped configs are not seen.
- Neutral: no CLI was run against the rendered MCP files in this change (UNVERIFIED); goldens pin the rendered shapes to the documented ones.

## More information

`internal/policy/mcp.go`, `internal/policy/mcpimport.go`, `internal/harness/*`, `internal/release/release.go`, `cmd/halod/mcpdrift.go`, `internal/server/mcptoken.go`, `internal/identity/mcptoken.go`, `cmd/halo/cmd_mcp_registry.go`; [MCP registry guide](/halos/guides/mcp-registry/).

[^c1]: https://code.claude.com/docs/en/mcp and https://code.claude.com/docs/en/managed-mcp (checked 2026-10-27)
[^c2]: https://code.claude.com/docs/en/permissions (checked 2026-10-27)
[^o1]: https://learn.chatgpt.com/docs/enterprise/managed-configuration (checked 2026-10-21, FACTS.md)
[^o2]: https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json (`RawMcpServerConfig`, `additionalProperties: false`; checked 2026-10-27)
[^g1]: https://geminicli.com/docs/reference/configuration/ (checked 2026-10-21, FACTS.md)
[^g2]: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md (checked 2026-10-27)
[^h1]: https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings (checked 2026-10-27)
[^u1]: https://cursor.com/docs/enterprise/security-hardening.md (checked 2026-10-21, FACTS.md)
[^p1]: https://opencode.ai/docs/mcp-servers/ and https://opencode.ai/config.json (checked 2026-10-27)
