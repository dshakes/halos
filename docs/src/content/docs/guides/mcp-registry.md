---
title: MCP registry and authorization
description: Approve MCP servers once, pinned to a URL or an exact version, deliver them to every harness by ring and unit, see who strays, and give remote servers 5-minute tokens instead of personal access tokens.
---

`halos.yaml` `mcp` is the list of MCP servers your org approves ([ADR-0029](/halos/adr/0029-mcp-registry-and-authorization/)). Releases render each ring's and unit's servers into every harness's native MCP settings, `halod` reports servers on machines that are not in it, and halo-server can be the authorization server for your own remote servers.

## 1. Import a server

```sh
halo mcp registry import io.github.microsoft/playwright-mcp
```

```yaml
# add under mcp.servers in halos.yaml:
- id: playwright-mcp
  registryName: io.github.microsoft/playwright-mcp
  version: 0.0.82
  package:
    type: npm
    identifier: '@playwright/mcp'
    version: 0.0.82
```

The argument is a name in the [official MCP Registry](https://registry.modelcontextprotocol.io) (fetched read-only), an https URL serving a `server.json`, or a local file. `--remote` pins the streamable-HTTP endpoint instead of the package; an OCI package needs `--sha256` with the image digest. Notes on stderr list what the entry does not carry: arguments, required environment variables, headers. Nothing is written.

## 2. Add it to policy

```yaml
# halos.yaml
mcp:
  mode: allowlist          # default. warn: render, block nothing else, report drift
  servers:
    - id: playwright-mcp
      package: {type: npm, identifier: "@playwright/mcp", version: 0.0.82}
      rings: [ring0-harness-team]
    - id: wiki
      url: https://mcp-wiki.internal.acme.example/mcp
      rings: [ring1-canary, ring2-early, ring3-ga]
      units: [payments]    # also members of payments and units below it
      tools:
        allow: [search, fetch]
        deny: [delete_page]
      auth: {mode: halos}
```

`halo validate` checks the pins (exact versions only, image digests, https URLs, `${VAR}` header values), that rings and units exist, and in `allowlist` mode that profiles, unit overlays and toggles name only registry servers. Ship it like any policy change: `halo plan`, a ring rollout, eval gates.

Moving from `mcp.servers` in a profile: list the servers in the registry with the profile's rings, delete them from the profile, then drop `mode: warn`.

## 3. What each harness gets

| | Server allowlist | Tool lists | Auth |
|---|---|---|---|
| Claude Code | `allowManagedMcpServersOnly` + `allowedMcpServers` | deny only | `oauth`; `halos` via `headersHelper` |
| Codex | `requirements.toml` identities | allow and deny | warns |
| Gemini CLI | `mcp.allowed` (names) | allow and deny | `oauth` |
| Copilot CLI | `allowedMcpServers` | warns | warns |
| Cursor CLI | warns (dashboard) | warns | warns |
| OpenCode | warns (no allowlist) | deny only | `oauth` |

Everything a harness cannot express is a warning in the release manifest; `halo plan` shows them. Details and sources: [harness matrix](/halos/reference/harness-matrix/).

## 4. Drift

Each `halod` cycle reads the console user's own MCP configs for the harnesses the release ships and reports in its status:

```json
"mcpDrift": [
  {"harness": "claude-code", "file": "/Users/dev/.claude.json", "server": "playwright", "kind": "version-drift",
   "detail": "defined as npx -y @playwright/mcp@latest; the registry pins npx -y @playwright/mcp@0.0.82",
   "fix": "change \"playwright\" to npx -y @playwright/mcp@0.0.82, or remove it (the managed config already provides it)"},
  {"harness": "codex", "file": "/Users/dev/.codex/config.toml", "server": "scraper", "kind": "unapproved", ...}
]
```

`halod` never edits user files. Project `.mcp.json` files are not scanned.

## 5. Halos as the authorization server

For a server you run, `auth: {mode: halos}` makes halo-server mint its tokens: 5 minutes at most, `aud` the server's URL, `sub` the person (and `actors` the agent chain, when an agent asks). The caller's own credential is sent only to halo-server.

Claude Code gets a `headersHelper` that runs, on every connection:

```sh
halo mcp token --resource https://mcp-wiki.internal.acme.example/mcp --format headers
# {"Authorization":"Bearer eyJ..."}
```

It needs `HALO_SERVER` and `HALO_SESSION` (or, in CI, `HALO_GATEWAY_TOKEN` from `halo ci token`) in the user's environment, and `halo-server --workload-key-file`. Each exchange is audited as `mcp.token.exchange` or `mcp.token.denied`.

The server verifies the token with halo-server's workload public key, the same PEM the gateways trust:

```go
c, err := identity.VerifyMCPToken(keys, bearer, "https://mcp-wiki.internal.acme.example/mcp", time.Now())
```

or any JWT library: `alg` `EdDSA`, `typ` `halo-mcp+jwt`, `iss` `halos`, `aud` its own canonical URL, `exp`/`nbf`/`iat`, `mcp_server` its registry id.

Other modes: `oauth` renders a pre-registered `clientID` and `scopes` where the harness supports it (users still sign in with `/mcp`); `clientIDMetadataURL` and `enterprise` (Enterprise-Managed Authorization through `identity.issuer`) are policy for now, rendered by no CLI, and warn.
