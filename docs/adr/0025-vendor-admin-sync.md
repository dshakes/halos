---
title: "ADR-0025: Vendor admin sync"
description: One policy also drives the vendors' cloud admin consoles. Halos writes only the settings a vendor exposes through a documented public API, reads back what it can for drift, and exports the rest with manual steps. The GA ring's profile is the console's profile.
status: accepted
date: 2026-10-21
---

# ADR-0025: Vendor admin sync

- Status: accepted
- Date: 2026-10-21

## Context and problem statement

Halos renders per-machine configuration through the `internal/harness/*` adapters and ships it in signed releases that `halod` applies. Each vendor also has a cloud admin tier that applies org-wide settings server-side, with no machine agent: Claude for Teams/Enterprise server-managed settings, ChatGPT workspace Agent Security, Gemini for Google Cloud administrator settings, GitHub Copilot organization policies and Cursor team settings. Today an admin keeps those consoles in step with policy by hand, and nothing notices when they drift.

Can one Halos policy drive the consoles too, without inventing APIs that do not exist and without letting a console quietly undo what `halod` enforces?

## Vendor research (checked 2026-10-21)

Primary sources only. "No write API" means none is documented publicly. It is not a guess that one exists privately.

| Vendor | Manageable centrally | Read API | Write API | Auth |
|---|---|---|---|---|
| Claude Code | Server-managed settings: the same JSON as `managed-settings.json` (permissions, env, hooks, `availableModels`, `managedMcpServers`, `forceRemoteSettingsRefresh`, ...), set in claude.ai Organization settings > Claude Code > Managed settings. Teams and Enterprise only.[^c1] | none | **none** (console only). The Admin API covers members, invites, workspaces and API keys.[^c2] The Plugins API (Enterprise, beta) covers plugins only.[^c3] The Claude Code analytics API is read-only usage.[^c4] | n/a |
| Codex | Agent Security: requirements (enforced) and `config.toml` defaults, edited as TOML, with workspace default plus targeted overrides.[^o1] | none public | A "policy API" for Global settings is mentioned, but its endpoint, auth and schema are **not documented publicly**.[^o1] Treated as none. | n/a |
| Gemini Code Assist | Two administrator settings: release channel and logging. Each is a resource in a container project, bound to a target.[^g1] | `GET .../{settings}/{id}`, `.../settingBindings/{id}`[^g2] | `POST` (create, `<kind>_id` query), `PATCH` (`updateMask`), bindings likewise[^g2][^g3] | OAuth 2.0 bearer, scope `cloud-platform`, IAM `cloudaicompanion.<kind>.*`[^g3] |
| GitHub Copilot | Policies (CLI, IDE chat, public code), seats, content exclusion, the enterprise custom-agent source repo.[^h1][^h2][^h3] | `GET /orgs/{org}/copilot/billing` (policy summary: `cli`, `ide_chat`, `platform_chat`, `public_code_suggestions`); `GET /orgs/{org}/copilot/content_exclusion` | `PUT /orgs/{org}/copilot/content_exclusion` (public preview). Seats via `selected_users`/`selected_teams`. **No write API for policies.**[^h1][^h2] | Bearer token, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2026-03-10`; classic scopes `copilot` / `read:org` / `manage_billing:copilot` |
| Cursor | Members, spend limits, repo blocklist, model access (preview), groups, audit log.[^u1] | yes (`api.cursor.com`) | Repo blocklist, model access (preview), spend limits, groups[^u1] | Basic auth, API key as user |

Coding-agent MCP configuration for Copilot is a repository setting with no REST API.[^h4] Privacy-mode enforcement and MDM keys for Cursor have no documented API.[^u2]

## Decision drivers

- Invariant 1: no console artifact or API write carries `bypassPermissions` or `danger-full-access`.
- Invariant 2: a profile field a console cannot express is warned, per vendor, never dropped.
- Invariant 5: a human applies. Agents get a read-only plan, never an apply tool.
- Only documented, public APIs. An API that is mentioned but not specified is treated as absent.
- Credentials never live in policy, logs or errors.
- A console must not silently loosen or shadow what `halod` delivers.

## Considered options

1. **Render, diff and apply through documented public APIs, export the rest.** Chosen.
2. **Browser automation of the consoles.** Rejected: brittle, needs an admin's interactive session, and is not reviewable.
3. **Write consoles from halo-server on every policy change.** Rejected for now: it puts long-lived admin credentials for five vendors in the server, and a console write is not reversible by re-pointing a ring (invariant 6 does not cover it). Drift is caught by a scheduled `halo admin plan` instead.

## Decision outcome

### Policy

`halos.yaml` gains an additive `vendorAdmin` section, omitted when unset so existing snapshot digests do not change:

```yaml
vendorAdmin:
  ring: ring3-ga          # optional; default is the highest-order ring (GA)
  claude: {}              # presence enables a vendor
  codex: {}
  cursor: {}
  gemini: {project: acme-dev, location: global, releaseChannel: stable}
  copilot: {org: acme}
```

The section is strictly decoded, so a `token:` key is an error. Validation requires `copilot.org` and `gemini.project`, checks `location` and `releaseChannel`, and rejects Gemini-only fields on other vendors.

### Mapping

| Vendor | Console setting | From policy | Access |
|---|---|---|---|
| claude | Server-managed settings JSON | the `claude-code` adapter's `managed-settings.json` for the profile, unchanged | manual (export) |
| codex | Agent Security requirements and defaults (TOML) | the `codex` adapter's `requirements.toml` and `managed_config.toml` | manual (export) |
| gemini | `loggingSettings/halos.logMetadata` | `telemetry.enabled` | write |
| gemini | `loggingSettings/halos.logPromptsAndResponses` | `telemetry.enabled && telemetry.logPrompts` | write |
| gemini | `releaseChannelSettings/halos.releaseChannel` | `vendorAdmin.gemini.releaseChannel` (`STABLE`/`EXPERIMENTAL`; unset = unmanaged) | write |
| gemini | binding of each setting | `projects/<vendorAdmin.gemini.project>`, product `GEMINI_CODE_ASSIST` | write |
| copilot | content exclusion `"*"` | `permissions.deny` entries `Read(<glob>)`: `./x` becomes `/x`, `//x` becomes `/x`, `~` is warned | write |
| copilot | Copilot CLI policy (`billing.cli`) | `enabled` if the profile enables `copilot-cli`, else `disabled` | read (a human sets it) |
| cursor | team model allowlist | `models.allowed` when `models.enforce`, with each alias's provider model ids | manual (export) |

Every other populated profile field is warned per vendor (`hutil.WarnUnsupported`, or the adapter's own warnings for claude and codex). `TestNoSilentDrop` in `internal/vendoradmin` checks that removing any populated field changes a setting, an artifact or a warning for every vendor.

Halos owns one settings resource per Gemini kind, named `halos`, and only the `"*"` key of Copilot content exclusion. Other repositories' exclusion rules are read and written back unchanged, because `PUT` sets the whole map.

### Rings, units and loosenings

A console setting is org-wide. A ring is a cohort of machines. So:

- The console gets exactly one ring's profile: `vendorAdmin.ring`, by default the GA ring (highest order). Every render warns that members of the other rings get the GA ring's console settings. `halo validate` warns when `vendorAdmin.ring` is not the GA ring. Ring rollouts and client-axis experiments reach machine-delivered config only.
- A ring pinned to a release still renders from its profile, with a warning.
- Unit overlays (ADR-0018) are not applied to consoles, with a warning: every unit gets the org baseline there.
- `apply` never loosens. A change loosens when it moves a scalar away from its strict value (logging off, release channel off `STABLE`), or drops an entry the console has from a list (content exclusion). `apply` refuses the whole run and sends nothing. A human loosens in the console, deliberately. `plan` marks such changes `! loosens`.

### Precedence against local managed files

- **Claude Code.** Server-managed and endpoint-managed settings share the top tier but do not merge. A session that fetches server-managed settings uses them and ignores `halod`'s `managed-settings.json`, apart from documented per-key exceptions such as `forceRemoteSettingsRefresh`.[^c1] The export is therefore the adapter's file byte-for-byte, so both sources agree. Sessions that authenticate with `apiKeyHelper` or a custom `ANTHROPIC_BASE_URL` (the Halos gateway) do not fetch server-managed settings at all,[^c1] so the console reaches claude.ai Team and Enterprise logins only. Both facts are warned on every render.
- **Codex.** From lowest to highest: system `requirements.toml` (`halod`), Agent Security, legacy `managed_config.toml` reinterpreted as requirements (`halod`), then MDM. Scalars and lists override and tables merge. Codex ignores authentication fields in cloud requirements.[^o1] Exporting the adapter's files keeps the layers identical.
- **Gemini.** The cloud settings govern Gemini Code Assist. Logging records IDE interactions only, not Gemini CLI.[^g4] The CLI is still governed by `halod`'s system settings, and this is warned.
- **Copilot.** Content exclusion is not supported by Copilot CLI or by agent mode in IDE chat, and organization rules cover only seats that organization assigns.[^h3] Warned. `halod`'s rendered denies still apply on machines.

### Credentials

Only `--<vendor>-token-file` or the environment variable `--<vendor>-token-env` names (default `HALO_ADMIN_GEMINI_TOKEN`, `HALO_ADMIN_COPILOT_TOKEN`). Never in policy (strict decoding rejects it), never printed. The token goes only into the `Authorization` header. Every error from the HTTP client is scrubbed of the token (`TestCredentialRedaction`). The MCP `admin_plan` tool reads the same environment variables in the server process and takes neither a credential nor a base URL as an argument, so a caller cannot redirect a credential.

### Drift

`halo admin plan` reads Gemini and Copilot, diffs, and exits 0 in sync, 2 on drift (including read-only settings) and 1 when a console cannot be read. `--output json` is the report for a scheduled CI job ([guide](/halos/guides/vendor-admin-sync/)). Claude, Codex and Cursor have no usable read API, so their drift is unverifiable and the plan says `manual (no API)`. A halo-server background job was not built: the CI cron covers it without putting admin credentials in the server.

### Release manifest

The console render is not part of a release build. Releases are signed bundles that `halod` applies to machines. Console settings are written by `halo admin apply` and are not reverted by re-pointing a ring. Putting their warnings in the manifest would imply the release delivers them. The warnings are in `halo admin plan` output and in each exported `STEPS.md`.

### Failure modes

- Missing credential: `plan` and `apply` report the vendor unread and exit 1. `--offline` renders without reading.
- API error or timeout (30s): the vendor is unread, the error is redacted, the exit code is 1, and other vendors are still reported.
- Partial apply: each vendor applies independently. The apply record marks each change `ok` or failed, and the exit code is 1. Re-running `plan` shows what is left. Writes are idempotent (`PATCH` with `updateMask`, `PUT` of the full map).
- Concurrent console edit between plan and apply: the Copilot `PUT` re-reads the map immediately before writing, so other repositories' rules are kept. A race on the `"*"` key itself is last-writer-wins, as in the console.
- Gemini settings created in the console under another id: Halos reads and writes only its `halos` resources, so it neither sees nor removes them. If the API refuses the `halos` binding because one already exists, `apply` reports the error and an admin reconciles by hand. Whether Google allows two bindings for one target is not documented. This case is UNVERIFIED.
- Vendor API change: the fakes in `internal/vendoradmin` encode the documented shapes. A changed field shows up as constant drift, never as a silent pass.

### What stays manual

- Claude Code server-managed settings (paste `claude-managed-settings.json`).
- Codex Agent Security (paste `codex-requirements.toml` and `codex-config.toml`).
- Copilot policies, including the CLI policy Halos reads back, and coding-agent MCP configuration.
- Cursor model allowlist (Cursor's model-access API is a preview keyed by Cursor's own model ids, which policy aliases do not name), privacy mode and every other dashboard setting.
- Every loosening, on every vendor.

`halo admin export --out DIR` writes each vendor's artifacts and a `STEPS.md` with the steps, the settings and the warnings.

## Consequences

- Good: one policy now covers the consoles, and a cron catches drift on the two vendors that can be read.
- Good: the Claude and Codex exports are the adapters' own files, so console and machine never disagree about what they say.
- Bad: three of five vendors stay manual and unverifiable until they publish APIs. The ADR names exactly where.
- Bad: console settings ignore rings. A canary ring cannot trial a console change. That needs the vendor's own targeting (Codex overrides, Gemini bindings per project), which Halos does not model yet.
- Neutral: no live vendor API was called in building this. The httptest fakes follow the documented shapes. The Gemini binding `target` format (`projects/<id>`) and the update-mask names are from the REST reference, without a live run.

## More information

`internal/vendoradmin`, `cmd/halo/cmd_admin.go`, `internal/mcpserver/tools_admin.go`, `internal/policy/vendoradmin.go`; [Vendor admin sync guide](/halos/guides/vendor-admin-sync/).

[^c1]: https://code.claude.com/docs/en/server-managed-settings (checked 2026-10-21)
[^c2]: https://platform.claude.com/docs/en/manage-claude/admin-api (checked 2026-10-21)
[^c3]: https://platform.claude.com/docs/en/manage-claude/plugins-api (checked 2026-10-21)
[^c4]: https://platform.claude.com/docs/en/manage-claude/claude-code-analytics-api (checked 2026-10-21)
[^o1]: https://learn.chatgpt.com/docs/enterprise/managed-configuration and https://learn.chatgpt.com/docs/enterprise/agent-security (checked 2026-10-21)
[^g1]: https://docs.cloud.google.com/gemini/docs/admin-settings (checked 2026-10-21)
[^g2]: https://docs.cloud.google.com/gemini/docs/api/reference/rest (v1; `projects.locations.releaseChannelSettings/patch`, `projects.locations.loggingSettings`, `...settingBindings`; checked 2026-10-21)
[^g3]: https://docs.cloud.google.com/gemini/docs/api/reference/rest/v1/projects.locations.loggingSettings/create (checked 2026-10-21)
[^g4]: https://docs.cloud.google.com/gemini/docs/configure-logging (checked 2026-10-21)
[^h1]: https://docs.github.com/en/rest/copilot/copilot-user-management (checked 2026-10-21)
[^h2]: https://docs.github.com/en/rest/copilot/copilot-content-exclusion-management (checked 2026-10-21)
[^h3]: https://docs.github.com/en/copilot/how-tos/configure-content-exclusion/exclude-content-from-copilot and https://docs.github.com/en/rest/copilot/copilot-custom-agents (checked 2026-10-21)
[^h4]: https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/extend-coding-agent-with-mcp (checked 2026-10-21)
[^u1]: https://cursor.com/docs/account/teams/admin-api (checked 2026-10-21)
[^u2]: https://cursor.com/docs/enterprise (checked 2026-10-21)
