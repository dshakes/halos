---
title: "ADR-0025: Vendor admin sync"
description: One policy also drives the vendors' cloud admin consoles. Halos writes only the settings a vendor exposes through a documented public API, reads back what it can for drift, and exports the rest with manual steps. The GA ring's profile is the console's profile.
status: accepted
date: 2026-10-21
---

# ADR-0025: Vendor admin sync

- Status: accepted, amended 2026-10-21 after a security review (see [Amended](#amended-2026-10-21))
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

The section is strictly decoded, so a `token:` key is an error. Validation requires `copilot.org` and `gemini.project`, checks `location` and `releaseChannel`, and rejects Gemini-only fields on other vendors. Every `org` must match `^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`, `project` must be a Google Cloud project id (`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`) and `location` a region or `global`: they become API path segments, terminal output and `STEPS.md` text.

### Mapping

| Vendor | Console setting | From policy | Access |
|---|---|---|---|
| claude | Server-managed settings JSON | the `claude-code` adapter's `managed-settings.json`, rendered with no gateway, ring or release and stripped of machine keys (below) | manual (export) |
| codex | Agent Security requirements and defaults (TOML) | the `codex` adapter's `requirements.toml` and `managed_config.toml`, rendered with no gateway, ring or release | manual (export) |
| gemini | `loggingSettings/halos.logMetadata` | `telemetry.enabled` | write |
| gemini | `loggingSettings/halos.logPromptsAndResponses` | `telemetry.enabled && telemetry.logPrompts` | write |
| gemini | `releaseChannelSettings/halos.releaseChannel` | `vendorAdmin.gemini.releaseChannel` (`STABLE`/`EXPERIMENTAL`; unset = unmanaged) | write |
| gemini | binding of each setting | `projects/<vendorAdmin.gemini.project>`, product `GEMINI_CODE_ASSIST`; created, never moved | write |
| copilot | content exclusion `"*"` | `permissions.deny` entries `Read(<glob>)`: `./x` becomes `/x`, `//x` becomes `/x`, `~` is warned | write |
| copilot | Copilot CLI policy (`billing.cli`) | `enabled` if the profile enables `copilot-cli`, else `disabled` | read (a human sets it) |
| cursor | team model allowlist | `models.allowed` when `models.enforce`, with each alias's provider model ids | manual (export) |

Every other populated profile field is warned per vendor (`hutil.WarnUnsupported`, or the adapter's own warnings for claude and codex). `TestNoSilentDrop` in `internal/vendoradmin` checks that removing any populated field changes a setting, an artifact or a warning for every vendor.

Halos owns one settings resource per Gemini kind, named `halos`, and only the string entries of the `"*"` key of Copilot content exclusion. Non-string entries of `"*"` (an `{"if-any-match": [...]}` rule) and other repositories' rules are read and written back unchanged, because `PUT` sets the whole map.

### Rings, units and loosenings

A console setting is org-wide. A ring is a cohort of machines. So:

- The console gets exactly one ring's profile: `vendorAdmin.ring`, by default the GA ring (highest order). Every render warns that members of the other rings get the GA ring's console settings. `halo validate` warns when `vendorAdmin.ring` is not the GA ring. Ring rollouts and client-axis experiments reach machine-delivered config only.
- A ring pinned to a release still renders from its profile, with a warning.
- Unit overlays (ADR-0018) are not applied to consoles, with a warning: every unit gets the org baseline there.
- `apply` never loosens. A change loosens when it moves a scalar away from its strict value (logging off; release channel from `STABLE`, or from `CHANNEL_TYPE_UNSPECIFIED`, which is the stable default, to `EXPERIMENTAL`), moves an existing binding to another target (it un-governs the old one), or drops a string entry the console has from a list (content exclusion). If a change Halos would write loosens, `apply` refuses the whole run and sends nothing. A loosening of a read-only setting (the Copilot CLI policy) is shown as `! loosens (set by hand)` but does not block: Halos never writes it. A human loosens in the console, deliberately.
- A Gemini setting of the same kind under another id, bound to the same project, is a conflict. `plan` lists it and `apply` refuses the run.

### Precedence against local managed files

- **Claude Code.** Server-managed and endpoint-managed settings share the top tier but do not merge. A session that fetches server-managed settings uses them and ignores `halod`'s `managed-settings.json`, apart from documented per-key exceptions such as `forceRemoteSettingsRefresh`.[^c1] Keys from an `apiKeyHelper` do not trigger the fetch, and a custom `ANTHROPIC_BASE_URL` or third-party provider variable skips it,[^c1] so the console reaches claude.ai Team and Enterprise logins only, and machine keys in it would break those logins. The export is the adapter's file rendered with no gateway, ring or release, and then stripped of `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `hooks` and `statusLine` (commands at machine paths), `modelOverrides`, `env.ANTHROPIC_*`, `env.CLAUDE_CODE_USE_*`, `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS`, `env.OTEL_EXPORTER_OTLP_HEADERS`, and the `halo.ring`/`halo.release`/`halo.experiment`/`halo.variant` OTEL attributes. Each removed key is warned. The steps say to diff the artifact against the console's current JSON and keep anything stricter that is already there, never to paste it unchanged.
- **Codex.** From lowest to highest: system `requirements.toml` (`halod`), Agent Security, legacy `managed_config.toml` reinterpreted as requirements (`halod`), then MDM. Scalars and lists override and tables merge. Codex ignores authentication fields in cloud requirements.[^o1] The steps say to reconcile the artifacts with the console's current policy and keep stricter requirements.
- **Gemini.** The cloud settings govern Gemini Code Assist. Logging records IDE interactions only, not Gemini CLI.[^g4] The CLI is still governed by `halod`'s system settings, and this is warned.
- **Copilot.** Content exclusion is not supported by Copilot CLI or by agent mode in IDE chat, and organization rules cover only seats that organization assigns.[^h3] Warned. `halod`'s rendered denies still apply on machines.

### Credentials

Only `--<vendor>-token-file` or the environment variable `--<vendor>-token-env` names (default `HALO_ADMIN_GEMINI_TOKEN`, `HALO_ADMIN_COPILOT_TOKEN`). Never in policy (strict decoding rejects it), never printed. The token goes only into the `Authorization` header. Every error from the HTTP client is scrubbed of the token (`TestCredentialRedaction`). A base URL must be https, or http only to a loopback host, checked when clients are built and again on every request. The MCP `admin_plan` tool renders from policy only unless the server was started with `halo mcp serve --admin-read`. Then it reads `HALO_MCP_ADMIN_<VENDOR>_TOKEN`, deliberately not the CLI's `HALO_ADMIN_*`, so an admin token in a shell profile is never used by an agent's server without a decision. It takes neither a credential nor a base URL as an argument, so a caller cannot redirect a credential. Every string from policy or a console is stripped of control and format characters before it reaches a terminal or `STEPS.md`, and escaped for Markdown tables there.

### Drift

`halo admin plan` reads Gemini and Copilot, diffs, and exits 0 when every readable console is in sync, 2 on drift (including read-only settings), 1 when a console cannot be read, and 3 with `--offline` (nothing compared; never gate CI on it). `--output json` is the report for a scheduled CI job ([guide](/halos/guides/vendor-admin-sync/)). Claude, Codex and Cursor have no usable read API, so their drift is unverifiable and the plan says `not checked (manual)`, never in sync. A halo-server background job was not built: the CI cron covers it without putting admin credentials in the server.

### Release manifest

The console render is not part of a release build. Releases are signed bundles that `halod` applies to machines. Console settings are written by `halo admin apply` and are not reverted by re-pointing a ring. Putting their warnings in the manifest would imply the release delivers them. The warnings are in `halo admin plan` output and in each exported `STEPS.md`.

### Failure modes

- Missing credential: `plan` and `apply` report the vendor unread and exit 1. `--offline` renders without reading.
- API error or timeout (30s): the vendor is unread, the error is redacted, the exit code is 1, and other vendors are still reported.
- Partial apply: each vendor applies independently. `Apply` returns one result per writable change: written, failed (with the redacted error), or not attempted after an earlier failure. The apply record carries every one, and the exit code is 1. Re-running `plan` shows what is left. Writes are idempotent (`PATCH` with `updateMask`, `PUT` of the full map).
- Concurrent console edit between the confirmed plan and the write: `apply` re-reads each console and re-diffs. If the changes, loosenings or conflicts differ from the plan the human confirmed, it aborts that vendor with nothing written (`ErrStale`). Copilot re-reads the map again immediately before the `PUT` and aborts if `"*"` changed. When GitHub returns an `ETag`, the `PUT` carries `If-Match` and a `412` is `ErrStale`. The REST pages do not document an ETag, so Halos never assumes one. The Gemini settings resources have no `etag` field (REST reference), so a write that lands between the re-read and the `PATCH` remains possible. That window is milliseconds and is accepted.
- Gemini settings created in the console under another id: `plan` lists each kind's settings (paginated) and their bindings, and reports any non-`halos` setting bound to the same project as a conflict that `apply` refuses. The list response field names (`<kind>`, `settingBindings`, `nextPageToken`) follow AIP-132. They are not confirmed against a live API: UNVERIFIED.
- Vendor API change: the fakes in `internal/vendoradmin` encode the documented shapes. A changed field shows up as constant drift, never as a silent pass.

### What stays manual

- Claude Code server-managed settings (reconcile `claude-managed-settings.json` into the console JSON).
- Codex Agent Security (reconcile `codex-requirements.toml` and `codex-config.toml`).
- Copilot policies, including the CLI policy Halos reads back, and coding-agent MCP configuration.
- Cursor model allowlist (Cursor's model-access API is a preview keyed by Cursor's own model ids, which policy aliases do not name), privacy mode and every other dashboard setting.
- Every loosening, on every vendor.

`halo admin export --out DIR` writes each vendor's artifacts and a `STEPS.md` with the steps, the settings and the warnings.

## Consequences

- Good: one policy now covers the consoles, and a cron catches drift on the two vendors that can be read.
- Good: the Claude and Codex exports come from the adapters' own renderers, minus machine config, so console and machine never disagree about policy.
- Bad: three of five vendors stay manual and unverifiable until they publish APIs. The ADR names exactly where.
- Bad: console settings ignore rings. A canary ring cannot trial a console change. That needs the vendor's own targeting (Codex overrides, Gemini bindings per project), which Halos does not model yet.
- Neutral: no live vendor API was called in building this. The httptest fakes follow the documented shapes. The Gemini binding `target` format (`projects/<id>`) and the update-mask names are from the REST reference, without a live run.

## Amended (2026-10-21)

An independent security review found these issues, all fixed on `vendor-admin-fixes` with a regression test each (every test fails when its fix is reverted):

| Finding | Fix | Test |
|---|---|---|
| H1: object entries in Copilot `"*"` were dropped on read and deleted by `PUT`, and plan reported in sync | read keeps them; the desired list is policy strings plus live objects; a live string missing from policy loosens | `TestCopilotObjectEntriesPreserved` |
| H2: stale-plan race on the Copilot read-modify-write | re-read and re-diff in `Apply`; re-read again before `PUT`; `If-Match` when an ETag is returned; `412` is stale | `TestCopilotStalePlanAborts`, `TestCopilotETagIfMatch` |
| M1: Gemini never re-read before writing | the same re-read and re-diff in `Apply`; Gemini resources have no etag | `TestGeminiStalePlanAborts` |
| M2: the Claude export was machine config | render without gateway, ring or release; strip machine keys with a warning each; the steps say to reconcile, not paste | `TestClaudeConsoleArtifactHasNoMachineConfig`, `TestConsoleSettingsStripsMachineKeys` |
| M3: MCP `admin_plan` silently used inherited shell tokens | live reads only with `halo mcp serve --admin-read`, from `HALO_MCP_ADMIN_<VENDOR>_TOKEN` | `TestAdminPlanReadOnly` |
| L1/L2: unvalidated identifiers; terminal and Markdown injection | strict `org`, `project` and `location` validation in policy and schema; `Sanitize` and Markdown escaping on all output | `TestVendorAdminValidate`, `TestOrgPathEscaped`, `TestSanitize`, `TestAdminOutputSanitized` |
| L3: plain-http base URL | https only, or http to loopback | `TestCheckBaseURL`, `TestAdminPlanExitCodes` |
| L4: the apply record lied on partial failure | per-change `Result`s, including not-attempted changes | `TestApplyPartialFailureResults`, `TestAdminApplyRecordOnFailure` |
| L5: loosening classification gaps | unspecified channel counts as stable; rebinding loosens; conflicting bindings refuse | `TestGeminiLooseningClassification` |
| L6: exit-code softness | `--offline` exits 3; manual vendors are `not checked (manual)`; only writable loosenings block apply | `TestAdminPlanExitCodes`, `TestReadOnlyLooseningDoesNotBlock` |
| Final review (2026-10-22): the API client followed redirects, and net/http resends `Authorization` to the same host over http or to a subdomain | `CheckRedirect` returns `http.ErrUseLastResponse` on every client, the caller's included; a 3xx is an error naming the `Location` | `TestClientDoesNotFollowRedirects` |

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
