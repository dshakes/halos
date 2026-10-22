---
title: Vendor admin sync
description: Drive the vendors' cloud admin consoles (Claude, ChatGPT/Codex, Gemini Code Assist, GitHub Copilot, Cursor) from the same policy, apply where a public API exists, export the rest, and fail CI on drift.
---

`halod` enforces policy on machines. Each vendor also has a cloud admin console that applies org-wide settings without any machine agent. `halo admin` keeps those consoles in step with the same policy ([ADR-0025](/halos/adr/0025-vendor-admin-sync/)):

- `halo admin plan` renders each console's settings from the GA ring's profile and diffs them against the live consoles that have a read API. It writes nothing. It exits 2 on drift, and 3 with `--offline`, which compares nothing.
- `halo admin apply` writes the drifted settings that have a public write API, after showing the diff and asking for confirmation (or `--yes`). Just before writing, it re-reads each console and aborts if the console changed since the plan you confirmed. It refuses anything it would write that loosens a control the console has now. It prints an apply record with one result per change.
- `halo admin export` writes the artifacts and step-by-step instructions for consoles with no write API.

Agents get the read-only MCP tool `admin_plan`. By default it renders from policy only. It reads the live consoles only on a server started with `halo mcp serve --admin-read`, using `HALO_MCP_ADMIN_<VENDOR>_TOKEN`. There is no apply tool: a human applies.

## What can be synced

| Vendor | Setting | From policy | Halos can |
|---|---|---|---|
| Claude for Teams/Enterprise | Server-managed settings (claude.ai > Organization settings > Claude Code > Managed settings) | the Claude Code adapter's `managed-settings.json` without machine keys | export (no API) |
| ChatGPT workspace (Codex) | Agent Security requirements and defaults | the Codex adapter's `requirements.toml` and `managed_config.toml` | export (no documented API) |
| Gemini Code Assist | logging (`logMetadata`, `logPromptsAndResponses`) | `telemetry.enabled`, `telemetry.logPrompts` | read and write |
| Gemini Code Assist | release channel | `vendorAdmin.gemini.releaseChannel` | read and write |
| GitHub Copilot | org content exclusion (`"*"` rules) | `permissions.deny` `Read(...)` rules | read and write |
| GitHub Copilot | Copilot CLI policy | `copilot-cli` enabled in the profile | read (set by hand) |
| Cursor | team model allowlist | `models.allowed` with `models.enforce` | export (no stable API) |

Every profile field a console cannot express is listed as a warning for that vendor. Every limit below is printed by `plan` and written into `STEPS.md`:

- **Console settings are org-wide.** Every ring gets the GA ring's console settings.
- **Claude Code.** Server-managed settings replace the file `halod` delivers for sessions that fetch them, and sessions on the Halos gateway (`apiKeyHelper`) do not fetch them. The export therefore leaves out machine config: `apiKeyHelper` and other credential helpers, hooks and status line commands, `modelOverrides`, `env.ANTHROPIC_*`, and ring or release stamps. Each removal is a warning.
- **Gemini Code Assist.** Logging covers IDE use, not Gemini CLI.
- **Copilot content exclusion.** Copilot CLI and agent mode do not apply it.

## Policy

```yaml
# halos.yaml
vendorAdmin:
  # ring: ring3-ga        # default: the highest-order ring (GA)
  claude: {}
  codex: {}
  cursor: {}
  gemini:
    project: acme-gemini-admin   # Google Cloud project holding the settings
    location: global             # default
    releaseChannel: stable       # unset = leave the channel alone
  copilot:
    org: acme
```

Credentials are never in policy. A `token:` key is a validation error. `org` must be letters, digits and hyphens (at most 39 characters), `project` a Google Cloud project id, and `location` a region or `global`.

## Per-vendor setup

### Claude for Teams/Enterprise

No API. Run `halo admin export`. As an Owner, open claude.ai **Organization settings > Claude Code > Managed settings** and diff `claude/claude-managed-settings.json` against the JSON already there. Add or tighten what the policy requires, and keep anything already there that is stricter. Never add machine keys (`apiKeyHelper`, `env.ANTHROPIC_*`, hooks): they break claude.ai logins or stop the settings fetch. Do not save "with errors". Fix the policy instead. Re-export after every policy change: drift cannot be detected.

### ChatGPT workspace (Codex)

No documented API. In **Admin Console > Agent security > Workspace default**, choose **Edit as TOML**. Diff `codex/codex-requirements.toml` (requirements) and `codex/codex-config.toml` (defaults) against the current policy. Add or tighten what the policy requires, and keep any stricter requirement already there. Do not add overrides that grant more than the default.

### Gemini Code Assist

1. Pick the project that holds the settings. Grant the identity that runs `halo admin` the IAM permissions `cloudaicompanion.loggingSettings.*` and `cloudaicompanion.releaseChannelSettings.*`, including on their `settingBindings`.
2. Provide an OAuth access token with the `cloud-platform` scope:

   ```bash
   gcloud auth print-access-token > /run/secrets/gemini-token   # or HALO_ADMIN_GEMINI_TOKEN
   ```

3. `halo admin plan --gemini-token-file /run/secrets/gemini-token`, review, then `halo admin apply --gemini-token-file /run/secrets/gemini-token`.

Halos manages resources named `halos` (`loggingSettings/halos`, `releaseChannelSettings/halos`) and binds each to `projects/<project>` for product `GEMINI_CODE_ASSIST`. It never moves an existing binding: a rebind is a loosening. If a setting made in the console under another id is bound to the same project, `plan` lists it as a conflict and `apply` refuses until you reconcile it.

### GitHub Copilot

1. Create a token for an org owner: classic scopes `copilot` and `manage_billing:copilot` (or `read:org` for plan only).
2. `halo admin plan --copilot-token-env GITHUB_ADMIN_TOKEN`.
3. `halo admin apply` writes the `"*"` content exclusion rules from your `Read(...)` denies (for example `Read(./.env)` becomes `/.env`). Other repositories' rules, and object rules such as `{"if-any-match": [...]}` under `"*"`, are kept as they are. A path string under `"*"` that the policy does not have is a loosening, and `apply` refuses it. When GitHub returns an `ETag`, the `PUT` is conditional on it.
4. Set the Copilot CLI policy by hand at `https://github.com/organizations/<org>/settings/copilot/policies`. GitHub has no write API for policies, but `plan` reads it back and reports drift.

For GitHub Enterprise Server, pass `--copilot-base-url https://<host>/api/v3`. Base URLs must be https. Plain http is accepted only to a loopback host.

### Cursor

`halo admin export` writes `cursor/cursor-models.md`, the policy's model aliases with their provider model ids. Restrict the team's models in the Cursor dashboard to match.

## Credentials

| Vendor | Flag | Default environment variable |
|---|---|---|
| Gemini | `--gemini-token-file` or `--gemini-token-env NAME` | `HALO_ADMIN_GEMINI_TOKEN` |
| Copilot | `--copilot-token-file` or `--copilot-token-env NAME` | `HALO_ADMIN_COPILOT_TOKEN` |

The token is sent only in the `Authorization` header and is scrubbed from every error. The MCP server never reads these variables. With `halo mcp serve --admin-read`, it reads `HALO_MCP_ADMIN_GEMINI_TOKEN` and `HALO_MCP_ADMIN_COPILOT_TOKEN`, so a CLI token in your shell profile is never handed to an agent's server by accident. `admin_plan` takes neither a credential nor an API URL as an argument.

## Apply

```text
$ halo admin apply --copilot-token-file ~/.halo/gh   # output abbreviated
vendor admin: ring ring3-ga (profile engineering)
copilot acme: 1 drifted
  ~ content_exclusion.*: [/.env] -> [/.env /.env.* /secrets/**] (write)
Apply 1 change(s) to the live consoles? Type yes to continue: yes
applied copilot acme content_exclusion.*: [/.env] -> [/.env /.env.* /secrets/**]
apply record: 2026-10-21T18:02:11Z by alice, ring ring3-ga (profile engineering)
```

With `--output json`, the apply record is JSON, ready to append to an audit log. Each change is marked written, failed (with the error) or not attempted. `apply` refuses the whole run and sends nothing when a change it would write loosens a console control, for example dropping an exclusion rule that someone added in the console or turning logging off, and when a conflicting Gemini binding exists. Make that change in the console, deliberately, or tighten the policy. A loosening of a read-only setting (the Copilot CLI policy) is shown as `! loosens (set by hand)` and does not block. If the console changed between your confirmation and the write, `apply` aborts that vendor with nothing written. Run `plan` again.

## Drift in CI

`halo admin plan` exits `0` when every readable console is in sync, `2` on drift, `1` when a console cannot be read, and `3` with `--offline`. Never gate CI on `--offline`: it compares nothing. Run it on a schedule:

```yaml
# .github/workflows/vendor-admin-drift.yml
name: vendor-admin-drift
on:
  schedule: [{cron: "17 6 * * *"}]
  workflow_dispatch: {}
permissions: {contents: read, id-token: write}
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ vars.GCP_WIF_PROVIDER }}
          service_account: ${{ vars.GEMINI_ADMIN_SA }}
      - uses: google-github-actions/setup-gcloud@v2
      - name: halo admin plan
        env:
          HALO_ADMIN_COPILOT_TOKEN: ${{ secrets.COPILOT_ADMIN_TOKEN }}
        run: |
          export HALO_ADMIN_GEMINI_TOKEN="$(gcloud auth print-access-token)"
          halo admin plan --policy-dir . --output json > vendor-admin-plan.json
      - if: always()
        uses: actions/upload-artifact@v4
        with: {name: vendor-admin-plan, path: vendor-admin-plan.json}
```

The job fails on drift (exit 2) and on an unreadable console (exit 1). The JSON lists each vendor's `changes` with `current`, `desired`, `access` and `loosens`. Claude, Codex and Cursor show `read: false` and print `not checked (manual)`: no API can confirm them, and they never count as in sync.

## What it does not do

- Rings, experiments and unit overlays do not reach consoles.
- The console render is not part of a release, so its warnings are in `plan` and `STEPS.md`, not in the release manifest.
- No halo-server job writes consoles. The CI cron detects drift and a human applies.
