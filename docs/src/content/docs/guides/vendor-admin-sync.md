---
title: Vendor admin sync
description: Drive the vendors' cloud admin consoles (Claude, ChatGPT/Codex, Gemini Code Assist, GitHub Copilot, Cursor) from the same policy, apply where a public API exists, export the rest, and fail CI on drift.
---

`halod` enforces policy on machines. Each vendor also has a cloud admin console that applies org-wide settings without any machine agent. `halo admin` keeps those consoles in step with the same policy ([ADR-0025](/halos/adr/0025-vendor-admin-sync/)):

- `halo admin plan` renders each console's settings from the GA ring's profile and diffs them against the live consoles that have a read API. It writes nothing. It exits 2 on drift.
- `halo admin apply` writes the drifted settings that have a public write API, after showing the diff and asking for confirmation (or `--yes`). It prints an apply record and refuses anything that would loosen a control the console has now.
- `halo admin export` writes the artifacts and step-by-step instructions for consoles with no write API.

Agents get the read-only MCP tool `admin_plan`. There is no apply tool: a human applies.

## What can be synced

| Vendor | Setting | From policy | Halos can |
|---|---|---|---|
| Claude for Teams/Enterprise | Server-managed settings (claude.ai > Organization settings > Claude Code > Managed settings) | the Claude Code adapter's `managed-settings.json` | export (no API) |
| ChatGPT workspace (Codex) | Agent Security requirements and defaults | the Codex adapter's `requirements.toml` and `managed_config.toml` | export (no documented API) |
| Gemini Code Assist | logging (`logMetadata`, `logPromptsAndResponses`) | `telemetry.enabled`, `telemetry.logPrompts` | read and write |
| Gemini Code Assist | release channel | `vendorAdmin.gemini.releaseChannel` | read and write |
| GitHub Copilot | org content exclusion (`"*"` rules) | `permissions.deny` `Read(...)` rules | read and write |
| GitHub Copilot | Copilot CLI policy | `copilot-cli` enabled in the profile | read (set by hand) |
| Cursor | team model allowlist | `models.allowed` with `models.enforce` | export (no stable API) |

Every profile field a console cannot express is listed as a warning for that vendor. Every limit below is printed by `plan` and written into `STEPS.md`:

- **Console settings are org-wide.** Every ring gets the GA ring's console settings.
- **Claude Code.** Server-managed settings replace the file `halod` delivers for sessions that fetch them, and sessions on the Halos gateway (`apiKeyHelper`) do not fetch them.
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

Credentials are never in policy. A `token:` key is a validation error.

## Per-vendor setup

### Claude for Teams/Enterprise

No API. Run `halo admin export`, then paste `claude/claude-managed-settings.json` into claude.ai **Organization settings > Claude Code > Managed settings** as an Owner. Do not save "with errors". Fix the policy instead. Re-export after every policy change: drift cannot be detected.

### ChatGPT workspace (Codex)

No documented API. In **Admin Console > Agent security > Workspace default**, choose **Edit as TOML**. Paste `codex/codex-requirements.toml` as the requirements and `codex/codex-config.toml` as the defaults. Do not add overrides that grant more than the default.

### Gemini Code Assist

1. Pick the project that holds the settings. Grant the identity that runs `halo admin` the IAM permissions `cloudaicompanion.loggingSettings.*` and `cloudaicompanion.releaseChannelSettings.*`, including on their `settingBindings`.
2. Provide an OAuth access token with the `cloud-platform` scope:

   ```bash
   gcloud auth print-access-token > /run/secrets/gemini-token   # or HALO_ADMIN_GEMINI_TOKEN
   ```

3. `halo admin plan --gemini-token-file /run/secrets/gemini-token`, review, then `halo admin apply --gemini-token-file /run/secrets/gemini-token`.

Halos manages resources named `halos` (`loggingSettings/halos`, `releaseChannelSettings/halos`) and binds each to `projects/<project>` for product `GEMINI_CODE_ASSIST`.

### GitHub Copilot

1. Create a token for an org owner: classic scopes `copilot` and `manage_billing:copilot` (or `read:org` for plan only).
2. `halo admin plan --copilot-token-env GITHUB_ADMIN_TOKEN`.
3. `halo admin apply` writes the `"*"` content exclusion rules from your `Read(...)` denies (for example `Read(./.env)` becomes `/.env`). Other repositories' rules are kept as they are.
4. Set the Copilot CLI policy by hand at `https://github.com/organizations/<org>/settings/copilot/policies`. GitHub has no write API for policies, but `plan` reads it back and reports drift.

For GitHub Enterprise Server, pass `--copilot-base-url https://<host>/api/v3`.

### Cursor

`halo admin export` writes `cursor/cursor-models.md`, the policy's model aliases with their provider model ids. Restrict the team's models in the Cursor dashboard to match.

## Credentials

| Vendor | Flag | Default environment variable |
|---|---|---|
| Gemini | `--gemini-token-file` or `--gemini-token-env NAME` | `HALO_ADMIN_GEMINI_TOKEN` |
| Copilot | `--copilot-token-file` or `--copilot-token-env NAME` | `HALO_ADMIN_COPILOT_TOKEN` |

The token is sent only in the `Authorization` header and is scrubbed from every error. The MCP server reads the same default variables from its own environment. `admin_plan` takes neither a credential nor an API URL as an argument.

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

With `--output json`, the apply record is JSON, ready to append to an audit log. If any change would loosen a console control, for example dropping an exclusion rule that someone added in the console or turning logging off, `apply` refuses the whole run and sends nothing. Make that change in the console, deliberately, or tighten the policy.

## Drift in CI

`halo admin plan` exits `0` in sync, `2` on drift and `1` when a console cannot be read. Run it on a schedule:

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

The job fails on drift (exit 2) and on an unreadable console (exit 1). The JSON lists each vendor's `changes` with `current`, `desired`, `access` and `loosens`. Claude, Codex and Cursor show `read: false`: no API can confirm them.

## What it does not do

- Rings, experiments and unit overlays do not reach consoles.
- The console render is not part of a release, so its warnings are in `plan` and `STEPS.md`, not in the release manifest.
- No halo-server job writes consoles. The CI cron detects drift and a human applies.
