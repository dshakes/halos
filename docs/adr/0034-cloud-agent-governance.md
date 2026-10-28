---
title: "ADR-0034: Cloud agent governance"
description: Background coding agents that run on vendor or CI infrastructure (Claude Code GitHub Action and cloud sessions, Codex cloud, Copilot cloud agent, Cursor cloud agents, Gemini CLI GitHub Action) get one policy section, SHA-pinned rendered workflows, an inventory mapped to Halos identities, kill fan-out and reversible over-limit pauses.
status: accepted
date: 2026-10-27
---

# ADR-0034: Cloud agent governance

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

Halos governs agents on developer machines: `halod` writes managed config, halo-proxy routes and meters model calls, the kill switch reverts a ring. A growing share of agent work never touches a machine Halos manages. A developer mentions `@claude` on an issue and the Claude Code GitHub Action runs on a GitHub runner; assigns an issue to Copilot and the Copilot cloud agent opens a pull request; starts a Codex cloud task or a Cursor cloud agent from a browser. None of these read `halod`'s files, most never pass the gateway, and none stop when a ring is killed.

How should Halos govern these agents with the same policy, identities, kill switch and budgets, without claiming control a vendor does not expose?

## Vendor research (checked 2026-10-27)

Official documentation only; sources are in [`internal/harness/FACTS.md`](https://github.com/dshakes/halos/blob/main/internal/harness/FACTS.md) (Cloud and background agents). External content was read as data. Where a mapping could not be verified it is marked UNVERIFIED and implemented against the documented interface with httptest fakes.

| Vendor | Configured in | Inventory | Cancel | Pause (reversible) | Egress setting | Halos renders |
|---|---|---|---|---|---|---|
| Claude Code GitHub Action[^c1] | workflow file in each repository | GitHub `workflow_run` webhook; Actions runs API[^h2] | Actions run cancel[^h2] | disable the workflow[^h3] | none on GitHub-hosted runners | `.github/workflows/halos-claude.yml` |
| Claude Code cloud sessions[^c2][^c3] | claude.ai console (`allow_remote_sessions`; per-environment network level None, Trusted, Full, Custom) | creation only, through the Anthropic Compliance API `ccr_session_created` (ADR-0031) | none | none | console only, per environment | manual steps (`halo admin plan`) |
| Codex cloud[^o1][^o2] | ChatGPT workspace (role permission, per-environment internet access Off or On with an allowlist) | none (no public task API) | none | none | console only | manual steps |
| Copilot cloud agent[^h4][^h5][^h6] | `copilot-setup-steps.yml` in each repository; org repository access and firewall in the console | GitHub `workflow_run` webhook (path UNVERIFIED) | Actions run cancel, effect on the session UNVERIFIED | none (repository access is console-only) | org and repository firewall; read per repository through a public-preview API, no write API | `.github/workflows/copilot-setup-steps.yml` |
| Cursor cloud agents[^u1] | Cursor dashboard | Cloud Agents API v1 (public beta): the key owner's agents | `POST /v1/agents/{id}/runs/{runId}/cancel` | `POST /v1/agents/{id}/archive` (unarchive resumes) | none documented | manual steps |
| Gemini CLI GitHub Action[^g1] | workflow file in each repository | GitHub `workflow_run` webhook; Actions runs API | Actions run cancel | disable the workflow | none on GitHub-hosted runners | `.github/workflows/halos-gemini.yml` |

## Decision drivers

- Invariant 1: nothing rendered may carry a permission-bypass token. Workflows are checked by reading their text, like machine config.
- Invariant 2: a control a vendor cannot express is warned per vendor, never dropped.
- Invariant 3: rings and experiment variants of a cloud task's user come from `internal/assign` through `policy.ResolveRing` and `AssignVariant`, never a second hash.
- Invariant 5: no automatic enable or resume. Cancel is explicit; the only automatic action is a reversible pause, and only when policy opts in.
- Credentials as in ADR-0025: files or environment variables, never a flag value or policy, never printed, no redirects, https only.
- A webhook is a public endpoint: authenticate every delivery, cap the body, and never let a replay turn a finished task back on.
- No new dependency, process or store.

## Considered options

1. **Policy section + rendered workflows + webhook/API inventory + server-side kill fan-out** (chosen).
2. **Machine-style delivery**: put the workflows in releases and have `halod` write them. Rejected: they live in repositories, not on machines; a PR is how a repository changes.
3. **Gateway-only control**: route every cloud agent through halo-proxy. Rejected as the only control: Copilot, Codex cloud, Cursor and Claude cloud sessions call their vendor's models directly. Offered where it works (`identity: workload`).
4. **Auto-cancel on over-limit**. Rejected: cancel is terminal. A pause can be undone by a human; a cancel cannot.

## Decision outcome

### Policy

`halos.yaml` `cloudAgents` (schema in `schemas/halos.schema.json`), strictly decoded:

```yaml
cloudAgents:
  identities:                      # vendor login -> Halos user
    - {user: alice@acme.com, github: alice-acme}
  server: https://halo.acme.example # identity: workload only
  haloVersion: v0.3.0               # identity: workload only
  claude:
    enabled: true
    repos: [acme-corp/web, acme-corp/*]   # owner/repo or owner/*
    models: [claude-sonnet-5]             # first one is rendered
    maxConcurrent: {perUser: 2, perGroup: 10, groups: [platform]}
    budgets: [{name: daily, scope: user, window: day, limitTokens: 5000000}]  # ADR-0017 fields
    network: {mode: allowlist, recommended: true, allow: [packages.acme.example]}
    identity: workload             # gateway credential instead of a repository secret
    onOverLimit: alert             # or pause
    timeoutMinutes: 30
  codex: {enabled: false}
  copilot: {...}
  cursor: {...}
  gemini: {..., version: 0.34.0}
```

Validation checks every repo pattern, model id, domain and login against a strict charset (they become API path segments and terminal text); `budgets` reuses the ADR-0017 checks (`budgetEntry`) and refuses `action: enforce` (cloud usage is reported after the fact, so `onOverLimit` decides); `identity: workload` requires a GitHub Actions `workloads` issuer (ADR-0023), a gateway, an https `server` and a `vX.Y.Z` `haloVersion`; Copilot's `timeoutMinutes` is at most 59. Every control a vendor cannot express is a warning: models for Copilot, Codex and Cursor; network for Gemini and Cursor; budgets for vendors that report no usage; `limitUSD` for Cursor (tokens only).

### Rendering

`internal/cloudagents/workflow` renders, for each enabled workflow vendor, one file per vendor. It imports only `policy`, so `release.Build` carries the files as signed blobs in `Manifest.CloudAgents` (vendor, path, digest, repos), apart from the harness files: `halod` never writes them. `halo cloud-agents render [--out DIR]` writes them for the pull request that adds them to each repository.

Every rendered workflow:

- pins every `uses:` to a full commit SHA with the tag in a comment (`actions/checkout` v7.0.1, `anthropics/claude-code-action` v1.0.264, `google-github-actions/run-gemini-cli` v0.1.22; one table in the package);
- sets top-level `permissions: {}` and grants each job only what its vendor documents (Claude: `contents`, `pull-requests`, `issues` write and `id-token: write` for the App token exchange; Gemini: `contents: read`, `issues`/`pull-requests` write, `id-token: write`; Copilot: `contents: read`, as Copilot gets its own token);
- checks out with `persist-credentials: false` and puts no `${{ }}` expression inside a `run:` script;
- refuses bypass in the agent's own settings (Claude `permissions.disableBypassPermissionsMode: "disable"`, Gemini `security.disableYoloMode: true`);
- with `identity: workload`, installs the pinned `halo` and runs `halo ci token --format github`, so the agent calls the Halos gateway with a short-lived workload credential and no long-lived vendor key exists in the repository. The Claude action refuses to start without a key input, so the gateway credential is passed as `anthropic_api_key` (halo-proxy reads `x-api-key`).

`workflow.Check` enforces the first four points and invariant 1 on the rendered bytes (permission-bypass tokens, literal credentials, unpinned actions, missing `permissions: {}`, `write-all`, expressions in scripts); any violation fails the release build.

Console-configured settings extend ADR-0025's vendor plans: `halo admin plan|export` adds manual steps for Claude cloud sessions (enable, network level per environment), Codex cloud (role permission, internet access), Cursor cloud agents and Copilot cloud agent repository access, and reads each explicit repository's Copilot firewall (`GET /repos/{o}/{r}/copilot/cloud-agent/configuration`) as read-only settings diffed against policy. `halo admin apply` never writes them.

### Inventory

A cloud task is normalized to one shape: id `<vendor>:<repo>:<run>` or `cursor:<agent>`, vendor, source, repository, vendor ref, workflow, managed, vendor login, Halos user, status (queued, running, completed, failed, cancelled), tokens, URL, times. Every vendor string passes a strict charset before it is kept.

- **Webhook**: `POST /api/v1/cloud-agents/webhooks/github` (public; 404 without `--cloud-webhook-secret-file`). The `X-Hub-Signature-256` HMAC is verified in constant time against one secret, or two while rotating, over a body capped at 1 MiB. Only `workflow_run` deliveries of a governed workflow are kept: Halos's own file paths, Copilot's `dynamic/copilot-swe-agent/` path (UNVERIFIED), and the vendors' quick-setup files (`claude.yml`, `gemini-cli.yml`, ...), which are recorded as **unmanaged**. Others are acknowledged and dropped.
- **Vendor APIs**: `halo cloud-agents list` without a server reads the Actions runs of each explicit repository and the Cursor key's agents (with usage when budgets need it), bounded per call.
- **Storage**: a task is an audit entry `cloudagent.task` with the task JSON, like the session ledger (ADR-0031): one hash chain, the SIEM export, both backends. The newest version by vendor `updated_at` wins, so a replayed or reordered delivery is answered `stale` and stored nothing.
- **Identity**: `cloudAgents.identities` maps a GitHub login to a Halos user, resolved server-side at read time from current policy. A Cursor task belongs to the key's owner (`--cloud-cursor-user`): Cursor names no user. An unmapped active task raises an `unattributed` alert.
- **Ledger**: a finished task becomes a `session.record` with source `cloudagents` (confidence high), harness `claude-code-action`, `gemini-cli-action`, `copilot-cloud-agent` or `cursor-cloud-agent`, redacted under the default policy (repositories counted, not kept).
- `GET /api/v1/cloud-agents` (read permission) lists tasks updated in the last 7 days (`?active=true` for running ones) with alerts and what is configured.

### Control

- **Kill fan-out**: `POST /api/v1/cloud-agents/kill` (operate permission) `{scope: user|ring|experiment, name, reason, dryRun}`. Reason required; `dryRun` defaults to true and only plans. The ring or experiment of each task's user comes from `ResolveRing`/`AssignVariant` (invariant 3), with groups from the SCIM directory. A real run audits the intent with `AuditStrict` before any vendor call (refused if the audit log is unavailable) and every result after. Calls: GitHub run cancel for the GitHub-hosted vendors (409 reads as already finished), Cursor run cancel; vendors without an API get a manual step. `halo cloud-agents kill --scope --name --reason [--execute]` drives it.
- **Experiment kill**: the existing kill switch answer adds `cloudAgents.activeTasks` and the exact call that cancels them. It never cancels by itself: a gateway kill and a cancel of a running agent are different blast radii.
- **Limits**: on every delivery halo-server evaluates the tasks: disabled vendor, ungoverned vendor, unmanaged workflow, repository or model outside policy, unattributed, `maxConcurrent` per user and per group, and budgets (tokens in the ADR-0017 window, keyed with `budget.Charges`). Each alert involving the delivered task is logged, audited (`cloudagent.alert`) and counted in `halo_server_cloud_agent_alerts_total{vendor,kind}`.
- **Pause**: with `onOverLimit: pause`, the tasks an alert names (the newest past a concurrency limit, the active tasks over a budget, the task of a violation) are paused: the GitHub workflow is disabled (`PUT .../disable`; a human runs `enable`), the Cursor agent archived (unarchive resumes). Copilot has no pause API: a manual step. Every pause is audited (`cloudagent.pause`). halo-server never sends an enable, unarchive or resume.

### Consequences

- Good: one policy governs machine and cloud agents; the workflows a repository runs are reviewed, pinned and signed; a cloud task carries a Halos identity, ring and experiment; a kill reaches GitHub-hosted and Cursor agents; finished tasks land in the session ledger.
- Bad: Codex cloud and Claude cloud sessions have no task API, so they are configured by hand and cannot be listed (beyond ADR-0031's Compliance API session creation) or cancelled. Pausing a GitHub workflow stops it for the whole repository, not only the user over the limit. Repository allowlists cannot stop a copied workflow; inventory alerts on it (unmanaged) after it runs.
- Wildcard repositories (`owner/*`) are not listed through the API; their runs arrive by webhook only.

### Failure modes

- Bad or missing signature: 401, counted as `halo_server_auth_failures_total{flow="cloud_webhook",reason="signature"}`, nothing stored.
- Policy unavailable: 503, nothing stored; GitHub redelivers.
- Audit log unavailable: the task is not stored (500, GitHub redelivers); a kill is refused before any vendor call; a pause result that cannot be audited is logged.
- Vendor API error: the action is `failed` with the redacted error, the others continue; a missing client is `no-client` and nothing is sent.
- A replayed delivery older than the stored task: `stale`, nothing stored.

## Security review

| Risk | Control | Test |
|---|---|---|
| Forged webhook delivery | HMAC-SHA256 over the raw body, constant-time, empty secrets never match, two-secret rotation, GitHub's documented vector | `TestVerifySignature`, `TestCloudWebhook` |
| Replay turns a finished task back to running (false alerts, pointless cancels) | newest `updated_at` wins; older delivery is `stale` | `TestCloudWebhook` (stale replay) |
| Vendor strings reach API paths or terminals | strict charsets for repos, logins, ids, workflow paths; `url.PathEscape`; `Sanitize` on output | `TestParseGitHubEvent` (repo, login injection), `TestCursorNormalize` |
| Workflow injection or privilege | SHA pins, `permissions: {}`, no expressions in scripts, `persist-credentials: false`, bypass and literal credential scan | `TestCheck`, `TestRenderGoldens` |
| Unattended destructive action | kill is dry run by default, reason required, operate permission, audited before any call; automatic actions are pauses only and never resumed | `TestCloudKill`, `TestKillFanOut`, `TestCloudOverLimitPauses` |
| Credentials | files or environment variables only; vendoradmin client (no redirects, https or loopback, redacted errors) | `TestCloudAgentsConfig`, ADR-0025 tests |

## Sources

[^c1]: https://code.claude.com/docs/en/github-actions and https://raw.githubusercontent.com/anthropics/claude-code-action/main/action.yml (checked 2026-10-27)
[^c2]: https://code.claude.com/docs/en/claude-code-on-the-web (checked 2026-10-27)
[^c3]: https://code.claude.com/docs/en/cloud-environments (checked 2026-10-27)
[^o1]: https://developers.openai.com/codex/cloud and https://learn.chatgpt.com/docs/environments/cloud-environments (checked 2026-10-27)
[^o2]: https://developers.openai.com/codex/cloud/internet-access (checked 2026-10-27)
[^h2]: https://docs.github.com/en/rest/actions/workflow-runs and https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries (checked 2026-10-27)
[^h3]: https://docs.github.com/en/rest/actions/workflows (checked 2026-10-27)
[^h4]: https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment (checked 2026-10-27)
[^h5]: https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall and https://docs.github.com/en/rest/copilot/copilot-cloud-agent-management (checked 2026-10-27)
[^h6]: https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-organization/add-copilot-cloud-agent (checked 2026-10-27)
[^u1]: https://cursor.com/docs/background-agent/api/endpoints (Cloud Agents API v1, public beta; checked 2026-10-27)
[^g1]: https://github.com/google-github-actions/run-gemini-cli (README and action.yml; checked 2026-10-27)
