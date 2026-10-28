---
title: Cloud and background agents
description: Govern coding agents that run on vendor or CI infrastructure (Claude Code GitHub Action and cloud sessions, Codex cloud, Copilot cloud agent, Cursor cloud agents, Gemini CLI GitHub Action) with the same policy, identities, kill switch and budgets.
---

Some agents never run on a machine `halod` manages: the Claude Code GitHub Action answering `@claude`, the Copilot cloud agent working an assigned issue, a Codex cloud task or a Cursor cloud agent started from a browser. `cloudAgents` in `halos.yaml` governs them ([ADR-0034](/halos/adr/0034-cloud-agent-governance/)). For CI jobs that run a harness CLI themselves, see [CI and cloud agents](/halos/guides/ci-and-cloud-agents/).

## What each vendor allows

| Vendor | Halos renders | Inventory | Kill (cancel) | Pause | Egress |
|---|---|---|---|---|---|
| Claude Code GitHub Action | `.github/workflows/halos-claude.yml` | webhook, Actions API | yes | disable workflow | runner only |
| Claude Code cloud sessions | console steps | session creation via the [session ledger](/halos/guides/session-ledger/) | no API | no API | console, per environment |
| Codex cloud | console steps | no API | no API | no API | console, per environment |
| Copilot cloud agent | `.github/workflows/copilot-setup-steps.yml` + console steps | webhook | Actions cancel (effect UNVERIFIED) | no API | console firewall, read back per repository |
| Cursor cloud agents | console steps | Cloud Agents API (key owner's agents) | yes | archive | none documented |
| Gemini CLI GitHub Action | `.github/workflows/halos-gemini.yml` | webhook, Actions API | yes | disable workflow | runner only |

Anything a vendor cannot enforce is a warning in `halo validate`, `halo cloud-agents render` and the release manifest, never silently dropped.

## 1. Policy

```yaml
cloudAgents:
  identities:                       # vendor login -> Halos user (rings, experiments, budgets)
    - {user: alice@acme.com, github: alice-acme}
  claude:
    enabled: true
    repos: [acme-corp/payments-api, acme-corp/web]   # or acme-corp/*
    models: [claude-sonnet-5]
    maxConcurrent: {perUser: 2}
    network: {mode: allowlist, recommended: true, allow: [packages.acme.example]}
    timeoutMinutes: 30
  copilot:
    enabled: true
    repos: [acme-corp/*]
    network: {mode: allowlist, recommended: true}
  cursor:
    enabled: true
    budgets:
      - {name: cursor-daily, scope: user, window: day, limitTokens: 5000000}
    onOverLimit: pause              # reversible; halo-server never resumes
  codex:
    enabled: false
  gemini:
    enabled: true
    models: [gemini-2.5-pro]
    version: 0.34.0
```

- `budgets` take the [cost budget](/halos/guides/cost-budgets/) fields. Only Cursor reports usage (tokens), so only `limitTokens` counts, and `action` is `warn`: `onOverLimit` decides what happens.
- `network.mode` is `none`, `allowlist` (`allow` plus the vendor's dependency list with `recommended`) or `full` (warned).
- `identity: workload` (claude, gemini) makes the workflow exchange its GitHub OIDC token at `halo-server` and call the model through the Halos gateway with a short-lived credential, so no vendor API key lives in the repository. It needs a GitHub Actions issuer under `workloads`, a gateway, `cloudAgents.server` and `cloudAgents.haloVersion`.

## 2. Repository workflows

```bash
halo cloud-agents render --out ../payments-api   # writes .github/workflows/halos-claude.yml, ...
```

Open a pull request with the files in each repository `repos` names. Every `uses:` is pinned to a commit SHA, the workflow starts from `permissions: {}`, jobs get only the permissions their vendor documents, checkout does not persist credentials, and the agent's own bypass mode is refused. The same files are signed into every release (`manifest.json` `cloudAgents`), so a reviewer can verify what was rendered; `halod` never writes them to machines.

Delete the vendors' quick-setup workflows (`claude.yml`, `gemini-cli.yml`): runs of those are reported as `unmanaged`.

## 3. Console settings

With `vendorAdmin` configured ([vendor admin sync](/halos/guides/vendor-admin-sync/)), `halo admin plan` and `halo admin export` add the cloud agent steps: Claude cloud sessions on or off and their environment network level, Codex cloud access and internet access, Cursor cloud agents, and Copilot cloud agent repository access. For each explicit Copilot repository it reads the live firewall and reports drift. None of these are written by `halo admin apply`: no vendor publishes a write API for them.

## 4. Inventory

Add a webhook to the GitHub organization (or each repository): payload URL `https://halo.acme.example/api/v1/cloud-agents/webhooks/github`, content type `application/json`, a secret, and the **Workflow runs** event.

```bash
openssl rand -hex 32 > /etc/halos/github-webhook.secret     # also paste it into GitHub
halo-server ... \
  --cloud-webhook-secret-file /etc/halos/github-webhook.secret \
  --cloud-github-token-file /etc/halos/github-actions.token \
  --cloud-cursor-token-file /etc/halos/cursor.key --cloud-cursor-user svc-cursor@acme.com
```

Every delivery is verified (`X-Hub-Signature-256`, two secrets while rotating), stored in the audit chain, mapped to a Halos user, and checked against policy. Finished tasks also become [session ledger](/halos/guides/session-ledger/) records. The GitHub token needs `actions: write` on the governed repositories (cancel and disable); without it, kills and pauses are planned but not sent.

```bash
halo cloud-agents list --server https://halo.acme.example --active    # HALO_SESSION, read permission
HALO_CLOUD_GITHUB_TOKEN=... halo cloud-agents list --since 24h        # no server: read the vendor APIs directly
```

`list` exits 2 when an alert is raised: a disabled or ungoverned vendor, an unmanaged workflow, a repository or model outside policy, an unattributed task, a concurrency limit, or a budget.

## 5. Kill and pause

```bash
halo cloud-agents kill --scope ring --name ring1-canary --reason "INC-1234"            # plan (dry run)
halo cloud-agents kill --scope ring --name ring1-canary --reason "INC-1234" --execute  # cancel
```

Scopes are `user`, `ring` and `experiment`; a task's ring and variant come from its user's identity, exactly as the gateway assigns them. The kill needs the operate permission, is audited before any vendor call, and each result after. A task no identity maps cannot be reached by a ring or experiment kill: the answer counts them.

Killing an experiment (`POST /api/v1/experiments/{name}/kill`) reports how many cloud tasks its users are running and the call that cancels them; it does not cancel them itself.

With `onOverLimit: pause`, halo-server pauses the tasks an alert names: it disables the GitHub workflow (for the whole repository) or archives the Cursor agent. Resuming is yours: `gh workflow enable halos-claude.yml -R acme-corp/web`, or unarchive in Cursor. Watch `halo_server_cloud_agent_alerts_total{vendor,kind}`.

## Limits

- Codex cloud and Claude cloud sessions have no public task API: no inventory, no cancel.
- Copilot cloud agent runs are recognized by an observed (undocumented) workflow path, and whether an Actions cancel stops the session is not verified.
- Cursor lists only the API key owner's agents.
- `owner/*` repositories are not listed through the API; their runs arrive by webhook only.
