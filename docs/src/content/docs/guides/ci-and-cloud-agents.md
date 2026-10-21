---
title: CI and cloud agents
description: Run Claude Code, Codex and Gemini CLI in GitHub Actions, GitLab CI, Buildkite, CircleCI or cloud workloads through the gateway, with a short-lived credential from the job's own OIDC token instead of a provider API key.
---

:::caution[UNVERIFIED against live CI providers]
The exchange, the gateway verifier and `halo ci` are covered by unit tests against a local OIDC issuer (`internal/server/tokenexchange_test.go`, `cmd/halo-proxy/workload_test.go`, `cmd/halo/cmd_ci_test.go`). Issuer URLs and claim names were checked against each provider's documentation and discovery document. No token from a real GitHub, GitLab, Buildkite, CircleCI or cloud runner has been exchanged yet.
:::

Agents increasingly run without a laptop: `claude -p` or `anthropics/claude-code-action` in GitHub Actions, `codex exec`, `gemini -p`, scheduled and background agents. They never see `halod`, so the usual shortcut is a long-lived provider API key in a CI secret. That key skips the gateway's identity, rings, model allowlist, kill switch and audit.

Halos replaces it with workload identity federation ([ADR-0023](/halos/adr/0023-workload-identity-federation/)):

1. The job gets an OIDC token from its CI provider. It names the repository, branch, environment or pipeline.
2. `halo ci token` sends it to `halo-server` `POST /api/v1/token/exchange` (RFC 8693).
3. `halo-server` verifies it, finds the first `workloads` rule that matches its claims, audits the exchange and returns a gateway credential: 15 minutes by default, never more than 1 hour.
4. The harness calls the gateway with that credential. The gateway treats it like a verified human: ring from its groups, model allowlist, kill switch, telemetry. Workloads get control routing in experiments unless policy opts them in.

## 1. Policy

Add `workloads` to `halos.yaml` ([schema](/halos/reference/policy/halos/); full example in `examples/ci-agents/halos.yaml`):

```yaml
workloads:
  audience: halos              # the aud CI tokens must carry
  issuers:
    - name: github
      url: https://token.actions.githubusercontent.com
    - name: gitlab
      url: https://gitlab.com
  rules:
    - name: github-main
      issuer: github
      match:                   # every entry must hold; exact or glob, * never crosses /
        repository_owner_id: "123456789"   # the tenant pin: acme's immutable org id
        repository: acme/*
        ref: refs/heads/main
        environment: ai-agents
      subject: workload:gh:{repository}   # {claim} expands; must start with workload:
      groups: [ci-agents]                 # ring membership, like IdP groups
      maxTTLSeconds: 1800                 # default 900, at most 3600
  experiments: false           # default: workloads are never in experiments
```

### Pinning the tenant

GitHub, GitLab.com, Buildkite, CircleCI and Google sign a token for every customer, with whatever `aud` the job asks for. The audience proves nothing about who you are, so `ref: refs/heads/main` alone would admit every repository on GitHub, and `repository_owner: acme*` would admit `acme-evil`. `halo validate` therefore requires every rule to match one of its issuer's **tenant claims** exactly, or as `literal/*` (one path segment under a literal, such as `repository: acme/*`):

| Issuer | Tenant claims |
|---|---|
| GitHub Actions (`token.actions.githubusercontent.com`, also `/<enterprise>`) | `repository_owner_id`, `repository_owner`, `repository`, `repository_id` |
| GitLab.com | `namespace_id`, `namespace_path`, `project_id`, `project_path` |
| Buildkite | `organization_id`, `organization_slug` |
| CircleCI (`oidc.circleci.com/org/<org-id>`) | `oidc.circleci.com/org-id` |
| Google (`accounts.google.com`) | `email`, `sub` |
| Entra ID (`login.microsoftonline.com`, `sts.windows.net`) | `tid` |

Any other issuer (self-managed GitLab, AWS, AKS, your own) must name its tenant claim, and every rule of it must pin that claim:

```yaml
  issuers:
    - name: aws
      url: https://0f1e2d3c.tokens.sts.global.api.aws
      tenantClaim: sub         # rules must match sub exactly, e.g. the role ARN
```

On a known issuer `tenantClaim` may narrow the choice to one of its tenant claims (for example `repository_owner_id`), never widen it.

**Prefer immutable ids.** `repository_owner` and `repository` are names. If `acme` renames or deletes its organization, anyone can register `acme` and its workflows then match. `repository_owner_id` and `repository_id` never change (`gh api orgs/acme --jq .id`, `gh api repos/acme/app --jq .id`). `halo validate` warns on a GitHub rule that pins names only. The same holds for GitLab: prefer `namespace_id` or `project_id`.

**Forks and `pull_request_target`.** A pinned owner or repository says which repository's workflow runs, not whose code. `pull_request_target` and `workflow_run` workflows run on the base branch (`ref: refs/heads/main`), with the base repository's identity, and can be made to check out and run a fork's code. Pinning `ref` does not stop that. For anything that reaches production models or spends real budget, also pin one of:

- `environment: <name>` with required reviewers on the GitHub environment, so a human approves each run;
- `job_workflow_ref: acme/ai-platform/.github/workflows/agent.yml@refs/heads/main`, a reusable workflow the platform team owns, so only that workflow's jobs match;
- `event_name: push` (or `workflow_dispatch`), so pull-request-triggered runs never match.

`halo validate` warns on a GitHub rule that pins neither `environment` nor `job_workflow_ref`. On GitLab, `ref_protected: "true"` plus a protected `environment` plays the same role; note that in a merge request pipeline `project_path` and `namespace_path` name the source project.

### Issuers and claims

| Provider | `url` (exact `iss`) | Claims worth matching (tenant claim first) | Getting the token |
|---|---|---|---|
| GitHub Actions | `https://token.actions.githubusercontent.com` (GHE with a custom issuer: `.../<enterprise>`) | `repository_owner_id`, `repository_owner`, `repository`, `repository_id`, `ref`, `environment`, `job_workflow_ref`, `event_name` | `permissions: id-token: write`; `halo ci token` requests it with your audience |
| GitLab | `https://gitlab.com` or your instance URL | `namespace_id`, `namespace_path`, `project_id`, `project_path`, `ref`, `ref_protected`, `environment`, `ci_config_ref_uri` (self-managed: set `tenantClaim`) | `id_tokens: HALO_ID_TOKEN: {aud: halos}` |
| Buildkite | `https://agent.buildkite.com` | `organization_id`, `organization_slug`, `pipeline_slug`, `build_branch` | `HALO_ID_TOKEN=$(buildkite-agent oidc request-token --audience halos)` |
| CircleCI | `https://oidc.circleci.com/org/<org-id>` | `oidc.circleci.com/org-id`, `oidc.circleci.com/project-id`, `oidc.circleci.com/vcs-origin`, `oidc.circleci.com/vcs-ref` (V2 token) | `HALO_ID_TOKEN=$CIRCLE_OIDC_TOKEN_V2`; the default `aud` is the org id, so set the issuer's `audience` to it |
| Google Cloud | `https://accounts.google.com` | `email` (service account), `sub` | metadata server `.../service-accounts/default/identity?audience=halos` |
| AWS | `https://<id>.tokens.sts.global.api.aws` (per account) | `sub` (role ARN; set `tenantClaim: sub`) | STS `GetWebIdentityToken` (IAM outbound identity federation) |
| Azure AKS workload identity | `https://<region>.oic.prod-aks.azure.com/<tenant>/<uuid>/` | `sub` (`system:serviceaccount:<ns>:<sa>`; set `tenantClaim: sub`) | projected service account token |

Sources: GitHub [OIDC reference](https://docs.github.com/en/actions/reference/security/oidc), GitLab [ID token authentication](https://docs.gitlab.com/ci/secrets/id_token_authentication/), Buildkite [`oidc request-token`](https://buildkite.com/docs/agent/v3/cli-oidc), CircleCI [OIDC tokens](https://circleci.com/docs/guides/permissions-authentication/openid-connect-tokens/), Google [instance identity](https://cloud.google.com/compute/docs/instances/verifying-instance-identity), AWS [outbound identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound.html), Azure [AKS workload identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster). The `url` must equal the token's `iss` byte for byte, trailing slash included. Only string, boolean and number claims can be matched; arrays and objects never match.

## 2. halo-server and the gateway

```bash
halo keys generate --name workload             # workload.key / workload.pub; a new key, not the release or kill key
halo-server ... --workload-key-file workload.key
```

Without `--workload-key-file`, or without `workloads` in policy, the endpoint answers 404.

Give the gateways the public half:

- `halo-proxy`: `identity.workloadPubkeyFile: /etc/halos/workload.pub` (or `--workload-pubkey-file`). Several PEM blocks in the file allow rotation: add the new key, roll `halo-server`, remove the old one after an hour.
- `halo-kong`: `workload_pubkey` (PEM, or `{vault://env/HALO_WORKLOAD_PUBKEY}`).

Workload credentials are accepted alongside the normal identity mode (`jwt` or `trusted_header`). In mode `none` nobody is verified, workloads included.

## 3. The job

### GitHub Actions

`examples/ci-agents/.github/actions/halo-ci/action.yml` is a composite action: it installs `halo`, exchanges the token and installs the ring's managed config.

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: actions/checkout@v4
  - uses: ./.github/actions/halo-ci
    with:
      server: https://halo.acme.example
      harness: claude-code
      policy-dir: .halos-policy        # a checkout of the policy repo; omit to skip config
  - run: npm install -g @anthropic-ai/claude-code
  - run: claude -p "Make go test ./... pass" --allowedTools "Read,Edit,Bash(go test:*)"
```

`halo ci token --format github` prints `::add-mask::<credential>` before anything else, so the value is masked in the log, then appends to `$GITHUB_ENV`:

| Variable | Used by |
|---|---|
| `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN` | Claude Code (`Authorization: Bearer`) |
| `OPENAI_BASE_URL` (gateway + `/v1`), `OPENAI_API_KEY` | OpenAI-compatible clients |
| `HALO_GATEWAY_TOKEN` | Codex (the rendered `env_key`) |
| `GOOGLE_GEMINI_BASE_URL`, `GEMINI_API_KEY` | Gemini CLI (sent as `x-goog-api-key`, verified like a bearer token) |
| `HALO_RING`, `HALO_SUBJECT` | `halo ci config`, logs |

Do not also set `ANTHROPIC_API_KEY` or another provider key in the job.

With `anthropics/claude-code-action`, keep the env from the step above (the action forwards `ANTHROPIC_BASE_URL`) and pass the credential as its key: `anthropic_api_key: ${{ env.HALO_GATEWAY_TOKEN }}`. The gateway accepts `x-api-key` exactly like a bearer token. Tool permissions go in `claude_args: --allowedTools ...`.

### GitLab CI

```yaml
ai-review:
  id_tokens:
    HALO_ID_TOKEN:
      aud: halos
  script:
    - eval "$(halo ci token --format env)"       # credential never echoed
    - halo ci config --policy-dir policy --harness codex --ring "$HALO_RING" --os linux --out /
    - codex exec "Review this merge request"
```

Full file: `examples/ci-agents/.gitlab/halo-ci.yml`. Buildkite, CircleCI and cloud workloads use the same `--format env` path with the token in `HALO_ID_TOKEN` (`--token-env` picks another variable).

## 4. Headless permissions

`halo ci config --harness <h> --ring <ring> --out /` writes only that harness's files from the ring's release: the same bundle laptops get, the same guardrails, and never `bypassPermissions` or `danger-full-access` (it refuses to write a file containing either). Install to `/` (with `sudo` on hosted runners) so the files land where the harness reads managed settings. Managed settings take precedence over anything a pull request adds under `.claude/`; permission rules from every scope still merge and `deny` wins, so keep risky tools in the profile's `deny`.

Nothing can prompt in a headless run. A tool call that would need approval is denied, so:

- Keep the ring's profile mode (`default`, `acceptEdits` or `plan`). Do not pass `--dangerously-skip-permissions` or `--permission-mode bypassPermissions`; the guardrails exist so that CI cannot opt out.
- Grant each job only what it needs with `claude -p ... --allowedTools "Read,Edit,Bash(go test:*)"`. The profile's `deny` rules still win.
- Prefer one rule per pipeline purpose, each with its own `groups`, so review bots and fix bots land on different rings and budgets.

## Operating it

- **Audit.** `GET /api/v1/audit?action=workload.token.exchange` lists every credential minted: subject, rule, issuer, matched claims, ring, expiry. `workload.token.denied` lists verified tokens no rule matched, and replays.
- **Revoke.** Remove or narrow the rule (a policy PR); new exchanges stop at once. Credentials already issued live until `exp` (at most `maxTTLSeconds`). To cut them off sooner, rotate the workload key at the gateways.
- **Replay.** Each CI token is exchanged once. Request a fresh one per `halo ci token` call (GitHub does this automatically; a GitLab `id_tokens` value is fixed per job, so exchange it once and reuse the exported variables).
- **Several `halo-server` replicas.** The replay cache is per process: a captured token could be exchanged once per replica within its lifetime.
