---
title: "ADR-0023: Workload identity federation for headless agents"
description: CI and cloud agents exchange their platform's OIDC token at halo-server for a short-lived, ed25519-signed gateway credential instead of holding a provider API key.
status: accepted
date: 2026-10-21
---

# ADR-0023: Workload identity federation for headless agents

> **Amended 2026-10-21.** "One pattern that does not start with a wildcard" was not a tenant pin: `ref: refs/heads/main` alone, or `repository_owner: acme*`, admitted other organizations' jobs, because a public issuer mints a token with any `aud` for every tenant on it. Every rule must now match one of its issuer's tenant claims exactly (or as `literal/*`): GitHub `repository_owner_id`, `repository_owner`, `repository`, `repository_id`; GitLab.com `namespace_id`, `namespace_path`, `project_id`, `project_path`; Buildkite `organization_id`, `organization_slug`; CircleCI `oidc.circleci.com/org-id`; Google `email`, `sub`; Entra ID `tid`. Other issuers must declare `issuers[].tenantClaim`. GitHub rules that pin only renamable names, or neither `environment` nor `job_workflow_ref`, validate with a warning. See the [guide](/halos/guides/ci-and-cloud-agents/#pinning-the-tenant).

- Status: accepted
- Date: 2026-10-21

## Context and problem statement

Coding agents run more and more without a laptop: Claude Code in GitHub Actions (`anthropics/claude-code-action`, `claude -p`), `codex exec`, `gemini -p`, Copilot's coding agent, scheduled and background agents on cloud runners. They never get `halod`'s managed config, and the gateway only knows humans (an IdP JWT, or a trusted header). The path of least resistance is a long-lived provider API key in a CI secret. That key bypasses everything Halos governs: identity, rings, model allowlist, kill switch, budgets, telemetry attribution and audit. It also never expires and leaks with the repository's secrets.

Every major CI platform and cloud already issues short-lived OIDC tokens that say which workload is running (repository, branch, environment, pipeline, service account). The question is how to turn one into a gateway identity without weakening the gateway's trust model (AGENTS.md invariant 4: cohort comes only from an authenticated identity).

## Decision drivers

- No long-lived secret in CI, ever.
- The gateway decides the cohort from a verified identity only, exactly as for humans.
- Workloads must not be able to pose as people, or as other workloads.
- Short credential lifetime with an explicit ceiling.
- Every credential traceable to the pipeline and the policy rule that allowed it.
- Headless runs keep the ring's permission policy; nothing may emit a bypass mode (invariant 1).
- No new dependencies: reuse the OIDC verifier the gateway already uses.

## Considered options

1. **Gateways trust CI issuers directly.** Each gateway verifies GitHub/GitLab tokens itself. Rejected: every gateway would need the full rule engine and the replay cache, CI tokens are often valid much longer than we want a gateway credential to be, and there would be no single audited decision point.
2. **Static per-pipeline API keys issued by halo-server.** Rejected: long-lived secrets in CI are the problem being solved.
3. **Token exchange at halo-server (RFC 8693) minting a halo-signed credential.** Chosen.
4. **Exchange for a short-lived provider key (Anthropic/OpenAI workload identity, cloud STS).** Rejected as the default: the agent would talk to the provider directly and skip the gateway. It remains possible behind the gateway, where `halo-proxy` holds the provider identity.

## Decision outcome

**Policy.** `halos.yaml` gains an additive `workloads` section (halos.dev/v1, omitted when unset so existing snapshots keep their digest): a default `audience`, trusted `issuers` (`name`, exact `url` = `iss`, optional per-issuer `audience`) and ordered `rules` (`issuer`, `match` claim -> exact value or `path.Match` glob, `subject` template, `groups`, `maxTTLSeconds`), plus `experiments` (default false). Validation requires: an https issuer (http only on loopback); a tenant claim matched exactly per rule (see the amendment above), because public issuers sign tokens for everyone; a subject starting with `workload:` so a workload can never take a human's id; `maxTTLSeconds` at most 3600.

**Exchange.** `POST /api/v1/token/exchange` (form-encoded, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type` jwt or id_token; `actor_token` refused). `halo-server`:

1. reads the unverified `iss` only to pick a trusted issuer, then verifies fully with `identity.OIDCJWT` (go-oidc discovery, cached JWKS refetched on unknown `kid`, `iss`, `aud`, `exp`, `nbf`, alg allowlist RS256/ES256/EdDSA, so no `none` and no `HS*`), then requires `iat` present and not in the future;
2. records the token in a replay cache (`iss` + `jti`, or the token hash when there is no `jti`) until its `exp`; a second exchange is refused;
3. takes the first rule of that issuer whose every match entry holds (missing or non-scalar claims never match) and expands the subject;
4. mints an EdDSA JWT (`typ: halo-workload+jwt`, `iss: halos`, `aud: halos-gateway`, `kind: workload`, `sub`, `groups`, `rule`, `jti`) valid for the rule's TTL (default 15 minutes), signed with a dedicated key (`--workload-key-file`), separate from the release and kill-switch keys;
5. appends `workload.token.exchange` to the hash-chained audit log, fail closed, with the rule, issuer, CI subject, `jti`, ring and the matched claims, never a token. Verified tokens that no rule matches, and replays, append `workload.token.denied`. Unverifiable input is only logged (anyone can send it) and counts toward the per-IP failure limiter.

The response is RFC 8693 (`access_token`, `issued_token_type`, `token_type: Bearer`, `expires_in`) plus `subject`, `groups`, `ring` and `gateway_url` for the client.

**Gateways.** `identity.Options.WorkloadKeys` (PEM, several keys for rotation) wraps the configured verifier: a bearer whose header says `typ: halo-workload+jwt` is verified with ed25519 against a trusted `kid`, exact `iss`/`aud`/`kind`, `exp` with no leeway, `nbf`/`iat` within one minute, and a lifetime cap of one hour; any failure is a 401, never a fall-through. Everything else goes to the human verifier unchanged. The subject carries `Kind: workload`. `halo-proxy` (`identity.workloadPubkeyFile`) and `halo-kong` (`workload_pubkey`) both use it; mode `none` still verifies nobody. Every `x-halo-*` header is stripped as before. `gateway.Decide` gives workload subjects no experiment and no shadow unless `workloads.experiments: true`, so CI traffic never skews experiment evidence; toggles and rings apply as for humans.

**Client.** `halo ci token` gets the job's token (GitHub: `ACTIONS_ID_TOKEN_REQUEST_URL` with the requested audience; otherwise the variable named by `--token-env`, default `HALO_ID_TOKEN`, which GitLab `id_tokens`, Buildkite, CircleCI and cloud metadata fill), exchanges it over https, and exports `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`, `OPENAI_BASE_URL`/`OPENAI_API_KEY`, `HALO_GATEWAY_TOKEN`, `GOOGLE_GEMINI_BASE_URL`/`GEMINI_API_KEY`, `HALO_RING`, `HALO_SUBJECT`. `--format github` emits `::add-mask::` first and appends to `$GITHUB_ENV`; values containing newlines are refused. `halo ci config` writes one harness's files from the ring's release (same rendering and guardrails), refuses any file containing a bypass mode, and tells the operator to grant job tools with `--allowedTools` rather than a bypass flag.

### Consequences

- Good: no provider key in CI; every agent call in CI is attributable to a repository/pipeline and a policy rule, and goes through rings, allowlist, kill switch and gateway telemetry.
- Good: a policy PR revokes a pipeline; credentials die within `maxTTLSeconds` (at most an hour), or at once by rotating the workload key at the gateways.
- Good: a dedicated signing key; stealing it allows minting workload credentials only, not releases or kills.
- Bad: the replay cache is per process. With several `halo-server` replicas a captured CI token can be exchanged once per replica within its lifetime. Sharing it belongs with the HA work (ADR-0021).
- Bad: a GitLab `id_tokens` value is fixed per job, so a job can exchange it only once; it must reuse the exported variables.
- Bad: issued credentials cannot be revoked individually before `exp`; there is no revocation list for them.
- Neutral: `halo-server` makes outbound discovery/JWKS requests to the trusted issuers.

## Implementation status (2026-10-21)

| Commitment | Code | Test | Status |
|---|---|---|---|
| `workloads` policy, schema, validation (https issuer, pinned rule, `workload:` subject, TTL cap) | `internal/policy/workloads.go`, `schemas/halos.schema.json` | `internal/policy/workloads_test.go` `TestValidateWorkloads`, `TestSchemaWorkloads`, `TestLoadWorkloads`, `TestCIAgentsExampleWorkloads` | Done |
| Exact/glob claim rules, subject templates | `policy.Workloads.MatchWorkload` | `TestMatchWorkloadGlobs`, `TestWorkloadSubjectExpansion` | Done |
| RFC 8693 endpoint; verification negatives (issuer, aud, exp, nbf, iat, none, HS256 confusion, unknown kid); replay; claim mismatch; audit without tokens | `internal/server/tokenexchange.go` | `internal/server/tokenexchange_test.go` `TestTokenExchangeRejectsBadSubjectTokens`, `TestTokenExchangeMintsGatewayCredential`, `TestTokenExchangeRequestShape`, `TestReplayCacheBounded`, `TestTokenExchangeDisabledWithoutKey` | Done |
| Workload credential sign/verify, gateway dispatch | `internal/identity/workload.go`, `resolve.go` | `internal/identity/workload_test.go` | Done |
| `halo-proxy` accepts it; `x-halo-*` stripped; expiry; no experiment by default | `cmd/halo-proxy/config.go`, `internal/gateway/decision.go`, `prepare.go` | `cmd/halo-proxy/workload_test.go` | Done |
| `halo-kong` accepts it | `cmd/halo-kong/main.go` (`workload_pubkey`) | shares `identity.New`; no Kong-specific test | Done, thin |
| `halo ci token` / `halo ci config` | `cmd/halo/cmd_ci.go` | `cmd/halo/cmd_ci_test.go` | Done |
| GitHub composite action, GitLab snippet | `examples/ci-agents/` | `TestExamplesValidate` (policy only) | Done; not run on real runners |
| Shared replay cache across replicas | | | Gap (ADR-0021) |

## Amended 2026-10-21 (security review)

- **`workload:` is reserved for workload credentials.** Human identities starting with `workload:` (any case) are refused in OIDC (`identity.SubjectFromClaims`), trusted-header mode and SCIM `userName` creation (`identity.CheckHumanID`). Tests: `TestSubjectFromClaims`, `TestTrustedHeader`, `TestSCIMResourceRules`.
- **Workloads and the SCIM directory.** With a gateway directory configured (ADR-0022), workload subjects skip the directory lookup and keep `Kind: workload`; before, every workload resolved to an unknown caller. The kind always comes from the verified credential, never from the directory. Tests: `TestDirectoryClientWorkloads`, `TestDirectoryKeepsWorkloads`.

## Amended 2026-10-21 (second security review)

- **Tenant pinning is enforced at runtime.** halo-server loaded policy without validating it, so a policy that never ran `halo validate` could mint for an unpinned rule. Now `Workloads.MatchWorkload` skips any rule that pins no tenant of a declared issuer (logged; `halo_server_workload_rules_skipped_total`), and halo-server and the gateways run `policy.SecurityIssues` (the error-severity `workloads`, `units` and `delegation` findings) on every load, refusing to activate such a policy and keeping the last good one (`halo_server_policy_refused_total`, `halo_proxy_policy_refused_total`). `halo release build` and `publish` already refused invalid policy; that is now tested. Tests: `TestMatchWorkloadSkipsUnpinnedRules`, `TestPolicyLoadRefusesSecurityErrors`, `TestSnapshotRefusesSecurityErrors`, `TestReleaseBuildRefusesUnpinnedWorkload`.
- **Rename warnings beyond GitHub.** A GitLab.com rule pinning only `namespace_path`/`project_path`, or a Buildkite rule pinning only `organization_slug`, now warns like a GitHub name-only rule: add `namespace_id`/`project_id` or `organization_id`. Test: `TestValidateWorkloadsGitHubWarnings`.
- **Separate failed-auth budget.** Exchange failures count against their own per-IP budget, so they cannot lock gateways out of halo-server (ADR-0022).
