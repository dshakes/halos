---
title: "ADR-0024: Agent identity and delegation for multi-agent and A2A"
description: A verified Halos credential is exchanged for a short-lived agent credential carrying an RFC 8693 act chain; the gateway routes it as the root principal, policy bounds depth, models and tools, and remote A2A agents are an allowlist with pinned AgentCard digests.
status: accepted
date: 2026-10-21
---

# ADR-0024: Agent identity and delegation for multi-agent and A2A

- Status: accepted
- Date: 2026-10-21

## Context and problem statement

Coding agents spawn subagents, call remote agents over Agent2Agent (A2A), and run as background or cloud agents. Halos sees a human (OIDC) or a CI workload (ADR-0023), never "agent X acting for human Y via agent Z". That leaves four risks:

- **Confused deputy.** A subagent holding its parent's credential can do anything the parent can.
- **Unbounded delegation.** Nothing limits how deep agents spawn agents, or for how long.
- **Wrong principal.** Budgets, posture and audit are attributed to whoever holds the token. An agent with a credential of its own could escape a budget, a posture gate or an experiment arm.
- **Unvetted remote agents.** An agent can call any A2A endpoint, and an AgentCard can change under it.

## Specifications checked (2026-10-21)

- **A2A.** Specification at `a2aproject/A2A` `docs/specification.md`. Latest released version 1.0.0 (https://a2a-protocol.org/v1.0.0/specification), GitHub release v1.0.1 on 2026-05-28. It is a Linux Foundation project.
  - **Discovery (section 8.2).** The card is at `https://{domain}/.well-known/agent-card.json`, in a registry, or configured directly.
  - **AgentCard (sections 4.4.1 and 8.5).** `name`, `description`, `version`, `supportedInterfaces[]` (`url`, `protocolBinding` `JSONRPC` / `GRPC` / `HTTP+JSON`, `protocolVersion`), `capabilities`, `securitySchemes`, `securityRequirements`, `skills[]` (`id`, ...) and `signatures[]`.
  - **Auth (section 7).** Production deployments MUST use HTTPS or TLS. `securitySchemes` declares API key, HTTP auth, OAuth 2.0, OpenID Connect or mutual TLS. The client gets credentials out of band and sends them in protocol headers on every request (for example `Authorization: Bearer`). Identity is handled at the protocol layer, not inside A2A messages.
  - **Signed cards (section 8.4).** A card MAY be signed. Each `AgentCardSignature` holds `protected` (base64url JWS protected header with `alg`, `typ: JOSE`, `kid`, optional `jku`), `signature`, and an optional unprotected `header`. The payload is the RFC 8785 (JCS) canonical card, without `signatures` and with default-valued fields dropped. Clients SHOULD verify at least one signature, and MAY keep a trusted key store.
- **RFC 8693.**
  - **`act` (section 4.1).** The top-level `act` is the current actor and nested `act` claims are prior actors, least recent deepest. Access control MUST consider only the top-level claims and the current actor. Prior actors are informational.
  - **`may_act` (section 4.4).** It states who may act for the subject.
  - Token-type URIs and extension parameters are open (section 3; RFC 6749 section 8.2).
- **OpenTelemetry GenAI semantic conventions v1.40.0.** `gen_ai.agent.name` is defined (Development stability) on agent spans (`create_agent`, `invoke_agent`, in `gen-ai-agent-spans.md`). It is not listed on inference spans.
- **Harness settings.**
  - Gemini CLI documents remote A2A subagents (`docs/core/remote-agents.md`): Markdown files in `~/.gemini/agents/` or `.gemini/agents/` with `kind: remote` and `agent_card_url` or `agent_card_json`. It has no system-level allowlist. `experimental.enableAgents: false` turns off every subagent.
  - Claude Code (sub-agents and settings docs), Codex (config reference) and Copilot CLI (command reference) document no A2A or remote-agent setting.

## Decision drivers

- Invariant 4: cohort comes only from an authenticated identity. An agent never chooses its ring, arm or budget.
- Scope only narrows down a chain. Lifetime never outlives the parent.
- One verifier for halo-server and both gateways. No new key, no new dependency.
- Every delegation and every refusal is audited with the full chain.
- Invariant 2 for remote agents: warn where a harness cannot render the allowlist, never drop it silently.

## Considered options

1. **Agents reuse the parent's credential.** Rejected: this is the confused deputy, and there is no chain and no bound.
2. **Agents get credentials of their own (a workload rule per agent).** Rejected: the agent becomes the principal, so budgets, posture and arms detach from the human or pipeline it serves.
3. **RFC 8693 delegation at halo-server.** The subject stays the root. The agent chain is an `act` claim. Policy bounds depth, lifetime, models and tools. Chosen.
4. **Put `may_act` in parent tokens.** Rejected for now: humans authenticate with IdP tokens Halos does not mint. Policy `agents.actors` is the central `may_act`.

## Decision outcome

### Policy

`halos.yaml` gains an additive `agents` section (omitted when unset, so existing snapshot digests do not change):

- `maxDepth`: default 2, ceiling 5.
- `maxTTLSeconds`: default 900, ceiling 3600.
- `experiments`: default false.
- `allowedModels`: gateway aliases.
- `deniedTools`.
- `actors[]`: `name`, optional `harnesses`, `groups` (the root must hold one), `models` (narrows `allowedModels`).
- `remote[]`: `name`, https `cardURL`, `digest` (required, `sha256:<hex>`), `publicKey` (PEM) or `jwksURL`, `skills`, `rings`, `units`.

Errors under `agents` are security issues (`policy.SecurityIssues`): halo-server and the gateways refuse to activate such a policy and keep the last good one.

Profiles and unit overlays gain `agents: {maxDepth, remote}`. They may only lower the depth and narrow the remote list. `Loosenings` reports a unit that raises `maxDepth` above its parent's effective value, adds a remote agent its parent does not allow, or drops the parent's list (internal/policy/unit.go).

### Exchange

`POST /api/v1/token/exchange` with `actor_id` (Halos extension parameters `actor_id`, `actor_harness`, `actor_session`, `expires_in`, and RFC 8693 `scope`). The `subject_token` is one of:

- a `halo_session` cookie value (`subject_token_type=urn:halos:params:oauth:token-type:session`);
- a workload credential;
- a delegated credential.

halo-server checks, in order:

1. It verifies the parent.
   - Session: HMAC, expiry, the revocation epoch, and the SCIM directory (inactive is refused).
   - Workload or delegated credential: Ed25519 with the workload key, `typ`, `iss`, `aud`, expiry and the lifetime cap.
   - A human root of a delegated credential is checked again: a session revoked after `auth_time`, or a deprovisioned user, kills the whole chain.
2. The actor must be in `agents.actors`, with the harness and root groups it allows.
3. The chain (parent's plus this actor) must have no agent twice (a cycle) and stay within the effective maximum depth: the org cap, lowered by the root's ring profile and unit chain.
4. Scope only narrows.
   - `scope=model:<alias>` entries must be within the parent's scope, `allowedModels` and the actor's `models`. An empty intersection is refused, never widened to "all".
   - `group:` entries must be held by the parent, and narrowing groups is refused too. In Halos, groups decide the ring, toggles and group budgets, so dropping one could move an agent out of a gate.
   - The credential has no budget of its own. Every call is charged to the root's user, group, ring and org counters (ADR-0017).
5. TTL is at most the lesser of `maxTTLSeconds` and the parent's remaining lifetime. A longer `expires_in` is refused, not clamped.
6. It mints an EdDSA JWT (`typ: halo-agent+jwt`, `kind: agent`, `sub` and `groups` of the root, `root_kind`, nested `act` with `sub: agent:<name>`, `harness` and `session`, plus `models`, `auth_time`, `parent_jti` and `jti`), signed with the workload key. Unknown claims are refused at verification.
7. It appends `agent.token.exchange` to the audit chain, fail closed. The record holds the root, `via`, the full chain with harnesses and sessions, depth, ring, unit, models, TTL, `jti` and `parent_jti`, never a token. Policy refusals append `agent.token.denied` with the chain and the reason.

### Gateways

`identity.WorkloadJWT`, already used by halo-proxy and halo-kong, dispatches `typ: halo-agent+jwt` to `VerifyDelegatedToken`. halo-server uses the same function. A failure is a 401, never a fall-through to the human verifier. The subject is the root (`ID`, `Groups`, `Kind`) with `Delegation` attached, so:

- Ring, toggles, posture and budgets are the root's.
- A SCIM directory looks the root up: an agent of a deprovisioned user gets a 403.
- Experiments and shadow are skipped unless `agents.experiments` is true. A workload root also needs `workloads.experiments`. When enrolled, the agent gets exactly its root's arm (same hash).

The gateway applies current policy on every model call. A refusal is a 400 `agent_not_permitted`. The checks are:

- The agent is still in `agents.actors`.
- The depth is within the current org `maxDepth`.
- The model is within the credential scope, `allowedModels` and the actor's `models`.
- No tool in `tools[]` is in `deniedTools`. Keys are matched case-insensitively and duplicate keys all count, so a body cannot show the gateway one tool list and the upstream another.

`x-halo-actor` (the chain) and `x-halo-actor-depth` are gateway-owned. Client copies are always cleared and the verified values stamped.

Telemetry:

- `halo.gateway.*` series and GenAI metrics carry `halo.actor.agent`, a policy-bounded name. The series also carry `halo.actor.depth`.
- Spans also carry `halo.actor.chain` and `gen_ai.agent.name`. This is the registry attribute v1.40 defines for agent spans, set on the inference span the agent caused.
- `halo.unit` stays the root's hash.

### Remote agents (A2A)

- **`halo agents verify <card-url>`** fetches a card over https only: at most 256 KB, a timeout, no proxy, at most three redirects, all to the same host and https. The dialed address must be public unless `--allow-private` (checked at connect time, so DNS rebinding cannot reach an internal service).
  - It prints the RFC 8785 digest to pin. A card pinned with `publicKey` or `jwksURL` must carry a JWS signature that verifies: EdDSA, ES256, ES384, RS256 or PS256, with `kid` matched against JWKS keys.
  - A `jku` in the card is never followed, and `crit` headers are refused.
  - With `--policy-dir` the `agents.remote` entry supplies the pins, and missing allowed skills fail the check.
- **Release pin.** A ring release manifest lists the remote agents its members (or listed units) may call, with each card digest. It is signed with the release, so a changed card is a policy change.
- **Rendering.** No harness has a system-level A2A allowlist setting. Each harness gets a manifest warning, and Gemini CLI's names its per-user files and `experimental.enableAgents`.
- **Egress decision API.** `POST /api/v1/agents/egress` on halo-server. The bearer is a workload or delegated credential signed by this server, and the body is `{"agent" | "url", "skill"}`. It answers `{allow, agent, digest, reason, ring, unit}` for the root's ring, unit and profile. Each decision is audited (`agent.egress.allow` / `agent.egress.deny`). This route is reviewed onto the public-routes list (bearer-authenticated, ADR-0015).

### Consequences

- **Good.**
  - An agent can never spend outside its root's budget, skip its root's posture gate, or pick an arm.
  - Every model call names the agent chain that made it.
  - Delegation depth and lifetime are bounded twice: at issuance and at the gateway.
- **Good.** A remote agent is a reviewed policy entry with a pinned card. A card change fails `halo agents verify` in CI.
- **Bad.**
  - Delegated credentials cannot be revoked one by one before `exp`. Their lifetime is capped, removing an actor or lowering `maxDepth` takes effect at the next gateway policy load, and deprovisioning the root takes effect at the next directory lookup.
- **Bad.** The gateway applies the org `maxDepth`. A profile or unit `maxDepth` is enforced at issuance only, so a lowered unit cap takes effect as credentials expire (at most `maxTTLSeconds`).
- **Bad.** Only the halo_session cookie and Halos credentials are accepted as parents. A human whose gateway credential is an IdP token must get a session first, from the portal login or `HALO_SESSION`.
- **Bad.** The egress decision is advisory unless an egress proxy enforces it. Harnesses cannot be configured to consult it.
- **Neutral.** Signature verification accepts the card as served, or with empty members dropped, because the spec's default-value rules need the proto schema. Both forms cover the same signed content.
- **Neutral.** RFC 8693 says nested actors are informational. Halos still checks chain length and cycles, because it minted the chain.

## Implementation status (2026-10-21)

| Commitment | Code | Test | Status |
|---|---|---|---|
| `agents` policy, schema, validation; profile and unit limits; unit loosenings | `internal/policy/agents.go`, `unit.go`, `schemas/*.schema.json` | `internal/policy/agents_test.go` `TestValidateAgents`, `TestUnitAgentLoosenings`, `TestSchemaAgents`, `TestIntersectScope`; `internal/gateway/snapshot_test.go` `TestSnapshotRefusesSecurityErrors` | Done |
| Delegated credential sign/verify, act chain, cycle and depth checks, gateway dispatch | `internal/identity/delegation.go`, `workload.go` | `internal/identity/delegation_test.go` `TestDelegatedTokenRoundTrip`, `TestDelegatedTokenRejections`, `TestWorkloadJWTDelegated` | Done |
| Exchange: session, workload and delegated parents; scope down-only; TTL; depth; cycles; revoked and deprovisioned roots; audit | `internal/server/delegation.go`, `tokenexchange.go` | `internal/server/delegation_test.go` `TestDelegationFromSession`, `TestDelegationChainDepthAndCycles`, `TestDelegationScopeEscalation`, `TestDelegationTTLBoundedByParent`, `TestDelegationRefusesForgedAndDeadParents`, `TestDelegationRevokedSession`, `TestDelegationFromWorkload` | Done |
| Gateway: root cohort, no experiments by default, model, tool and depth policy, actor headers | `internal/gateway/agents.go`, `decision.go`, `prepare.go`, `directory.go` | `internal/gateway/agents_test.go` `TestDelegatedCohortIsRoot`, `TestDelegatedAdmission`, `TestActorHeadersStripped`, `TestToolNames` | Done |
| halo-proxy: budgets charged to root, deprovisioned root refused, forged chain 401 | `cmd/halo-proxy/proxy.go` | `cmd/halo-proxy/agents_test.go` `TestDelegatedCredentialAtTheProxy`, `TestDelegatedBudgetChargedToRoot`, `TestDelegatedDeprovisionedRoot` | Done |
| halo-kong accepts delegated credentials | shared `identity.New`, `gateway.PrepareVerified` | `cmd/halo-kong/agents_test.go` `TestAccessDelegatedAgent` | Done |
| Telemetry `halo.actor.*`, `gen_ai.agent.name` | `internal/telemetry/gwmetrics` | `TestActorAttributes` | Done |
| AgentCard fetch (https, size, timeout, redirects, SSRF), JCS digest, JWS and JWKS | `internal/a2a` | `internal/a2a/card_test.go` `TestCanonicalize`, `TestVerifySignatures`, `TestParseJWKS`, `TestPublicAddr`, `TestFetchLimits`, `TestVerifyCard` | Done |
| `halo agents verify` | `cmd/halo/cmd_agents.go` | `cmd/halo/cmd_agents_test.go` `TestAgentsVerify` | Done; not run against a production A2A agent |
| Card digests pinned in ring releases; per-harness warnings | `internal/release/release.go` | `internal/release/agents_test.go` `TestBuildPinsRemoteAgents` | Done |
| Egress decision API | `internal/server/delegation.go` | `TestAgentEgressDecision`, `internal/policy/agents_test.go` `TestDecideRemote` | Done |
| A client command for the exchange (`halo agents token`) and MCP tools | | | Gap: the guide uses `curl` |
| Per-credential revocation; gateway-side profile and unit depth | | | Gap |
