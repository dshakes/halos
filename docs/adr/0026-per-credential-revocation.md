---
title: "ADR-0026: Per-credential revocation for agent and workload credentials"
description: An admin revokes one halo-server credential by jti, or every credential of an agent, workload or human root by epoch; halo-server checks the shared store on every exchange and egress decision, and gateways check a list they fetch with the directory, refreshed every 30 seconds.
status: accepted
date: 2026-10-27
---

# ADR-0026: Per-credential revocation for agent and workload credentials

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

Workload credentials ([ADR-0023](/halos/adr/0023-workload-identity-federation/)) and delegated agent credentials ([ADR-0024](/halos/adr/0024-agent-identity-and-delegation/)) are bearer JWTs that halo-server signs and gateways verify offline. Until now the only way to kill a leaked one before `exp` was to rotate the workload key, which kills every credential in the fleet. ADR-0024 listed per-credential revocation as a gap: a revoked human's agents stopped exchanging at once but kept calling models until `exp`, and a compromised agent or CI job could not be cut off alone.

## Decision drivers

- Kill one credential, or everything one agent, workload or human holds, without rotating the key.
- Hold on every halo-server replica at once (ADR-0021) and reach every gateway within a stated bound.
- Fail closed on halo-server; at the gateway, follow the directory's existing fail mode, and never forget a revocation already seen.
- Bounded state: nothing a revocation matches outlives the longest credential lifetime.
- Privileged, audited and attributable, like session revocation.

## Considered options

1. **Rotate the workload key.** Already possible; kills every credential. Kept as the last resort.
2. **Token introspection on every gateway request** (RFC 7662). Exact, but puts halo-server on the hot path of every model call.
3. **A revocation list: jti entries plus per-subject revoked-before epochs, checked by halo-server per exchange and pulled by gateways with the directory.** Chosen.

## Decision outcome

Option 3.

### What can be revoked

- **A credential, by `jti`.** Every halo-server credential carries a `jti`, and a delegated one also carries its ancestors' (`policy.CredentialRef.IDs`: own jti, then parent first). Revoking a jti kills that credential and every credential exchanged from it.
- **A subject, by epoch.** `agent:<name>` kills every credential with that agent anywhere in its chain issued at or before the epoch; `workload:<subject>` every workload credential and every chain rooted at it; a human id every chain rooted at them (compared with the signed `auth_time`) and, as `POST /api/v1/sessions/revoke` does, all their sessions. An agent or workload epoch is the revocation time plus one minute (the replica clock-skew pad of ADR-0021), so new credentials for that subject are refused for that minute. A human's epoch is their session epoch, so a fresh login can delegate again at once.
- **Not IdP tokens.** A caller authenticated by the IdP's own JWT carries no halo-server credential and is not checked here; deprovision them through SCIM ([ADR-0022](/halos/adr/0022-scim-provisioning/)).

### Storage

One table, `halo_revocations (kind, rkey, epoch, expires_at, record)` (`internal/pgstore/migrations/0003_revocations.sql`) on the Postgres backend; on a single replica, an in-memory map with a JSONL log under `--data-dir` (`credential-revocations.jsonl`), replayed on start. A live row's epoch and expiry only move forward, and the record follows the larger epoch; an expired row is replaced. A row expires `MaxWorkloadTTL` (1 hour) plus the skew pad after its epoch (subject) or its creation (jti): no credential it could match is still valid then, so expired rows are pruned. At most 10,000 rows are live; past that the API answers 409 and the operator revokes the subject or rotates the key.

### API, RBAC, audit

- `POST /api/v1/revocations` `{"jti"|"subject", "reason"}` and `GET /api/v1/revocations`, both `admin` in `routePerms` ([ADR-0015](/halos/adr/0015-rbac-roles-for-halo-server/)). Exactly one of `jti` and `subject`; `reason` is required (at most 1000 characters). A jti is 1-128 of `[A-Za-z0-9_-]`; a subject has no spaces or control characters, and an `agent:` subject must be a valid actor name.
- The revocation is stored before it is audited. `credential.revoke` (actor, key, kind, reason, expiry, epoch) is appended with `AuditStrict`: a failed append is a 500 and the revocation stays in force, as for session revocation. A store error is a 503 and nothing is revoked.
- `halo agents revoke --jti J | --subject S --reason R` and `halo agents revocations` call the API with an admin session (`HALO_SESSION`), over https or to loopback only.

### Enforcement

- **halo-server.** Every delegation exchange (the new credential's chain) and every `POST /api/v1/agents/egress` decision does one indexed point query (`RevocationsFor`: the credential's jtis and the subjects of its chain) against the shared store. A revocation made on any replica holds on every replica on the next request. A store error refuses (503), never passes.
- **Gateways.** `halo-proxy` and `halo-kong` with `directory.url` set fetch the whole list from `GET /api/v1/gateway/directory?revocations=1` (gateway token, at most 4 MiB) and check every caller holding a halo-server credential against it before the directory lookup, workload callers included. A revoked credential is 401 `credential_revoked` in the caller's protocol. The list is reused for 30 seconds (`DefaultRevocationTTL`); one caller refreshes while the others keep the current list.
- **Gateway outage.** If the list cannot be fetched, a list younger than `grace` (default 5 minutes) keeps serving. Past `grace`, `failMode: closed` refuses every halo-server credential (503); `failMode: open` keeps checking against the last list it fetched, however old, so an outage never forgets a revocation the gateway already saw. Any non-200 answer counts as an outage here, so a gateway in front of an older halo-server without the list follows its fail mode.

### Propagation bound

- halo-server: the next exchange or egress decision on any replica.
- A gateway with `directory.url` and halo-server reachable: at most 30 seconds plus one fetch.
- A gateway that cannot reach halo-server: not until it can. Fail closed refuses all halo-server credentials after `grace`; fail open accepts what it last knew.
- A gateway without `directory.url`: never; the credential dies at `exp` (workload credentials at most 1 hour, agent credentials at most `maxTTLSeconds`).

## Consequences

- **Good.** One leaked CI or agent credential is cut off without rotating the key or touching anyone else; a compromised agent is cut off everywhere in every chain.
- **Good.** No new hot-path dependency: gateways check a cached list in memory.
- **Bad.** Gateway enforcement depends on the SCIM directory endpoint being configured; without it, revocation holds only on halo-server.
- **Bad.** A binary at schema 2 ignores the table: during a mixed-version rollout an old replica does not check revocations.
- **Neutral.** The single-replica log is never compacted; expired rows are skipped on replay.

## Implementation status (2026-10-27)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Store: Postgres table, single-replica log, forward-only merge, expiry | `internal/pgstore/revocations.go`, `internal/server/revocations.go` | `internal/pgstore/revocations_test.go` `TestRevocationsSQL`; `internal/server/revocations_test.go` `TestRevocationLogMerge` | Done |
| API: validation, `admin` only, AuditStrict, 409 at the cap | `internal/server/revocations.go`, `rbac.go` | `TestRevocationAPI`, `TestRevocationCap` | Done |
| halo-server enforcement: jti lineage, subject epochs, workload-rooted chains, every replica, fail closed | `internal/server/delegation.go`, `revocations.go` | `TestRevokedJTIKillsLineage`, `TestRevokedSubjectEpoch`, `TestRevocationsAcrossReplicasInMemory`, `TestRevocationsAcrossReplicasPostgres`, `TestRevocationsFailClosed` | Done |
| Gateway list, check and fail mode | `internal/gateway/revocation.go`, `directory.go` | `internal/gateway/revocation_test.go` `TestRevocationListCheck`, `TestDirectoryRevocations`; `internal/server/revocations_test.go` `TestGatewayRevocationList`, `TestRevocationReachesGatewayWithinBound` | Done |
| `halo agents revoke`, `halo agents revocations` | `cmd/halo/cmd_revoke.go` | `cmd/halo/cmd_revoke_test.go` `TestAgentsRevoke` | Done |
