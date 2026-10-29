---
title: "ADR-0021: HA control plane on Postgres"
description: How several halo-server and halo-shadow replicas share state through Postgres without losing data or splitting the brain, and what stays single-replica.
status: accepted
date: 2026-10-21
---

# ADR-0021: HA control plane on Postgres

- Status: accepted (amended 2026-10-22: review fixes; amended 2026-10-27: shared failed-auth limiters, posture, revocations)
- Date: 2026-10-21

## Context and problem statement

`halo-server` and `halo-shadow` are pinned to one replica (`values.schema.json`). Each is a single writer over JSONL files in its data directory, replayed into memory at start: devices, access requests, session revocations, the hash-chained audit log, the kill list, the controller's action log, rollout state and fleet reports for `halo-server`; the pair file and an in-process spend counter for `halo-shadow`. Short-lived state (enrollment tokens, consumed OIDC login states, server-side sessions) lives only in process memory. An upgrade or reschedule is therefore an outage of the console, enrollment and the kill-list endpoint, and a node failure waits on volume reattachment. A second replica today would lose writes (each replays only its own file), fork the audit chain, run the experiment controller twice (duplicate PRs, double notifications) and multiply `halo-shadow`'s budget.

## Decision drivers

- No data loss and no split brain with N replicas behind one Service.
- The file backend stays the default and behaves exactly as before. Merges with concurrent work on `internal/server` stay tractable: a storage seam, not a rewrite of the handlers.
- The audit chain stays strictly linear under concurrent writers on any replica.
- Singleton loops run on exactly one replica, and a deposed leader cannot write behind its successor.
- Security decisions fail closed when the shared store cannot be read.
- One standard dependency, no cluster coordinator to operate.

## Considered options

1. Keep one replica; make restarts faster.
2. Shared filesystem (RWX volume) with file locks. NFS lock semantics vary by provider, the in-memory replay still diverges between replicas, and it does not give a lease.
3. An embedded consensus store (raft) between replicas. Correct, but it makes every Halos operator run and back up a quorum system.
4. **Postgres as the shared store**, behind interfaces the file backend also implements, with a lease row for leader election.

## Decision outcome

Chosen: **option 4**. Postgres is the database most platform teams already run with backups, PITR and failover (RDS, Cloud SQL, CloudNativePG). The driver is `github.com/jackc/pgx/v5/stdlib` behind `database/sql`: pure Go, the de-facto standard Postgres driver, and the only new module (plus its own small dependencies `pgpassfile`, `pgservicefile` and `puddle`).

### The seam

- `internal/storage` defines `Log` (append, catch up, close), `Opener` and `KV` (expiring keys: put, add-if-absent, get, take, delete). `storage.Dir` (the JSONL files, through the existing `fsutil.OpenJSONL`) and `storage.MemKV` are the defaults. The stores keep their in-memory indexes and replay functions; only `f *os.File` became `log storage.Log`.
- `server.Config.Backend` (an interface; `server.PGBackend` wraps `pgstore.DB`) supplies the logs, the KV, the audit chain, rollout state and a `Ping`. `nil` means the file backend, unchanged. Fleet reports use the existing `server.Store` interface (`server.NewPGStore`). The kill list and the controller's action log use the same `Log` (`controller.NewKillStore`, `controller.OpenStateLogOn`); rollout state uses `rollout.StateStore` (`DirStore` or `DocStore`).
- `internal/pgstore` holds all SQL and stores opaque bytes; packages that own a type encode it. Migrations are embedded (`internal/pgstore/migrations/NNNN_*.sql`), versioned 1..n without gaps, forward-only and applied in one transaction under an advisory lock, so replicas starting together apply each exactly once. `halo-server migrate` applies them; `--auto-migrate` does it at start. A binary refuses a database behind it (run migrate) or ahead of it (the database is newer than the binary).

### Shared logs and replica consistency

Each store's records go to `halo_journal` under a stream name (`devices`, `requests`, `session-revocations`, `killswitch`, `controller-state`). Appends to a stream take a transaction-scoped advisory lock on the stream, so ids commit in id order and a replica tailing `id > cursor` can never skip a row that commits later. `Append` replays every foreign record that precedes the new one before returning, and the caller then applies its own record, so each replica applies the stream in exactly the global order. Before every read that matters a store calls `Catchup`: one indexed query.

- Device and request records are keyed by id; a keyed append deletes the older rows of that key, which bounds the device stream's `lastSeen` updates. A revocation is keyed apart from the device's other records, and revocation is sticky in the index, so a stale `lastSeen` write from a replica that had not yet seen the revocation can never resurrect a device, on that replica or on a fresh one.
- Session revocations and the kill list are unkeyed: the full history replays, so the kill list `version` is the same on every replica.
- Device authentication and session checks **fail closed**: if `Catchup` fails, a device gets 503 (no rate-limit penalty) and a session is treated as revoked, because a revocation made on another replica might be unseen. List views serve the last view and the error is counted.
- Enrollment tokens are `Take`n (`DELETE ... RETURNING`): of concurrent redemptions on any replicas exactly one succeeds. Login states are consumed with `Add` (insert, or overwrite only an expired row). Server-side sessions are `Put`/`Get`. Approving or denying an access request first `Add`s a claim (`request-claim/<id>`, expiring after the PR timeout), so two admins on two replicas cannot open two PRs for one request.
- At most one pending access request per (user, kind, item): `POST /api/v1/requests` takes a claim row (`halo_request_pending`, primary key on the hashed triple) before it appends the request. A claim whose holder this replica sees decided is replaced at once; one whose request never reached the log (the replica died between the two writes) is replaced after a minute. Deciding a request releases its claim.

### State added by later features

These landed after the first cut of this ADR and are shared the same way:

- **Gateway budgets (ADR-0017).** Counters are rows (`halo_budget_buckets`: budget, key, bucket start), usage is added in place, and the usage batch id is a primary key (`halo_budget_batches`) inserted in the same transaction, so a batch retried to two replicas at once counts once. `check` and `GET /api/v1/budgets` read the rows, so N replicas grant one budget, not N. The gateway's estimated charges (`EstimateUsage`) are ordinary usage records and take the same path. Old buckets are pruned by age on the database clock, never by a replica's policy (see Amended).
- **Workload token exchange (ADR-0023).** The replay cache is a KV row per exchanged token (hashed replay key, expiry = the token's `exp`), inserted only if no live row exists: a token is exchanged once cluster-wide. A store error refuses the exchange.
- **SCIM (ADR-0022).** The directory is the `scim` log, replayed into the same in-memory store with its `memberOf` index; every read catches up first, and `Lookup` fails closed (user inactive) when it cannot. Mutations take an owned cluster lock (503 if it cannot be taken) and each userName a claim, so uniqueness holds across replicas (see Amended). Deprovisioning revokes sessions (lowercased epoch), devices (after catching up, so devices enrolled on other replicas count) and pending enrollment tokens, all in shared state. Enrollment tokens are keyed by hash, so the last is a per-user void epoch (`enroll-drop`) that `consume` checks; it reaches one minute past the deprovisioning to cover replica clock skew.
- **Audit export and rotation (ADR-0016).** Segments and rotation are file-backend features; on Postgres the chain is one table and rotation is refused. Each sink forwards from one replica under lease `audit-export-<sink>`, with its cursor a fenced document, so sinks do not receive N copies. `GET /api/v1/audit` pages by `seq` and caches the verified prefix while its last hash reads back unchanged; `halo audit verify --database-url-file` re-reads the whole chain.

- **Agent delegation and egress (ADR-0024).** Stateless per request: a delegated credential carries its act chain, depth, scope and parent `jti` in its signed claims, so there is no per-chain counter to share, and delegation is deliberately not single-use (a parent may delegate to several agents). What it reads is shared: the root's session epoch, the server-side session and the SCIM directory, so a revocation or deprovisioning on one replica ends every chain on all of them. Its only per-process state is the token-exchange failure bucket below.
- **Failed-auth limiters are shared (amended 2026-10-27).** The per-IP, per-endpoint-class buckets (devices and enrollment, logins, gateway tokens, token exchange, delegation, SCIM) are in memory on each replica, and every failure is also counted in the shared store (`CountAuthFailure`, a KV row per class and address with a one-minute window on the database clock), so N replicas grant one budget, not N. See Amended (2026-10-27).
- **Policy acceptance.** Each replica loads policy from its own git-sync checkout and refuses a policy with `policy.SecurityIssues` errors, keeping the last good one. The in-process controller acts on that same accepted policy (`Server.Policy`), not on a raw load, so the leader never acts on a policy its own API refuses. Replicas can disagree only while their checkouts differ (git-sync period, default 30s); a replica that starts while the repository head is refused has no last good policy and stays unready until a good commit lands.

Replicas are assumed to run NTP-synced clocks within a minute of each other: session revocations compare a cookie's issue time (one replica's clock) with the revocation time (another's), and both the revocation epoch and the enrollment void are padded by one minute to absorb skew (see Amended). Leases, locks and claims use the database clock only.


### Audit chain

`halo_audit` has `seq` as its primary key and a single `halo_audit_head` row. An append locks the head row (`SELECT ... FOR UPDATE`), chains the entry with `server.ChainAuditEntry` (the same function the file backend uses), inserts it and advances the head in one transaction. Concurrent writers on any replica therefore append strictly one after another, and even a writer that bypassed the lock could not fork the chain: two entries cannot share a `seq`. `GET /api/v1/audit` verifies the whole chain as before.

### Leader lease and fencing

The experiment controller (verdicts, kill switch on rollback, PRs, notifications, rollout ticks) runs under `pgstore.Elector` on lease `controller` in `halo_leases`. `Acquire` is one upsert judged on the **database clock**: it renews the holder's live lease without changing its token, takes an expired lease and increments the **fencing token**, and refuses a live lease held by someone else. The elector renews every TTL/3 (default TTL 15s) and steps down on its own once TTL-Renew has passed since its last successful renewal started, so it stops leading before the lease can expire on the database; a replica that stepped down campaigns under a new holder id, so it cannot quietly resume its old term. On shutdown it releases the lease and a peer takes over on its next round.

Each term opens the controller's action log and rollout state through `pgstore.Fenced`: every write first checks, in the same transaction, that the lease is still held at the term's token, and fails with `ErrFenced` otherwise. A deposed leader still finishing a tick cannot record actions or overwrite rollout state behind its successor. Side effects outside Postgres are not fenced. The term's context is cancelled at step-down, before the lease can expire, which aborts in-flight `git`/`gh` calls; a side effect that completes anyway in that window (a pull request, a kill) is at worst a duplicate: a second PR a human closes (nothing merges automatically, invariant 5), or a kill that is already set (the safe direction, and idempotent).

### halo-shadow

With `-database-url-file`, workers keep no state. Pairs go to `halo_shadow_pairs`, one row per pair, in exactly the `FileStore` row format: sealed with AES-256-GCM (AAD = pair id) when `-pair-key-file` is set, so `halo-shadow export-pairs | halo-shadow decrypt-pairs` works as on a file. The budget is global: a reservation is one conditional `UPDATE ... SET reserved = reserved + $est WHERE spent + reserved + $est <= $cap` on the scope's row plus a reservation row with an expiry. Settling swaps the reservation for the charged amount. A reservation whose worker died is reaped at expiry (15 min) and charged in full, since its upstream calls may have been paid. If the budget store is unreachable a job is refused: nothing is spent without a booking. Because the shared spend persists across restarts (the file mode's counter resets), `-budget-scope` names the budget; a new name starts a fresh one.

### Readiness, metrics, Helm

`/readyz` on both binaries returns 503 while Postgres is unreachable (2s ping), so the Service routes around a replica that lost its database; `/healthz` never checks it, so an outage does not restart pods. `/metrics` (`--metrics-listen`) adds `halo_leader{lease}`, `halo_leader_changes_total{lease}`, `halo_db_errors_total` and `halo_db_open_connections`. The chart lifts the replica pin only when `<component>.database.existingSecret` is set (a `values.schema.json` conditional that also requires `persistence.enabled: false`), mounts the URL from that Secret as a file, renders a PodDisruptionBudget for more than one replica, adds a startup probe and `networkPolicy.databaseEgress`.

### Migration

`halo-server import --from-data-dir DIR --database-url-file F` reads a stopped server's data dir (only reads it), refuses a non-empty database and a source whose audit chain does not verify, copies every log record for record, the latest report per reporter and every rollout state (verifying each history chain), then checks per-stream counts against what it copied and verifies the imported audit chain ends at the source's head.

## Consequences

- Good: N replicas serve the console, enrollment, reports and the kill list; upgrades are rolling; a lost node costs one replica, not the service.
- Good: exactly one controller acts, and its state writes are fenced.
- Good: the file backend is unchanged and remains the default, and the stores did not change shape.
- Bad: Postgres becomes a dependency of an HA install, and its availability bounds the control plane's. Gateways and `halod` are unaffected by a control-plane outage, as before.
- Bad: every device authentication and session check is one indexed query (the catch-up). That is the price of revocations taking effect on every replica at once.
- Bad: rows in `halo_journal` for unkeyed streams (session revocations, kills, the controller log) grow without compaction, as their files did.
- Neutral: on the Postgres backend the controller writes verdicts as one document per experiment (kind `verdict`, fenced) instead of `--verdicts-file`, and every replica's console reads them. `halo exp analyze --verdicts-file` still writes a file.

## Amended (2026-10-22): review fixes

An independent review of the first HA cut found these gaps; each is fixed with a regression test that fails when the fix is reverted (mutation-checked), on the in-process fake and on Postgres.

- **Cluster locks and claims are owned and judged on the database clock.** `storage.KV` gained `TryLock`/`Unlock`/`Raise`. A lock row's value is a random owner token, its expiry is `now() + ttl` on the database, and `Unlock` deletes only the owner's row. The SCIM cluster lock no longer proceeds unlocked after its 10s wait: the mutation answers 503 and the IdP retries. userNames are additionally claimed (`scim-username/<canonical name>`, owned by the user id, pinned once written, released on rename and delete), so two replicas whose uniqueness checks race still provision a name once. The access-request decision claim uses the same owned lock.
- **Fencing is race-free.** `checkFence` reads the lease row `FOR SHARE` and compares the expiry with `clock_timestamp()`: a takeover's UPDATE waits for an in-flight fenced write, and a long transaction cannot pass its check on its start time.
- **Controller side effects are fenced through intents.** Before every kill, PR and notification (experiments and rollouts) the controller records an intent in its fenced state; a refused intent (`storage.ErrFenced`) skips the call and everything after it. The intent's key travels with the effect: a `<!-- halos-intent: KEY -->` marker in the PR body, which a new leader looks up (`gh pr list` via `promote.PRFinder`) before opening another, and the notification's `id` (webhook header `X-Halo-Event-Id`) for receivers to dedupe. Kills are idempotent. A non-fence store error still lets the call through: a missing rollback is worse than a duplicate.
- **Budget pruning never consults a replica's policy.** `ApplyBudget` only counts (increments sorted, so concurrent batches lock rows in one order and cannot deadlock). `PruneBudgets` drops buckets older than `budget.MaxRetention` (95 days: the longest rolling period policy accepts, plus a bucket) on the database clock, at most once a minute per replica; a budget no policy names yet keeps its counters, and removed budgets age out.
- **Revocations are padded for clock skew.** A session revocation epoch is `now + 1m`; the OIDC callback stamps a fresh login just past the epoch (`issueAt`), so the pad never locks out a re-login.
- **Deprovisioning beats a racing enrollment.** `deprovision` voids enrollment tokens first; `postEnroll` re-reads the void after minting and revokes the device it just made if the void covers the token. The void epoch is raised with `Raise` (GREATEST), so it never moves backwards.
- **No database round trip under a process-wide lock per request.** Device authentication, session checks, SCIM reads and the kill list's catch-ups go through a `storage.Coalescer`: concurrent requests share one catch-up that started after they arrived, and the store's mutex is held only while records are applied. The shared audit tail reads newest-first in pages (`ORDER BY seq DESC LIMIT`). The pool size is `--database-max-conns` (default 16).
- **Rolling back the binary.** Every migration declares `-- min-binary-schema: N` (the parser refuses one that does not); `halo_schema_migrations.min_binary` records it. A binary older than the database starts when every newer migration still accepts it. Migrations within a major are additive, so N is normally 1.
- **Smaller fixes.** The workload jti row lives until `exp + exchangeIatSkew`. `headSeq` returns an error instead of 0 on a database error. A database URL to a non-loopback host must use `sslmode=verify-full` unless `--database-insecure-tls`. `halo-server import` runs in one transaction and verifies before committing, so a failed import leaves the database empty; `Counts` covers every table; a source whose oldest audit segments were archived is refused with instructions. The chart fails to render HA with NetworkPolicy and an empty `databaseEgress.to`, and `server.database.migrateJob` runs `halo-server migrate` as a pre-install/pre-upgrade hook with a separate DDL-capable URL, so the serving role needs only DML.

Self-review of what the review did not cover:

- `internal/rollout` state is one document per rollout written through the fenced view; rollout intents are marks in that state, persisted before each external call.
- `internal/controller/state.go`: the state log is opened per leadership term on the fenced view; `Reset` also forgets intents, so a new run of an experiment starts clean.
- The kill store's catch-up is now coalesced for gateway polls; `set` still catches up under its lock before appending (write path).
- `GitPolicyWriter`: each replica has its own clone (an `emptyDir`) and lock, so replicas never share a working tree. Console proposals are serialised per request by the decision claim; controller PRs come only from the leader, with intent markers.
- Known equivalent mutant: removing the guard that stops a rollback when its own record is fenced is masked by the per-call intents (each external call is refused on its own; `TestLeaseLostBeforeKill` kills the per-call mutant).

## Amended (2026-10-27): shared limiters, posture, revocations

A security review of halo-server found these; each has a regression test that fails when the fix is reverted (mutation-checked).

- **Failed-auth limiters shared across replicas.** This ADR first kept them per replica, so N replicas gave a client spread across them N times the budget. Every failure is now also counted in the Backend: the replica whose failure brings the shared count to the burst (10) blocks the address for one minute, and every other replica does at its next failure from it. The write-amplification concern above is bounded instead of avoided: only failures write, and never from an address the replica already blocks, so a flood costs at most burst + N writes per address per window. A store error leaves the local budget in force (logged), never less. IPv6 addresses are keyed by their /64, since one host usually controls its whole /64 (`TestLimiterKeysIPv6By64`, `TestSharedAuthLimiterInMemory`, `TestSharedAuthLimiterPostgres`, `internal/pgstore` `TestCountAuthFailure`).
- **SCIM checks the token before the limiter.** A valid SCIM token from an address the SCIM budget blocks (a NAT shared with a guesser) is accepted, as gateway tokens already were; only failures are charged (`TestSCIMValidTokenFromBlockedIP`).
- **Access-request decisions are fail closed.** Approve and deny append with `AuditStrict`: a failed save puts the request back to pending and answers 500; a failed audit append answers 500 with the decision stored (`TestDecisionNotReportedUnlessPersisted`).
- **Posture never passes on a partial view.** The gateway posture check catches up with the shared device registry first (a device enrolled on another replica counts) and answers unknown, not compliant, if it cannot; an unreachable release registry with no verified pointer cached is unknown too, never current (`TestPostureSeesDevicesFromOtherReplica`, `TestPostureUnknownWhenRegistryUnreachable`).
- **Credential revocations** ([ADR-0026](/halos/adr/0026-per-credential-revocation/)) are a shared table (`halo_revocations`, migration 0003), read with one indexed query per exchange and egress decision, so a revocation on one replica holds on all of them at once.

## Implementation status (2026-10-21)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Storage seam; file backend unchanged | `internal/storage`; `internal/server/{devices,requests,sessions,audit}.go`; `internal/controller/{killstore,state}.go` | `storage_test.go`; existing server and controller suites | Done |
| Embedded, versioned, forward-only migrations; `migrate`, `--auto-migrate` | `internal/pgstore/pgstore.go`, `migrations/0001_init.sql`; `cmd/halo-server/ha.go` | `pg_test.go` `TestMigrate`, `TestCheckSchemaMismatch`; `cmd/halo-server` `TestHA` | Done |
| Tailed logs in one global order across replicas | `internal/pgstore/journal.go` | `TestJournalReplicas`, `TestJournalKeyCompaction`; `internal/server` `TestReplicasPostgres` | Done |
| Linear audit chain under concurrent writers | `pgstore.AppendAudit`; `server.ChainAuditEntry` | `TestAuditChainConcurrent`; `TestReplicas*` (audit subtest) | Done |
| Leader lease with fencing token; failover | `internal/pgstore/lease.go`; `Fenced` in `tables.go`; `cmd/halo-server/ha.go` | `TestElectorTick` (fake clock, partition), `TestElectorRunFailover`, `TestElectorRunCrashFailover`, `TestLeaseSQL`, `TestFencedWrites`, `TestElectorPostgresFailover`, `cmd/halo-server` `TestHA` | Done |
| Shared single-use state (enrollment, login state, sessions, approval claims) | `internal/server/{portal,auth,requests}.go`; `pgstore` KV | `TestKV`; `TestReplicas*` | Done |
| Fail closed when the store is unreachable | `devices.go` `deviceAuth`, `sessions.go` `valid` | `TestReplicaFailsClosedWhenStoreUnreachable` | Done |
| halo-shadow stateless workers, sealed rows, global budget | `internal/shadow/shared.go`; `pgstore` pairs and budget | `shared_test.go`; `TestPairsAndBudget`; `cmd/halo-shadow` `TestDatabaseMode` | Done |
| `/readyz` reflects the database; leader and DB metrics | `server.go` `/readyz`; `shadow/server.go`; `pgstore.WriteMetrics`, `Elector.WriteMetrics` | `TestReadyzReflectsBackend`, `TestReadyzPing`, `TestElectorMetrics` | Done |
| Helm: conditional replica pin, PDB, probes, DSN Secret | `deploy/helm/halos/{values.yaml,values.schema.json,templates/*}`, `ci/ha-values.yaml` | `helm lint -f ci/ha-values.yaml` | Done; not run on a cluster |
| `import --from-data-dir` with verification | `internal/server/import.go`; `cmd/halo-server/ha.go` | `TestImportDataDir`, `TestImportRefusesBrokenChain`, `TestHA` | Done |
| Verdicts shared across replicas | `controller.VerdictDocs`; `server.verdicts` | `TestSharedVerdicts` | Done |
| Budget ledger shared; batch dedupe atomic | `migrations/0002_budgets_requests.sql`; `pgstore.ApplyBudget`; `server/budgets.go` | `TestBudgetLedger`; `TestSharedBudgets` | Done |
| Workload jti replay cache shared | `server.rememberSubjectToken` | `TestSharedWorkloadReplay` | Done |
| SCIM directory shared; deprovisioning on every replica | `OpenSCIMStoreOn`; `clusterMutex`; `enrollments.dropUser` | `TestSharedSCIMDeprovision` | Done |
| Audit export: one forwarder per sink, shared fenced cursor; paging and verify on the table | `RunAuditExport`, `verifyShared`, `VerifyAuditBackend`; `halo audit verify --database-url-file` | `TestSharedAuditExport`, `TestAuditVerifyDatabase` | Done |
| Atomic duplicate-request check across replicas | `pgstore.ClaimPending`; `server.claimPending` | `TestClaimPending`; `TestSharedPendingRequestUnique` | Done |
| Owned locks and claims on the database clock; SCIM lock refuses (503); userName claims | `storage.KV` `TryLock`/`Unlock`/`Raise`; `clusterMutex`; `scimLogStore.claimName` | `TestSCIMLockHeldIs503`, `TestClusterMutexOwnerRelease`, `TestSCIMUserNameClaim`, `TestDecisionClaimOwner`, `TestKVLockSQL`, `TestMemKVLock` | Done (amended) |
| Race-free fence check | `pgstore.checkFence` (FOR SHARE, clock_timestamp) | `TestFenceHoldsOffTakeover`, `TestFenceUsesCheckTime` | Done (amended) |
| Fenced intents before controller side effects; PR and notification dedupe keys | `controller/intent.go`; `promote.GHOpener.FindPR`; `Event.ID` | `TestDeposedLeaderTakesNoSideEffects`, `TestLeaseLostBeforeKill`, `TestFencedAfterKillStopsPRAndNotify`, `TestNewLeaderFindsPRInsteadOfReopening`, `TestRolloutFencedSkipsNotify`, `TestGHOpenerFindPR`, `TestWebhookEventID` | Done (amended) |
| Budget pruning by age on the database clock; sorted increments | `pgstore.PruneBudgets`, `budget.MaxRetention` | `TestBudgetPruneByAgeOnly`, `TestApplyBudgetNoDeadlock` | Done (amended) |
| Skew-padded revocation; deprovisioning before a racing enrollment; monotonic void | `sessions.go` `revocationSkew`, `issueAt`; `portal.go` `postEnroll`, `dropUser` | `TestRevocationSkewPad`, `TestPostMintVoidRevokes`, `TestEnrollVoidWindow`, `TestKVRaiseSQL`, `TestMemKVRaise` | Done (amended) |
| Coalesced catch-ups; paged audit tail; configurable pool | `storage.Coalescer`; `EachAuditDesc`; `--database-max-conns` | `TestCoalescer`, `TestSharedTailReadsOnlyWhatItNeeds`, `TestAuditTailPaged` | Done (amended) |
| Binary rollback across additive migrations | `min-binary-schema` headers; `newerCompatible` | `TestSchemaRollbackCompat`, `TestMigrationHeaders` | Done (amended) |
| jti row past exp; head read errors; verify-full TLS; transactional import | `rememberSubjectToken`; `auditLog.headSeq`; `pgstore.CheckTLS`; `pgstore.Import` | `TestJTIRowOutlivesExp`, `TestHeadSeqErrorNotZero`, `TestCheckTLS`, `TestImportIsTransactional` | Done (amended) |
