---
title: "ADR-0021: HA control plane on Postgres"
description: How several halo-server and halo-shadow replicas share state through Postgres without losing data or splitting the brain, and what stays single-replica.
status: accepted
date: 2026-10-21
---

# ADR-0021: HA control plane on Postgres

- Status: accepted
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
- Known gap: the "already have a pending request" check on `POST /api/v1/requests` is not atomic across replicas, so two simultaneous identical requests on two replicas can both be created. Both are visible and an admin denies one.

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
- Neutral: the verdicts file (`--verdicts-file`) stays a local file written by the leader and recomputed every tick; on an HA install the console's verdict column is only populated on the replica holding the lease unless the path is on shared storage.

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
| Verdicts shared across replicas | | | Gap, documented |
| Atomic duplicate-request check across replicas | | | Gap, documented |
