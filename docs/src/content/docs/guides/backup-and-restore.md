---
title: Backup and restore
description: Recovery targets per deployment mode, Postgres point-in-time recovery, what state lives where, the restore order, and the drill that proves it.
---

This page is the disaster-recovery runbook. [Operations](/halos/guides/operations/#backup-and-restore) lists every file and table and what losing each costs; this page says what to promise, how to get there and how to check it. Where a number was measured it says where; everything else is a target you must confirm against your own database.

## What to promise: RPO and RTO

RPO is how much recent state you can lose, RTO how long console, enrollment and the kill list stay unavailable. **Developers' CLIs keep working through an outage** (gateways keep their last accepted kill list, `halod` keeps its last good release), so RTO here is the time to get the control plane back, not the time developers are blocked.

| Deployment mode | State | Recommended RPO | Recommended RTO | How |
|---|---|---|---|---|
| Single replica, file backend (default) | PVC `--data-dir` (append-only JSONL) | 24 h (daily snapshot), 1 h with hourly CSI snapshots | 30 min | CSI `VolumeSnapshot` or tar of the data dir, restore into the claim |
| HA, self-run Postgres (CloudNativePG, Patroni) | Postgres | 5 min or less | 15 min | Continuous WAL archiving + base backups, PITR |
| HA, managed Postgres (RDS, Cloud SQL, Azure Flexible Server) | Postgres | 5 min or less | 15 to 60 min | Provider PITR; restore creates a new instance, so repoint the URL |
| Logical dump only (`pg_dump`) | Postgres | Dump interval (daily at best) | 15 min | The drill below; fine for small installs and for pre-upgrade copies |

These are recommendations, not measurements of your system. The chart never sees your database, so the only RTO measured here is the drill's: the whole destroy, restore, both-replicas-ready sequence with a few rows (`scripts/uat-dr.sh`, about 70 seconds in `local` mode on a laptop). A real database restores at the speed of your storage.

What an RPO gap costs, in order of severity: a lost **kill** is forgotten (gateways get an empty list at the next poll: re-issue it from the audit log or the SIEM copy), lost **device enrollments** mean those machines re-enroll, lost **session and credential revocations** make revoked sessions valid until they expire, lost **audit entries** are a detectable gap in the hash chain (the SIEM holds the second copy if [export](/halos/guides/siem-export/) is on). This is why the Postgres rows ask for a few minutes, not a day.

## What state lives where

| State | Where | Back it up with | Lost means |
|---|---|---|---|
| Control-plane state (devices, requests, audit chain, kill list, revocations, controller log, rollout state, budgets, sessions, shadow pairs) | Postgres (HA), or `--data-dir` PVC (file backend) | PITR / `pg_dump`, or a PVC snapshot | See [Operations](/halos/guides/operations/#what-to-back-up) |
| Release rings and releases | OCI registry (`portal.registry`, `halo release publish`) | The registry's own replication; releases are immutable and content-addressed, so a mirror is exact | Rings cannot be fetched by `halod`; republish from the policy repo |
| Policy repo | Git host | Your host's backup or a mirror | Source of truth for everything except device identity |
| Release signing key | CI secret or KMS | Your secret manager. **Never only the cluster** | Cannot publish, promote, refresh or roll back any ring |
| Kill-switch signing key and gateway token | Secret `server.killSwitch.existingSecret` | Your secret manager | `halo-server` cannot sign kill lists; a different key is a rotation, not a restore |
| Kill-switch and release **public** keys | Secrets and `release.pub` on devices | Anywhere | What gateways and `halod` already trust |
| Database URL, fleet token, session key, OIDC secret, shadow pair key | Kubernetes Secrets | Your secret manager | Pods do not start; the pair key is the only way to read encrypted shadow pairs |
| Signer state file | `~/.local/state/halos/pointers.json` on the signer | CI cache | Replay check has nothing to compare against ([lost signer state](/halos/guides/operations/#lost-signer-state-file)) |
| Evidence (sessions, cost, experiment metrics) | ClickHouse | ClickHouse backups | Experiment history; the controller cannot evaluate until it refills. Not control-plane state |

The chart keeps PVCs on `helm uninstall` (`helm.sh/resource-policy: keep`). Secrets are not in the chart: keep them in your secret manager and recreate them first.

## Postgres point-in-time recovery

Use PITR rather than dumps in production: the kill list must not lose recent writes, and a dump only recovers to the moment it was taken.

- **Self-run:** continuous WAL archiving (`archive_mode=on`, `archive_command` to object storage) plus periodic base backups. CloudNativePG does this declaratively with `backup.barmanObjectStore` and a `ScheduledBackup`; Patroni setups use pgBackRest or WAL-G. Recover with `recovery_target_time` just before the incident.
- **RDS / Aurora:** automated backups with a retention period of at least 7 days give PITR to any second (typically within the last 5 minutes); restore creates a **new** instance.
- **Cloud SQL:** enable point-in-time recovery (it needs WAL retention); restore creates a new instance (a clone).
- **Azure Database for PostgreSQL Flexible Server:** built-in PITR; restore creates a new server.

Because managed restores create a new endpoint, put the writer endpoint behind a DNS name and keep that name in the `server.database.existingSecret` URL, or update the Secret in step 4 below. The URL must keep `sslmode=verify-full` for any non-loopback host.

Take a logical dump as well, immediately before every upgrade (migrations are forward-only; a migration that raises `min-binary-schema` means a rollback is a restore):

```bash
pg_dump --format=custom --file=halos-$(date +%F).dump "$HALOS_DATABASE_URL"   # a human runs this; the URL holds the password
```

Test the backup, not just the job: restore into a scratch database on a schedule and run `halo audit verify --database-url-file F` against it. An untested backup is a hope.

## Restore order

Do not restore underneath running replicas: they cache state in memory and tail the tables by id. For the file backend see [Operations](/halos/guides/operations/#restore); for Postgres:

1. **Stop writers.** Scale `halo-server` and `halo-shadow` to 0. Gateways and `halod` keep working on their last good state.
2. **Secrets first.** Recreate the Secrets from your secret manager: database URL, kill-switch key pair, gateway tokens, fleet token, session key. A different kill-switch key is a rotation.
3. **Restore the database** into an empty database: PITR to just before the incident, or `pg_restore --no-owner --exit-on-error -d halos halos-<date>.dump`. Never restore single tables: `halo_audit_head`, `halo_audit` and the export cursors (`halo_docs` kind `audit-cursor`) must come from one snapshot.
4. **Repoint** `server.database.existingSecret` at the restored instance if it has a new endpoint.
5. **Migrate if needed.** If the restored data is older than the binary's schema, the migrate hook Job (`server.database.migrateJob`) or `halo-server migrate` brings it forward; migrations are additive.
6. **Start one replica**, check, then scale out (below).
7. **Re-issue** what the RPO window lost: kills you know were active (`halo toggle kill`, `POST /api/v1/experiments/{name}/kill`), enrollments (devices re-enroll through the portal). If an audit export sink's cursor is ahead of the restored chain it halts; keep the SIEM copy and delete its cursor row ([Operations](/halos/guides/operations/#restore)).
8. **Release rings** need nothing if the registry survived. If it did not, mirror or republish from the policy repo with the release key, then `halo release refresh`.

## Verify a restore

```bash
kubectl -n halos get deploy halos-server                          # READY n/n
curl -fsS https://halos.example.com/readyz                        # 200
halo audit verify --database-url-file db-url                       # OK: N entries, head <hash>; exit 2 if broken
curl -fsS -H "Authorization: Bearer $ADMIN" https://halos.example.com/api/v1/killswitch | jq '.killed[] | select(.killed) | .experiment'
```

Then check: exactly one `halo_leader{lease="controller"} 1` across the replicas' metrics ports, the gateway poll succeeds (`GET /api/v1/gateway/killswitch` with the gateway token answers 200), and `halo_db_errors_total` is flat. Gateways pick up the restored list within one poll interval (default 10 s).

## The drill

`scripts/uat-dr.sh` runs the restore as an automated test and CI runs it (`uat-dr` job, `make uat-dr`):

1. install the chart with HA values on kind (2 `halo-server` replicas, Postgres, the migrate hook Job, kill switch on);
2. write state through the API: kill a toggle and an experiment;
3. `pg_dump`, then write one more kill that the dump will not contain;
4. scale the servers to 0, `DROP DATABASE`, create it empty;
5. `pg_restore`, scale back to 2;
6. assert: both replicas ready, the kill list equals the dump point (the later kill is gone, which is the RPO), the audit chain has the same entry count and head hash and `halo audit verify` passes, exactly one controller leader, the gateway endpoint answers 200, and a new write works with the chain still verified.

`scripts/uat-dr.sh local` runs the same assertions against a Docker Postgres and two `halo-server` processes, with no Kubernetes. The drill uses `--dev-insecure-user` and plain-TCP Postgres; it proves the procedure, not your storage or your provider's PITR. Run your own version of it, against your own backups, at least quarterly.
