---
title: "ADR-0016: Audit export to SIEM"
description: halo-server forwards its hash-chained audit log to Splunk HEC, an HTTPS webhook or syslog over TLS, at least once and in order, rotates it into segments the chain runs across, and reads it by streaming.
status: accepted
date: 2026-10-21
---

# ADR-0016: Audit export to SIEM

## Context and problem statement

`halo-server` records privileged actions (kills, enrollments, revocations, approvals) in a hash-chained `audit.jsonl`. Three gaps stop a security team from relying on it. The only copy lives on the server's volume, so whoever controls that volume can drop the newest entries undetectably (the documented tail-truncation limit). The file grows forever. And every `GET /api/v1/audit` read the whole log into memory. How should the log leave the host, and how should it be bounded, without weakening the fail-closed append?

## Decision drivers

- Privileged actions keep failing closed on the local append; nothing remote may delay or fail them.
- No entry may be skipped, and the receiver must be able to verify the chain itself.
- Credentials (HEC tokens, API keys, HMAC secrets) never appear in config files, values, logs or errors.
- Memory use of reads must not grow with the log.
- No new dependency, and no new process to run.

## Considered options

1. **In-process forwarder with a persisted per-sink cursor** reading the local log after the append: at-least-once, in order.
2. **Synchronous dual write** to the SIEM inside the append. Ties every privileged action to the SIEM's availability; a SIEM outage becomes a Halos outage.
3. **Leave shipping to a log agent** (Fluent Bit, Vector) tailing `audit.jsonl`. No cursor tied to the chain, no chain checks, and rotation and torn lines handled by heuristics.

## Decision outcome

Chosen: **option 1**. Option 3 still works (the files are plain JSONL) for teams that already run an agent.

**Export.** `--audit-config` lists sinks: `splunk-hec` (`Authorization: Splunk <token>`, one HEC event per entry), `webhook` (a JSON array per batch, `X-Halo-Timestamp` and `X-Halo-Signature: sha256=HMAC(secret, timestamp.body)` as the controller's notifier signs, plus secret-valued headers such as `DD-API-KEY`) and `syslog` (RFC 5424 over TLS with RFC 5425 octet counting, facility 13 `log audit` by default). URLs must be https; syslog is TLS only; a CA bundle and a client certificate are optional. Each sink runs its own goroutine and cursor (`<data-dir>/audit-forward/<name>.json`, `{seq, hash}`), so one slow sink holds back only itself. An append wakes every sink; an idle sink also polls. A batch (default 100) is sent, then the cursor is written atomically; a crash in between resends that batch, so duplicates are bounded by one batch and receivers de-duplicate on `seq`. Failures retry from the same cursor with exponential backoff from 1 s, jittered, capped (default 5 min); nothing is ever skipped.

**Integrity.** The native format is the stored line, byte for byte, so a receiver can recompute each `hash` (blank the trailing `"hash"` value, SHA-256 the line) and check `prev` against the previous entry. The forwarder checks the same before sending: each entry must be `seq + 1` of the last one sent, link to its hash, and hash correctly. On the first that does not, it halts that sink and counts failures until an operator acts. A cursor ahead of the log, or an entry at the cursor's `seq` with a different hash, means the log was restored or rewritten and halts too. A new cursor anchors on the oldest entry still on disk.

**OCSF.** `format: ocsf` sends the OCSF 1.3 API Activity class instead:

| OCSF field | From |
|---|---|
| `class_uid` 6003, `category_uid` 6, `type_uid` 600399 | fixed (API Activity, Application Activity) |
| `activity_id` 99 (Other), `activity_name` | `action` (Halos actions are not CRUD verbs) |
| `time` | `time`, epoch milliseconds |
| `actor.user.uid`, `actor.user.name` | `actor` |
| `api.operation` | `action` |
| `api.request.uid` | `requestId` (omitted when empty) |
| `src_endpoint.ip` | `ip` (omitted when empty) |
| `resources[0].name` | `target` (omitted when empty) |
| `severity_id` 1, `status_id` 1 | fixed: only performed actions are audited |
| `metadata.sequence`, `metadata.uid`, `metadata.log_name` | `seq`, `hash`, `audit` |
| `metadata.product.name`, `vendor_name`, `metadata.version` | `Halos`, `Halos`, `1.3.0` |
| `unmapped.prev`, `unmapped.hash`, `unmapped.details` | `prev`, `hash`, `details` |
| `raw_data` | the stored line, so the hash stays verifiable |

**Rotation.** `rotation.maxBytes` and `rotation.maxAgeSeconds` rename the active `audit.jsonl` to `audit-<first seq, 20 digits>.jsonl` on the append that would cross a bound and open a new one. The chain does not restart: the new segment's first `prev` is the previous segment's last `hash`. A failed rotation is logged and counted, and the entry goes to the active segment; only a failed write or fsync fails the action, as before. The server never deletes a segment. `halo audit verify --data-dir` checks the chain across every segment.

**Reads.** `GET /api/v1/audit`, toggle history and the forwarder stream from a snapshot (rotated segments by name, the active segment by its own handle and size), so memory is bounded by the page size. Whole-chain verification streams too, and caches the state after the rotated segments keyed by their names, sizes and mtimes.

**Metrics** (on `--metrics-listen`, now served without `--controller`): `halo_server_audit_forward_sent_total`, `_failed_total`, `_lag_entries` and `_last_success_timestamp_seconds` per `sink`, and `halo_server_audit_rotate_errors_total`.

## Consequences

- Good: an external, append-only copy closes the tail-truncation gap, and a SIEM can verify the chain on its own.
- Good: a SIEM outage never blocks an action; lag and failures are metrics with alerts in the operations guide.
- Good: the log is bounded per file and reads no longer scale memory with history.
- Bad: syslog has no acknowledgement. A batch counts as delivered when the TLS write returns, so entries in flight when a connection drops can be lost. Prefer HEC or the webhook where loss is unacceptable.
- Bad: at-least-once means duplicates after a crash or a lost response; receivers de-duplicate on `seq` (or `metadata.sequence`).
- Bad: a broken chain stops export until a human acts. That is deliberate: forwarding entries that do not continue the exported chain would launder tampering.
- Neutral: secrets are read once at start; rotating a credential means restarting `halo-server`.
- Neutral: the API's cached verification of rotated segments misses an edit that keeps size and mtime; `halo audit verify` never caches.

## More information

- `internal/server/audit.go` (segments, streaming reads, `VerifyAuditDir`), `internal/server/audit_export.go` (config, sinks, forwarder, OCSF), `cmd/halo/cmd_audit.go`.
- [SIEM export guide](/halos/guides/siem-export/), [operations: audit log rotation](/halos/guides/operations/#audit-log-rotation), [security model: audit log](/halos/concepts/security-model/#audit-log).
