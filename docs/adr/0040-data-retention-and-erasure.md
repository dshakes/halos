---
title: "ADR-0040: Data retention and erasure"
description: Per-store, age-based retention for halo-server's unbounded stores on the file and Postgres backends, enforced by a leader-only sweep and off by default; an admin-only erasure API that deletes a person's records and pseudonymises them in the audit chain, which still verifies.
status: accepted
date: 2026-11-01
---

# ADR-0040: Data retention and erasure

- Status: accepted
- Date: 2026-11-01

## Context and problem statement

`halo-server` keeps personal data (user ids, OS users, hostnames, client IPs, IdP groups) in append-only stores that never shrink: fleet reports, access requests, devices, the audit chain, and the journal those stores replay from, on files under `--data-dir` or in Postgres ([ADR-0021](/halos/adr/0021-ha-control-plane-on-postgres/)). The [data flow page](/halos/compliance/data-flow-and-pii/) said so: "no API erases a user's audit entries or device rows". A privacy review asks for two things this blocks: a retention period per store (GDPR Art. 5(1)(e)) and a way to fulfil an erasure request (Art. 17). The audit chain ([ADR-0016](/halos/adr/0016-audit-export-to-siem/)) makes the second hard: any edit breaks its hashes, which is the point of it.

## Decision drivers

- Nothing compliance-relevant is deleted unless an operator asks: retention is off by default.
- One mechanism on both backends, and on every replica: a record deleted on one replica must not live on in another's memory or come back on a restart.
- After an erasure, `halo audit verify` still passes, and it still fails on any tampering it caught before.
- Erasure is a privileged, irreversible act: a person with a global admin binding ([ADR-0037](/halos/adr/0037-scoped-role-bindings/)), with a reason, audited at high severity, never on their own data.
- No new dependency, no schema migration.

## Decision

### Retention

Four flags, each an age; `0` (the default) keeps the store forever, as before.

| Flag | Deletes | Recommended |
|---|---|---|
| `--retention-fleet-reports` | reporters whose last report is older, with their history | `2160h` |
| `--retention-requests` | access requests decided longer ago (pending ones never) | `8760h` |
| `--retention-devices` | revoked devices unused for that long, expired devices that long after expiry (active ones never) | `2160h` |
| `--retention-audit` | audit entries older (at least `720h`); never entries a SIEM sink has not delivered | `9528h` (13 months) |

A sweep runs every `--retention-interval` (default `1h`) inside `Server.RunMaintenance`. With Postgres it runs under the existing leader lease mechanism, lease `maintenance`, so exactly one replica sweeps. Each sweep that removes something appends a `retention.sweep` audit entry with the counts.

**Journal stores** (requests, devices) delete in three steps under the store's lock: append a tombstone record `{"erase": [ids]}`, drop the ids from memory, then compact the log. Every replica's replay applies the tombstone, so another replica's memory converges at its next catch-up, and a late record for a deleted id (a `lastSeen` write in flight) is ignored rather than resurrecting it. Compaction is a new optional `storage.Log` capability (`storage.Compact`): the file log rewrites itself atomically without the selected records, the Postgres log deletes the rows under the stream's advisory lock. The tombstones stay; they hold only random ids. A failed compaction is retried by the next removal.

**Fleet reports** are deleted directly (the file store rewrites its compacted log; Postgres deletes from `halo_reports` and `halo_report_history`). The cutoff is the `lastSeen` the server stamped, on both backends.

**Audit retention** cuts a prefix. It picks the newest entry older than the cutoff that every configured export sink has delivered (each sink's own cursor, by name; a sink with no cursor yet holds everything), appends an `audit.retention` entry naming that seq and its hash, and only then deletes.

- **What it may cut.** First the whole chain must verify (below, "Nothing is signed over an unverified chain"). The cut is then the contiguous prefix of entries whose time, read from each entry's verified body (its hash matches, or it is a vouched-for redaction, and it links to the one before), is older than the cutoff. The Postgres `at` column, which anyone with write access can back-date, is never used, and one entry stamped in the past by a skewed replica cannot pull newer ones in.
- **File backend.** Segments are deleted whole, so it needs rotation on.
- **Crash safety.** A crash between the entry and the delete leaves a recorded cut not yet made, never an unrecorded one.

Verification accepts a chain that starts at seq N+1 only if a later `audit.retention` entry names seq N and the hash the first remaining entry links to, its actor is `halo-server`, and its `cutoff` is at least `MinAuditRetention` (30 days) before its own time. With an audit key ([ADR-0041](/halos/adr/0041-signed-audit-chain-heads/)) the entry is signed (`halos.audit.retention.v1`, over through, throughHash, cutoff and time), and a verifier given the public key accepts only a signed cut. Any other missing prefix is reported as removed entries.

### Erasure

`POST /api/v1/users/erase` with `{"user", "aliases", "reason", "dryRun"}`. The subject is in the body so it never reaches request logs. It needs `admin` with a global binding, a person (`requireHuman`: no service token or break-glass), and a reason. One erasure runs at a time across replicas, under a cluster lock renewed every 10 seconds while it runs. If a renewal fails, the erasure is cancelled before it touches the audit log, since another replica may hold the lock by then. `dryRun` reports the counts and changes nothing.

Audit entries about a pending or previewed erasure name the subject by `h:` plus HMAC-SHA256 of the canonical id, under a key derived from the session key with HKDF (label `halos/erasure-subject-hash/v1`). Without that key, a dictionary of candidate ids cannot reverse it. The earlier salted SHA-256 put its salt in the same entry, which made it reversible.

**Who and what may be erased.**

- **Never yourself.** The caller's id, and the id their service token acts for, may not match the user or any alias, in either direction, compared as canonical ids and after a `kind:` prefix (`user:boss@x`, ` BOSS@X `).
- **Aliases must identify a person.** The user and every alias are refused when shorter than 3 characters, purely numeric, shaped like a time, an `erased-` pseudonym, `halo-server`, a role name, a request status, or a ring in current policy. Such a value would match seqs, counts or statuses, not a person.
- **Two-person rule, for every erasure.** Erasure destroys evidence, and erasures are rare, so no single admin may erase anyone. This also removes any dependence on detecting who is an admin; an IdP-group-only admin leaves no server-side trace once their login entries age out. Only a dry run answers at once.
  - **Request.** The first call answers 202 with a pending erasure, audited as `subject.erase.request`.
  - **Review.** A second admin reads it with `GET /api/v1/users/erase/{id}`.
  - **Confirm.** A different admin, a person and not the subject, confirms it within an hour with `POST /api/v1/users/erase/{id}/confirm`. They must resubmit the same user, aliases and reason (compared as canonical ids, aliases as a set): a mismatch is 409 and the erasure stays pending, so nobody confirms blind.
  - **Locking.** The confirmation takes the erasure lock before it takes the pending erasure, so a busy lock (503) loses nothing.
  - **Replicas.** The pending erasure lives in the shared KV, so any replica can confirm it, and only one confirmation wins.
  - **Record.** The `subject.erase` entry names the confirming admin as actor and the first in `requestedBy`.

**In order:**

1. The subject's sessions are revoked (the session epoch is kept; see below).
2. Their devices are deleted (tokens stop working on every replica at once: device authentication catches up first).
3. Access requests they filed are deleted; requests they decided or approved keep their place with the subject replaced by a pseudonym. Compaction drops the deleted requests' records and the superseded records of the rewritten ones (every record of that id but the one just saved), and never touches another request.
4. Fleet reports whose user is the subject or an alias (an OS user a fleet-token report carries) are deleted, latest and history.
5. Every audit entry naming the subject in an **identity field** is redacted. The identity fields are the actor; the target; the details `user`, `by`, `onBehalfOf`, `approver`, `subject`, `requester`, `owner`, `createdBy`, `principal`, `decidedBy`, `vendorUser` and `email`; and inside a session-ledger record, `who.user`, `who.vendorUser` and `who.agents`. Each matching value becomes the pseudonym, the client IP of the subject's own actions is dropped, and the entry is marked `redacted: true`. Seq, prev and hash stay as they were. Other detail values are never touched, and neither are `audit.checkpoint`, `audit.retention` or `subject.erase` entries.

The pseudonym is random per erasure (`erased-<12 chars>`), not an HMAC of the subject: an HMAC under a key the operator holds would still be personal data, and there is nothing to correlate after the person is gone.

The report lists what was removed per store, and `retained` names what is kept and why: the session epoch (a user id and a timestamp that keep the subject's sessions dead; deleting it would revive their cookies), credential revocations (expire within the hour), rollout-step approvals (change records; their audit entries are redacted), service tokens (not personal data), SCIM (deprovision in the IdP first), budget counters (pruned after 95 days), and the copies already in the SIEM.

### How the audit chain still verifies after an erasure

A redacted entry no longer matches its hash, and cannot: recomputing it would change every later hash, which is what a forger does. So:

- A redacted entry keeps its original `hash`. The next entry's `prev` still matches it, so the chain still links and its order and completeness are still checked.
- Before redacting, the server appends a `subject.erase` entry (actor: the admin; target: the pseudonym; `severity: high`; the reason, the counts, the number of aliases and a keyed hash of each) whose `redacted` detail lists `seq:digest` for every entry it will redact, where digest is SHA-256 over the whole redacted entry, original hash included. With an audit key the server signs `halos.audit.erase.v1\n<pseudonym>\n<redacted list>` and stores the signature in the entry. Large erasures are split over several `subject.erase` entries, each signed.
- The verifier skips the hash check for an entry marked `redacted` but requires a later `subject.erase` entry to list its seq with the digest of its current content. A redacted entry edited again has no matching digest and fails.
- **Given the public key, only a signed `subject.erase` vouches** (or a legacy unsigned one from before signing was enabled, below). Without that rule anyone with write access could mark an entry `redacted`, edit it, and append a chained `subject.erase` vouching for the edit; that exact forgery is a regression test. A `subject.erase` with a signature that does not verify fails the chain outright. Without the key (links-only verification) any chained `subject.erase` vouches, as before; `--compare-export` then shows which entries were redacted after the SIEM received them.
- The export forwarder accepts redacted entries the same way, so export does not halt on them.

**When an unsigned vouch is accepted (the signing marker).** When signing is first enabled, the server appends a signed `audit.signing.enabled` entry at seq S, signing S and the hash it follows. Every signed entry after it (checkpoint, `subject.erase`, `audit.retention`) carries `since=S` inside its signed bytes. So a verifier with the key learns S from any signed entry it verifies, even after retention has cut the marker away. From then on:

- an unsigned `subject.erase` or `audit.retention` at seq S or later is a forgery and fails the chain, wherever it sits and whatever was cut before it;
- one before S is legacy (made before signing was enabled) and is checked links-only.

Retention never cuts the newest checkpoint, or the entry it names, so a signed entry always remains. A chain with unsigned vouches or a cut and no signed entry at all fails offline verification with the key.

The server also keeps S, the log id and the newest key that has signed in a record outside the chain (a document on Postgres, `audit-signing.json` in the data dir) and in memory. It refuses to sign over a chain that lost every signed entry, names a different S or log, or whose newest signed entry is by a previous key once the current one has signed. It writes the marker only over an empty log, or once with `--audit-signing-enable`. The record lives in the same storage as the chain: deletion of everything is caught only against the SIEM copy ([ADR-0041](/halos/adr/0041-signed-audit-chain-heads/), "What signatures prove").

Without a key nothing is authenticated: links-only verification accepts any chained vouch, and `halo audit verify` says so.

### Nothing is signed over an unverified chain

The server signs four things: the signing marker, checkpoints (periodic, and at segment rotation), erasure vouches and retention cuts. If it signed over a chain someone with write access had changed, its signature would launder the change. So before signing any of them it verifies the chain, incrementally from the cached verified prefix, and refuses to sign when the chain does not verify.

When an entry the work needs is not proven by the cached chain (another replica redacted it since), the server drops the cache and re-verifies once before refusing. Redactions are stored compare-and-swap: a row that no longer holds the body read is not overwritten. Postgres reads page through the table, each page under its own timeout, so a log of any size can be verified.

- The refusal is logged at error level and counted in `halo_server_audit_sign_refused_total`.
- A refused erasure changes nothing.
- An erasure never redacts an entry whose content is not proven (its hash matches, or a `subject.erase` vouched for it with its current digest).
- A checkpoint signs the head of the chain as verified, never a head read from storage.
- With the signing record, the server refuses to sign over a chain that lost every signed entry.

`omitempty` on `redacted` keeps every existing entry's hash unchanged: logs written before this ADR verify as before.

### Threats and how each is handled

| Threat | Handling |
|---|---|
| Write access to the store: rewrite an entry, mark it `redacted`, append a `subject.erase` vouching for it | With the key, only a signed `subject.erase` vouches (above); without it, `--compare-export` lists it as redacted since export |
| Write access: delete recent entries behind a forged `audit.retention` | A cut must be the system's and at least 30 days old at its own time; with the key it must be signed |
| An admin erasing their own trail, directly or through an alias | Refused for the user and every alias, canonically, both directions |
| An admin erasing anyone's trail alone, or a second admin confirming blind | Two-person rule for every erasure; the confirmer resubmits user, aliases and reason, a mismatch is 409 |
| Write access: tamper with an entry (frame someone), then have a legitimate erasure sign a vouch over it | The server verifies the chain before every erasure and refuses; it never redacts unproven content |
| Write access: back-date the Postgres `at` column, or a segment's last entry, so a signed cut covers fresh entries | The cut reads times from verified bodies only; a back-dated body breaks its hash, and the sweep refuses to sign over a chain that does not verify |
| Write access: recompute the head, then let the periodic checkpoint sign it | The checkpoint signs the verified head only; a recomputed chain fails at its earlier checkpoints |
| Dictionary attack on subject hashes in `subject.erase.request` and preview entries | Keyed HMAC under a server-held key |
| Enabling the audit key after an erasure, or rotating it | Unsigned vouches before the signing marker (seq S) are legacy and accepted; previous keys stay in the key set (`--audit-previous-public-key-files`, repeated `--public-key`, the current key first), each valid only until the current key has signed |
| Planting unsigned vouches after signing started, then deleting the prefix that held every signed entry | Every signed entry binds `since=S`, so an unsigned vouch at S or later fails wherever it sits; retention keeps the newest checkpoint; the server refuses to sign over a chain without a signed entry when its signing record says S |
| A previous (leaked) key signing new entries | Refused once the current key has signed |
| The erasure lock lost mid-erasure | The erasure is cancelled before it touches the audit log |
| Aliases that match non-identity values (`3`, `pending`, `halo-server`), rewriting seqs, statuses or checkpoints | Aliases must identify a person; only identity fields are redacted; chain entries never |
| Erasure compaction dropping other users' live records | Compaction drops only the erased ids and the superseded records of rewritten ones |
| A new SIEM sink's undelivered entries pruned because another sink's cursor is ahead | Each configured sink's own cursor is read by name |
| A replica with a skewed clock widening a Postgres cut | Only the contiguous prefix older than the cutoff (body times) is cut |
| The erasure lock expiring mid-erasure, letting a second erasure race the first | The lock is renewed while the erasure runs |
| Store errors or the subject leaking into responses and audit entries | Errors are generic (the detail goes to the server log); a preview names the subject by a keyed hash only |

The file backend rewrites a segment by streaming it through a temporary file, so memory stays at one line. The audit lock is held for one pass over the segments that hold redacted entries, which is bounded per segment by rotation's `maxBytes`. Enable rotation on large logs.

## Consequences

- Positive: retention is configurable per store on both backends; erasure is one audited call; the chain stays verifiable, and the erasure itself is in it.
- Positive: deleting audit segments by hand, which broke `halo audit verify`, is replaced by a recorded cut.
- Negative: `subject.erase` entries and `retention.sweep` entries are themselves records about the erasure (a pseudonym, the counts, the reason). Write the reason as a ticket number, not the person's name.
- Negative: the SIEM keeps what it received. The `subject.erase` entry is exported, so the SIEM can be told; erasing there is the operator's procedure.
- Negative: only identity fields are redacted. Free text, or a detail key outside the identity list, that names the subject stays in clear. Pass every identifier as an alias, and add a key to the identity list when a new audit action stores a person under another name.
- Negative: every erasure needs a second admin within an hour.
- Negative: a chain that does not verify blocks erasures, retention cuts and checkpoints until an operator investigates (by design; the metric and the log say so).
- Negative: the signing record lives in the same storage as the chain. An attacker who deletes every signed entry and the record, then restarts the server, is caught only offline: `--public-key` fails a log with no signed checkpoint, and `--anchor` or `--compare-export` against the SIEM.
- Negative: an audit entry naming the subject appended while an erasure runs stays in clear. Erasure is idempotent: run it again.
- Negative: approvals of rollout steps and SCIM records are not touched (above).
- Neutral: the audit `total` in `GET /api/v1/audit` is the number of entries kept after retention.

## Considered options

- **Commitment-based entries** (hash over a salted digest of each field, so a field can be dropped without breaking the hash). Clean for new entries, but every existing log would stay unerasable and the entry format changes. Rejected.
- **Recompute the chain after redaction and re-anchor.** Indistinguishable from a forger recomputing it; every anchored checkpoint would stop matching. Rejected.
- **Tombstone the entry entirely** (keep only seq, prev, hash). Loses the action and time, which the audit trail still needs about other people. Rejected in favour of field-level pseudonymisation.
- **Delete rows directly in Postgres** without tombstones. Other replicas would keep the records in memory until restart. Rejected.
