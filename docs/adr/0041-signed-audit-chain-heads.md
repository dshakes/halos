---
title: "ADR-0041: Signed audit chain heads"
description: Opt-in signed checkpoints of the audit hash chain, made with a key from internal/signer (file, AWS KMS, external signer), appended as chained entries so they reach every SIEM sink, and a verifier that checks signatures and detects truncation against the newest checkpoint the SIEM holds.
status: accepted
date: 2026-11-01
---

# ADR-0041: Signed audit chain heads

- Status: accepted
- Date: 2026-11-01

## Context and problem statement

The audit log is a plain SHA-256 hash chain ([ADR-0016](/halos/adr/0016-audit-export-to-siem/)). It catches an edit by someone who does not recompute the hashes. Anyone with write access to the data dir or the `halo_audit` table can recompute them: edit an entry, re-hash it and everything after it, and the chain verifies. Cutting entries from the end leaves a valid chain too; the code said so (`truncating the newest entries is undetectable from the log alone`). The SIEM copy is the only outside reference, and nothing compared against it mechanically.

## Decision drivers

- A forger with database or file write access, but not the signing key, must be caught.
- The anchor must live outside the database, using what operators already run: the SIEM export sinks.
- Keys come from `internal/signer` ([ADR-0038](/halos/adr/0038-external-key-management-and-fips-builds/)): `file://`, `awskms://`, `exec://`, so the key can sit in a KMS or HSM.
- Opt-in and backward compatible: an unsigned log, and every log written before, verifies exactly as before.
- No KMS call on the hot path of every audit append.

## Decision

### Checkpoints

`--audit-signing-key-uri` names the key. Every `--audit-checkpoint-interval` (default `5m`), if entries arrived since the last checkpoint, and at every file-segment rotation, `halo-server` appends an `audit.checkpoint` entry:

```json
{"actor":"halo-server","action":"audit.checkpoint",
 "details":{"seq":"41","head":"<hash of entry 41>","alg":"ed25519","keyId":"sha256:...","sig":"<base64>"}}
```

**The signing marker and `since`.** When signing is first enabled, the server appends a signed `audit.signing.enabled` entry at seq S, signing `halos.audit.signing.v3\n<log id>\n<S>\n<hash it follows>\n<time>`. Every later signed entry carries the log id (16 random bytes, created with the marker and kept in the signing record) and `since=S` in its signed bytes, so a signature never replays across deployments that share a key: checkpoints sign `halos.audit.checkpoint.v3\n<since>\n<seq>\n<head>\n<time>` (the checkpoint entry's own time, RFC 3339 with nanoseconds, UTC), erasure vouches `halos.audit.erase.v3\n<since>\n...` and retention cuts `halos.audit.retention.v3\n<since>\n...`. Each is signed with the key's native algorithm (Ed25519, or ECDSA P-256 over SHA-256), so a KMS or HSM key works. A verifier with the key learns S from any signed entry. It then rejects every unsigned `subject.erase` or `audit.retention` at S or later, wherever it sits and whatever was cut before it. Unsigned ones before S are legacy, links-only.

The checkpoint is an ordinary chained entry. That gives three things for free:

- it is stored next to the entries it vouches for, on both backends;
- it is exported to every SIEM sink like any other entry, anchoring outside the database without a new delivery path;
- the checkpoint itself is covered by the next one.

**Verify, then sign.** Before signing, the server verifies the whole chain, incrementally from its cached verified prefix, and signs the head of the chain as verified, never a head read back from storage. If the chain does not verify, it refuses: the refusal is logged and counted in `halo_server_audit_sign_refused_total`. A head someone recomputed in storage is therefore never signed. The same rule guards erasure vouches and retention cuts ([ADR-0040](/halos/adr/0040-data-retention-and-erasure/)).

**Signing outside the lock.** The signature is made outside the audit lock (a KMS call may take tens of milliseconds), so entries may land between the head it signs and the checkpoint. The verifier accepts a checkpoint naming any of the preceding 256 entries. The append checks the distance under the lock that orders appends: the file backend's audit mutex, or Postgres's head-row lock inside the append transaction. If 224 or more entries landed while it signed (a slow KMS and a burst), the append refuses the checkpoint and the next interval retries, rather than append one the verifier would reject forever. No check-then-append gap remains.

**At rotation** a rotated segment ends with a checkpoint of its own last entry. Like every signature it is made only over a chain that verifies (an incremental verification under the lock) and only once the marker exists. It is bounded to 5 seconds: past that, the segment rotates unsigned and the periodic checkpoint covers it.

**What the key signs.** It signs only a head that is a SHA-256 hex digest, so it is never an oracle for whatever a writer put in the head column. `halo-server` refuses to start with an audit key that is also the kill-switch key or the release key. The same key also signs the vouch lists of `subject.erase` entries and `audit.retention` cuts ([ADR-0040](/halos/adr/0040-data-retention-and-erasure/)), each under its own message prefix (`halos.audit.erase.v1`, `halos.audit.retention.v1`), so no signature can be passed off as another kind.

With Postgres the periodic checkpoints run on one replica, under the `maintenance` lease.

### Verification

The chain check gains, per checkpoint entry: the seq it names must be one of the entries just before it, the head must be that entry's hash, and, given the public key, the signature must verify. `halo audit verify` gains:

- `--public-key PEM`, repeatable: check every signature against the key set (the current audit key and the keys it replaced, so a rotation keeps old checkpoints verifiable; halo-server takes the old ones with `--audit-previous-public-key-files`). It reports how many checkpoints verified, the last one, and the **unsigned tail** (entries after it). With it:
  - a log that carries no signed checkpoint fails;
  - after signing was enabled (seq S, above), only a signed `subject.erase` or `audit.retention` entry may vouch for a redaction or a cut; an unsigned one at S or later fails the chain. A chain with unsigned vouches or a cut and no signed entry at all fails too. The first `--public-key` is the current key: an entry signed by a later one (a previous key) after the current key has signed is refused.
- **Without `--public-key` nothing is authenticated.** Links and hashes are checked, but any chained `subject.erase` or `audit.retention`, forged or not, is accepted, and the output says `unsigned: ... not authenticated` (JSON `authenticated: false`).
- `--max-unsigned-tail N`: fail when more than N entries follow the last signed checkpoint.
- `--anchor FILE`: a file of exported entries (native, or OCSF with `raw_data`). Its newest checkpoint, whose own hash and signature are checked first, must still be in the log at the same seq with the same hash; otherwise the log was cut back behind it or rewritten. It compares that one entry only.
- `--compare-export FILE`: compares content. Every seq both the log and the SIEM export hold must have the same hash and content, unless the log's entry is a vouched-for redaction (counted as `redactedSinceExport`), and the log must reach the export's newest seq.
- `--file FILE`: verify an export as the SIEM received it, instead of the data dir or database.

It exits 2 on any failure. `GET /api/v1/audit` reports `signed`, `checkpoints` and `lastCheckpoint`.

What each attack now costs:

| Attack (write access, no key) | Caught by |
|---|---|
| Edit an entry, leave hashes | the hash check (as before) |
| Edit, recompute the chain, keep the checkpoints | the first later checkpoint: its `head` no longer matches |
| Also rewrite each checkpoint's `head` | its signature (`--public-key`) |
| Drop the checkpoints and recompute | the anchor or the export comparison (`--anchor`, `--compare-export`) |
| Edit an entry, mark it `redacted`, append a `subject.erase` vouching for it | `--public-key`: an unsigned vouch vouches for nothing; `--compare-export` lists it as redacted since export |
| Delete recent entries behind a forged `audit.retention` | `--public-key`: an unsigned cut is not accepted; without the key, a cut must be the system's and at least 30 days old at its own time |
| Cut entries from the end | the anchor (past the SIEM's newest checkpoint) or `--compare-export` (past the SIEM's newest entry) |
| Cut only entries the SIEM has not received yet | not caught: at most the export lag; `--max-unsigned-tail` bounds what is unsigned |
| Tamper, then let the server sign over it (the next checkpoint, an erasure vouch, a retention cut) | the server verifies before signing and refuses |
| Back-date the Postgres `at` column so a sweep signs a cut over fresh entries | cuts read times from verified bodies, never `at` |
| Forge an unsigned vouch, verify without a key | not caught: links-only verification authenticates nothing (stated in the output); use `--public-key` |
| Plant unsigned vouches after signing started, then delete the prefix holding every signed entry | every remaining signed entry binds `since`; with none left, `--public-key` fails. While the signing record or the running process survives, the server refuses to sign again; a writer who also deletes the record and restarts the server is caught only by `--anchor` or `--compare-export` |
| Delete the signed tail and the signing record, restart | the server writes no new marker over a non-empty log without the one-shot `--audit-signing-enable`; offline, `--strict --compare-export` catches it |
| Rewrite the tail with a leaked previous key | the server refuses once the record says the current key has signed (it records that after its first signature); offline, several `--public-key` require the newest checkpoint by the first key unless `--allow-rotation-window` |
| Replay a signed entry from another deployment that shares the key | every signed entry binds the log id, created at the marker |

### What signatures prove, and what needs an anchor

Signatures prove authorship. Every checkpoint, erasure vouch and retention cut was made by the audit key for this log (the log id), and no entry they cover was edited or recomputed since. So with `--public-key`:

- an edited entry is caught;
- a recomputed chain is caught;
- a forged redaction or cut is caught;
- a rewrite by a previous key after the current one signed is caught.

Signatures cannot prove that nothing was deleted. Someone who can write to the store can cut the tail back to an earlier checkpoint, or delete everything (signing record included) and start a new log. What is left still verifies. halo-server makes this as hard as it can on its own:

- it never writes a new signing marker over a non-empty log unless started once with `--audit-signing-enable`;
- it keeps the log's `since`, log id and current key in a record outside the chain, and in memory, and refuses to sign when they disagree;
- the Postgres verifier compares the table with its head row.

The record and the process are on the attacker's side of that line. Only an external copy closes the gap: the SIEM export. Run `halo audit verify --strict --public-key <key> --compare-export <SIEM export>` on a schedule. `--strict` fails without an anchor, and without `--strict`, `--public-key` alone prints a warning saying deletion is not detected.

**Rotation.** Restart all replicas together when the audit key changes. A replica still on the old key signing after one on the new key makes the chain fail (an old key after the current key is refused). While replicas switch, verify with `--allow-rotation-window`.

### Compatibility

Signing is off unless the flag is set. A log with no checkpoints verifies as before without `--public-key`; with it, it fails (there is nothing signed to trust). Erasures and cuts made before signing was on are unsigned, and stay valid with the key because they precede the signing marker. To rotate the key, keep the old public key in the set: `--audit-previous-public-key-files` on the server, another `--public-key` on the verifier. Retention and erasure ([ADR-0040](/halos/adr/0040-data-retention-and-erasure/)) keep checkpoints valid: a checkpoint names no person, so erasure never redacts one, and a checkpoint whose entry a retention cut removed is skipped (nothing is left to check it against).

## Consequences

- Positive: a forger without the key can no longer edit or recompute history undetectably, or forge a redaction or a cut. Deletion (of the tail, or of everything with the signing record) is caught only against the SIEM copy (above).
- Positive: works with a KMS or HSM key; one signature every interval, not per entry.
- Negative: an operator must keep the public key and run `halo audit verify --anchor` against the SIEM copy (for example, from a scheduled job). Nothing compares automatically.
- Negative: one extra audit entry per interval when there is activity (288 a day at the default).
- Negative: entries after the newest exported checkpoint can still be cut without trace; shorten `--audit-checkpoint-interval` to narrow that window.
- Neutral: the key signs checkpoints and the erasure and retention vouches, each under its own domain. It must be a dedicated key; `halo-server` refuses the release or kill-switch key.

## Considered options

- **Keyed chain (HMAC each entry).** Every verifier would need the secret, and the SIEM could not check anything. Rejected.
- **Sign every entry.** A KMS call per audit append, on the request path of every privileged action. Rejected.
- **Store checkpoints in a separate table or file.** A second delivery path to the SIEM, and the checkpoints themselves unchained. Rejected in favour of chained entries.
- **Public transparency log (Rekor).** Leaks audit volume and timing to a public log and needs internet access. Possible later as an extra sink.
