---
title: Agent session ledger
description: Answer "which agent sessions ran, for whom, with what, and on what evidence" from one redacted, identity-linked, tamper-evident record per session.
---

The session ledger keeps one record per agent session: who ran it (and the delegated agent chain), harness and version, release, ring and experiment variant, models, MCP servers and tools, repositories and files (hashed or dropped), tokens, cost, start and end, outcome, and which evidence sources it rests on ([ADR-0031](/halos/adr/0031-agent-session-ledger/)).

Records are redacted before they leave the importing machine, stored by `halo-server` in the hash-chained audit log, and shipped to your SIEM with the rest of the chain. No field can hold prompt text.

## Import sessions

`halo sessions import` reads one or more sources, merges records of the same session, redacts them and posts them to `halo-server` (admin role). Run it on a schedule, for example a nightly CI job.

```console
export HALO_SERVER=https://halo.example.com HALO_SESSION=...   # an admin session
halo sessions import --source gateway --source otel \
  --clickhouse https://clickhouse.example.com:8443 --since 24h --dry-run
halo sessions import --source gateway --source otel \
  --clickhouse https://clickhouse.example.com:8443 --since 24h
```

`--dry-run` prints the normalized, redacted records and stores nothing. Start there.

| Source | Reads | Confidence | Needs |
|---|---|---|---|
| `gateway` | halo-proxy GenAI spans in ClickHouse, one record per trace | high | `telemetry.genai.traces` enabled on halo-proxy (off by default) |
| `otel` | Claude Code OTel events in ClickHouse, one record per `session.id` | medium (self-reported) | Claude Code exporting OTel to the collector |
| `anthropic` | Anthropic Compliance API `ccr_session_created` activities | high | a compliance key in `HALO_SESSIONS_ANTHROPIC_TOKEN` or `--anthropic-token-file` |
| `github` | GitHub enterprise audit log events with an `agent_session_id` | high | `--github-enterprise` and a `read:audit_log` token in `HALO_SESSIONS_GITHUB_TOKEN` or `--github-token-file` |
| `jsonl` | your own records, one per line (`--file`) | low | strict schema: an unknown field such as `prompt` fails the import |

Vendor credentials come from a file or an environment variable, never a flag value, and are never printed. A failing source stops the import before anything is sent.

The Anthropic `created_at` filter encoding and the GitHub `action:agent_session` search phrase are taken from the vendor docs and have not been checked against a live API. Override the phrase with `--github-phrase` if your audit log uses another.

## Redaction

Redaction is mandatory and fails closed:

- Every stored string must be a short identifier (no whitespace, quotes or control characters, at most 256 bytes). A value that is not is dropped and counted in the record's `redacted` field; a bad session id or harness rejects the whole import.
- `--paths drop` (default) keeps only the count of files touched. `--paths hash --hash-salt-file FILE` stores `h:` plus an HMAC-SHA256 of each path and repository, so you can match the same file across sessions without storing it. Keep the salt (16 bytes or more) stable and secret. Hash mode without a salt is an error before anything is read.
- `halo-server` validates every record again and refuses the whole batch on the first violation, so a client that skips the CLI cannot store raw paths or prose either.

## Identity

`halo-server` ignores any user the importer sends. It sets `who.user` from the [SCIM directory](/halos/guides/scim-provisioning/): an active user whose `userName` matches the identity the source reported. Unknown or deactivated identities stay unresolved and are listed under their vendor identity (`who.vendorUser`). Gateway records carry only the salted `halo.unit` pseudonym.

## Read and export

Reading needs the audit permission (auditor or admin role).

```console
halo sessions list --since 7d --user alice@example.com
halo sessions show <id>
halo sessions export --since 30d > sessions.jsonl
```

Filters: `--user`, `--harness`, `--ring`, `--tool`, `--since`, `--until`. Each response says whether the audit chain verified; `export` exits 1 when it does not. The same data is at `GET /api/v1/sessions[/{id}]` ([API](/halos/reference/api/)) and, for agents, the read-only MCP tool `session_ledger`.

Records reach SIEM sinks as audit entries with action `session.record` ([SIEM export](/halos/guides/siem-export/#agent-sessions)). For analytics, `--write-clickhouse` copies stored records into `halo.halo_session_ledger`; each row carries `record_sha256` so it can be checked against the chain. ClickHouse is a copy, not the evidence.

## Limits

- Sources do not share a session key. Records from different planes for one real session merge only when harness and session id match; `sources` and `confidence` say what each record rests on.
- Most sources cannot tell how a session ended, so `outcome` is often `unknown`. It is never guessed.
- GitHub logins and Anthropic account ids resolve only when they equal the SCIM `userName`.
- Codex, Gemini CLI, Cursor and Copilot CLI sessions arrive through gateway spans or a JSONL import; they have no per-session audit API.
