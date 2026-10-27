---
title: "ADR-0031: Agent session ledger"
description: One vendor-neutral, identity-linked record per agent session, built from gateway, OTel, vendor audit APIs and imports, redacted fail-closed (no field can hold prompt text), stored by halo-server in the hash-chained audit log and exported to SIEM with it.
status: accepted
date: 2026-10-27
---

# ADR-0031: Agent session ledger

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

A security or compliance team asks one question Halos cannot answer today: which agent sessions ran, for whom, with what, and on what evidence? The answer is spread across planes that do not share a key. halo-proxy sees routed model calls (cohort, model, tokens) but exports no user or session id ([gwmetrics](https://github.com/dshakes/halos/tree/main/internal/telemetry/gwmetrics)). Claude Code's OTel events carry a session id and an email but arrive on the client-reachable collector receiver. Vendors keep their own audit trails (the Anthropic Compliance API, the GitHub enterprise audit log). Delegated agents (ADR-0024) add a chain of actors between the human and the call.

How should Halos produce one normalized record per session, linked to a Halos identity, without storing prompt content and without a new trust boundary?

## Vendor research (checked 2026-10-27)

Primary sources only. Where a shape could not be confirmed it is marked UNVERIFIED and the code treats it as an assumption a fake encodes.

| Source | What it exposes per session | Auth | Status |
|---|---|---|---|
| Claude Code OTel events[^c1] | `session.id`, `user.email`, `user.account_id`, `app.version` (opt-in), `organization.id`; `claude_code.api_request` (`model`, `input_tokens`, `output_tokens`, `cost_usd`); `claude_code.tool_result` (`tool_name`, `success`; `tool_parameters` with `mcp_server_name` only with `OTEL_LOG_TOOL_DETAILS=1`); `vcs.repository.url.full` with `OTEL_METRICS_INCLUDE_REPOSITORY=1`. Prompts only with `OTEL_LOG_USER_PROMPTS=1` | the collector's receivers | attributes verified; `service.version` as the version fallback UNVERIFIED |
| Anthropic Compliance API[^a1] | `GET /v1/compliance/activities`, filter `activity_types[]`, `created_at.{gte,lt}`, `order`, cursor `after_id`/`last_id`/`has_more`. `ccr_session_created` (Claude Code cloud session) carries `id`, `created_at`, `actor` (`user_actor`: `email_address`, `user_id`; `api_actor`: `api_key_id`) and `agent_id`. **No session id, model, tool or usage field** | `Authorization: Bearer` compliance key, `anthropic-version: 2023-06-01` | endpoint, fields and pagination verified from the reference; the dotted encoding of the nested `created_at` filter is taken from the reference's prose (`updated_at.gte`) and is UNVERIFIED against a live call |
| GitHub enterprise audit log[^g1][^g2] | `GET /enterprises/{enterprise}/audit-log` (`phrase`, `include`, `order`, `per_page`, cursor `after` in the `Link` header). Events carry `actor`, `user`, `repo`, `@timestamp`, `actor_is_agent`; `agent_session_id` is documented on `pull_request.create` | classic PAT or OAuth token with `read:audit_log`; enterprise admin | endpoint and fields verified. An `agent_session.*` action family is **not** in the published event list; the default search phrase `action:agent_session` is UNVERIFIED and can be replaced with `--github-phrase` |
| halo-proxy GenAI spans | per call: `gen_ai.request.model`, `gen_ai.usage.*`, `halo.ring/release/experiment/variant/harness`, `halo.unit` (salted subject hash), `halo.actor.chain`; W3C trace id from the caller's `traceparent` | collector gateway receiver (bearer token), `halo.source=gateway` stamped by the collector | Halos's own; the clickhouseexporter `otel_traces` column names (`TraceId`, `SpanAttributes`, `Duration` in ns) are UNVERIFIED in this change (`make obs-e2e` covers metrics and logs, not this query) |

Codex, Gemini CLI, Cursor and Copilot CLI have no per-session audit API Halos could verify (ADR-0025's research applies); their sessions reach the ledger through halo-proxy spans or a JSONL import.

## Decision drivers

- No prompt or response text, tool input or error text is ever read or stored. Redaction is mandatory and fails closed.
- The Halos identity on a record comes from the identity directory on the server, never from a client or a vendor field (the same rule as invariant 4 for cohort headers).
- Tamper evidence and SIEM delivery as strong as the audit log's (ADR-0016), on both backends (ADR-0021).
- Vendor credentials are handled exactly as in ADR-0025: file or environment variable, never a flag value, never printed.
- Every record says where its evidence came from and how much to trust it.
- No new dependency, process or trust boundary.

## Considered options

1. **Records in the existing audit chain**, written by halo-server after validation, copied to ClickHouse for analytics. Chosen.
2. **A second hash chain** (`sessions.jsonl`) beside the audit log. Rejected: a second chain needs its own verifier, rotation, export cursor and Postgres table, and its truncation would not be visible in the SIEM copy of the audit log.
3. **ClickHouse only.** Rejected: ClickHouse rows are mutable and unchained; it is fine as a query copy, not as evidence.
4. **halo-server polls the vendors.** Rejected for the same reason ADR-0025 rejected it: long-lived vendor credentials in the server. A scheduled `halo sessions import` (CI cron) does the polling.

## Decision outcome

### Record

One `ledger.Record` per session (`internal/ledger`):

| Field | Meaning |
|---|---|
| `id` | `hex(sha256(harness, 0, sessionId))[:24]`: stable across sources and imports |
| `sessionId`, `harness`, `harnessVersion` | the harness's session id (a trace id for gateway evidence, an activity id for Compliance API evidence) |
| `who.user` | Halos identity (SCIM `userName`), set by halo-server only; empty when unresolved |
| `who.vendorUser`, `who.unit` | the identity the source reported; the `halo.unit` pseudonym for gateway evidence |
| `who.agents` | delegated agent chain, root side first (ADR-0024 `halo.actor.chain`, the Compliance API `agent_id`, a GitHub actor with `actor_is_agent`) |
| `release`, `ring`, `experiment`, `variant` | cohort |
| `models`, `mcpServers`, `tools` | identifiers only |
| `repos`, `files`, `filesTouched` | `h:<hmac>` or dropped (below); the count survives |
| `inputTokens`, `outputTokens`, `costUsd`, `start`, `end` | usage and span |
| `outcome` | `completed`, `error`, `cancelled` or `unknown` (most sources cannot tell; never guessed) |
| `sources`, `confidence`, `redacted` | evidence, its trust, and how many values redaction withheld |

### Sources and confidence

| Source | Grouping | Confidence | Notes |
|---|---|---|---|
| `gateway` | per trace id, spans with `halo.source=gateway` | high | identity is the `halo.unit` pseudonym only (halo-proxy never exports the subject) |
| `anthropic` | per `ccr_session_created` activity | high | proves who started a cloud session when; nothing about what it did |
| `github` | per `agent_session_id` | high | the human is `user` when `actor_is_agent`, else `actor`; the agent goes to `who.agents` |
| `otel` | per `session.id`, `claude_code.*` events | medium | client-reachable receiver: self-reported. The query names each attribute; it never selects `prompt`, `tool_input`, `error` or raw `tool_parameters` (which holds Bash commands), only `JSONExtractString(tool_parameters, 'mcp_server_name')` |
| `jsonl` | per line | low | strict decoding: an unknown field (`prompt`) fails the import; `sources`, `confidence` and `id` in the file are overwritten |

Records of the same session from several sources merge: scalars from the most trusted source, lists unioned, counters take the larger reading (two sources measuring one session must not double count), the span widens. Confidence is the best source's.

### Redaction (fail closed)

- **Prompt content has no field.** Every string in a record must match `^[A-Za-z0-9][A-Za-z0-9._%+@:/=>#~-]*$` and be at most 256 bytes: no whitespace, quotes or control characters, so no field can carry prose. A non-conforming identifier from a source is dropped and counted in `redacted`; a non-conforming session id or harness rejects the whole import. There is no opt-in to store prompt text.
- **Paths.** `--paths drop` (default) keeps only `filesTouched`; `--paths hash` stores `h:` + HMAC-SHA256(salt, path) truncated to 128 bits, with a salt of at least 16 bytes from `--hash-salt-file`. Hash mode without a salt, or an unknown mode, is an error before anything is read.
- Redaction runs in `halo sessions import` before anything is printed or sent. halo-server re-validates every record (`Validate`) and refuses the whole batch on the first violation, so a client that skips the CLI cannot store a raw path or prose either.

### Identity join

halo-server discards any `who.user` in the body and sets it from the SCIM directory (ADR-0022): an **active** user whose `userName` equals `who.vendorUser` (case-insensitive). A deactivated user, an unknown identity or a server without SCIM leaves the session unresolved; it is still listed, attributed to its vendor identity. A GitHub login resolves only when it is the SCIM `userName`. Mapping vendor logins to directory users is not built (see consequences).

### Storage and tamper evidence

`POST /api/v1/sessions` (admin) appends each record as an audit entry: action `session.record`, actor the importing admin, target the ledger id, `details.record` the record JSON. The audit chain is the ledger: `halo audit verify` covers it, rotation and the Postgres backend apply unchanged, and the ADR-0016 exporter ships every record to each SIEM sink (OCSF: `api.operation` `session.record`, `unmapped.details.record`). Re-importing a session appends a new version; readers take the newest `seq` per id. Reads (`GET /api/v1/sessions`, `/{id}`) stream the chain, report `verified`/`verifyError`/`head` like `GET /api/v1/audit`, and return each record with the `auditSeq`/`auditHash` of its entry.

`halo sessions import --write-clickhouse` copies the stored records to `halo.halo_session_ledger` (`deploy/observability/clickhouse/schema.sql`; `ReplacingMergeTree(stored_at)`, ordered by id, 400-day TTL) for analytics. Each row carries `record_sha256`, the SHA-256 of the record JSON in its audit entry, so a row can be checked against the chain. ClickHouse is a copy, never the evidence.

### Access

Reading the ledger needs the **audit** permission (auditor and admin roles), not read: it is per-person activity stored in the audit chain, and ADR-0015 keeps audit separate from fleet read. Ingest needs admin. The MCP tool `session_ledger` is read-only, calls the read API with the operator's `HALO_SESSION`, and takes no credential or URL argument.

### Surfaces

- `halo sessions import --source gateway|otel|anthropic|github|jsonl` (repeatable), `--since/--until`, `--paths`, `--hash-salt-file`, `--dry-run`, `--write-clickhouse`; vendor credentials via `--anthropic-token-file`/`--github-token-file` or `HALO_SESSIONS_{ANTHROPIC,GITHUB}_TOKEN` (deliberately not the `HALO_ADMIN_*` console keys). The vendor clients are `vendoradmin.Client`: token in the `Authorization` header only, scrubbed from errors, https (or loopback http) only, no redirects. The GitHub `Link` header is never followed; only its `after` cursor is used.
- `halo sessions list|show|export` with `--user`, `--harness`, `--ring`, `--tool`, `--since`, `--until`. `export` writes JSONL and exits 1 when the chain does not verify.
- `GET /api/v1/sessions[/{id}]`, `POST /api/v1/sessions`; MCP `session_ledger`.

### Failure modes

- A source fails (HTTP error, missing table, missing credential): the import stops before anything is sent and names the source; the error never carries the credential.
- One invalid record: nothing from that import is stored (CLI) or from that batch (server).
- The audit append fails mid-batch: the server answers 500 with how many records it stored; re-running stores the rest again (duplicates are harmless versions).
- Gateway evidence without spans: `telemetry.genai.traces` is off by default on halo-proxy, so the gateway source returns nothing until it is enabled.

## Consequences

- Good: one record answers who ran which agent, where, with what, and on what evidence, without prompt text, and every record is in the tamper-evident chain the SIEM already receives.
- Good: no second chain, no new credential in the server, no new dependency.
- Bad: reads scan the audit chain (O(log) per request). Fine for an audit-sized log; analytics belong on the ClickHouse copy.
- Bad: the sources do not share a session key. Gateway evidence is per trace and pseudonymous, Compliance API evidence is per activity without a session id, and OTel evidence is self-reported. Records from different planes for one real session are not joined unless they share harness and session id. The `confidence` and `sources` fields say what each record rests on.
- Bad: GitHub logins and Anthropic account ids resolve only when they equal the SCIM `userName`. A vendor-identity map (SCIM `emails`, `externalId`) is the next step if unresolved sessions are common.
- Neutral: re-imports grow the audit log; rotation (ADR-0016) bounds each file.
- Neutral: no live vendor API was called in building this. The httptest fakes encode the documented shapes; the UNVERIFIED items above are where a live run may differ.

## More information

`internal/ledger`, `internal/server/sessionledger.go`, `cmd/halo/cmd_sessions.go`, `internal/mcpserver/tools_autopilot.go` (`session_ledger`); [halo-server API](/halos/reference/api/), [SIEM export](/halos/guides/siem-export/#agent-sessions).

[^c1]: https://code.claude.com/docs/en/monitoring-usage (standard attributes, `claude_code.tool_result`, `claude_code.api_request`; checked 2026-10-27)
[^a1]: https://platform.claude.com/docs/en/api/compliance/activities and https://platform.claude.com/docs/en/manage-claude/compliance-api (checked 2026-10-27)
[^g1]: https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log (checked 2026-10-27)
[^g2]: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise (`pull_request.create` fields; checked 2026-10-27)
