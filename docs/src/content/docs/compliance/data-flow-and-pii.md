---
title: Data flow and PII inventory
description: Per component, what data Halos receives, which fields are personal data, where they are stored, the retention defaults, the redaction controls, and what leaves your boundary.
---

This is the inventory a privacy review asks for: for each Halos component, what it receives, what in that is personal data, where it lands, how long it stays, what redaction exists, and what leaves your network. It was written from the code. It is not legal advice, and the legal basis, the record of processing and any DPIA are yours.

Companion pages: [compliance control mapping](/halos/compliance/control-mapping/) and [security overview](/halos/compliance/security-overview/).

Halos does not send data to its maintainers. No code path in `cmd/` or `internal/` calls a Halos-operated service; every outbound connection below goes to a host you configure or to the vendor whose product you manage. (Checked by reading the code; there is no test that asserts the absence of a phone-home.)

## Data classes

| Class | Meaning | Examples |
|---|---|---|
| **ID** | Identity of a person | user id (normally the email), IdP groups, SCIM `userName`, display name, emails, SCM login, client IP, hostname and OS user of a laptop |
| **CONTENT** | What the developer and the agent wrote | prompts, completions, source code, tool results, terminal output |
| **USAGE** | Metadata about use | models, tokens, cost, timings, tools called, ring, variant, release |
| **CRED** | Credentials | provider API keys, IdP client secret, device and enrollment tokens, signing keys |
| **CONFIG** | Policy and rendered settings | `halos.yaml`; may name users in `membership.users` and unit owners |

## Where data moves

<img class="diagram dark:sl-hidden" src="/halos/diagrams/trust-zones-light.svg" alt="Z0 internet and vendor hosts (untrusted), Z1 the developer machine with a root-owned area for halod and its config, Z2 the supply chain (policy repo, CI publish job holding the key, OCI registry), and Z3 your infrastructure (halo-proxy or halo-kong, model upstreams and IdP, halo-shadow, halo-server)." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/trust-zones-dark.svg" alt="Z0 internet and vendor hosts (untrusted), Z1 the developer machine with a root-owned area for halod and its config, Z2 the supply chain (policy repo, CI publish job holding the key, OCI registry), and Z3 your infrastructure (halo-proxy or halo-kong, model upstreams and IdP, halo-shadow, halo-server)." width="760" />

| Flow | From | To | Data | Class |
|---|---|---|---|---|
| Model call | coding CLI | `halo-proxy` or `halo-kong` | request and response bodies, bearer JWT | CONTENT, ID, CRED |
| Forwarded call | gateway | model provider | the same body, with the gateway's own credential | CONTENT |
| Mirror | gateway | `halo-shadow` | a sampled copy of the request, experiment and variant | CONTENT |
| Replay | `halo-shadow` | candidate model provider | the mirrored request | CONTENT |
| Gateway telemetry | `halo-proxy` | OTel collector (gateway receiver) | request counts and latency by ring, variant, `halo.unit` pseudonym | USAGE |
| CLI telemetry | coding CLI | OTel collector (CLI receiver) | the CLI's own metrics and log events | USAGE, ID, CONTENT if `logPrompts` is on |
| DLP finding | gateway | `halo-server` | detector, 8-hex hash, location, user, ring, unit | ID, USAGE |
| Status report | `halod` | `halo-server` | hostname, OS user, ring, release digest, harness versions, drift, last error | ID, CONFIG |
| Enrollment | browser, laptop | `halo-server` | OIDC login, enrollment token, device token | ID, CRED |
| Directory | IdP | `halo-server` | SCIM users and groups | ID |
| Directory lookup | gateway | `halo-server` | subject, kill list, posture, budget counts, revocation list | ID, USAGE |
| Audit | `halo-server` | SIEM | every audit entry | ID, USAGE |
| Release | CI | OCI registry | signed release, pointer, AI-BOM, provenance | CONFIG |
| Release pull | `halod` | OCI registry, vendor CDN and npm | release, CLI binaries | none from the user, but the machine's IP is visible to those hosts |
| Ledger import | `halo` | vendor audit APIs, ClickHouse, then `halo-server` | session records | ID, USAGE |
| ROI ingest | `halo` | GitHub GraphQL or a file, then ClickHouse | PR outcomes | ID, USAGE |

## Components

"Stored" names the file or table; the paths are from [Operations: backup and restore](/halos/guides/operations/#backup-and-restore). Retention is in [the next section](#retention-defaults).

| Component | Receives | Personal data in it | Stored | Redaction and minimisation |
|---|---|---|---|---|
| **`halo` CLI** | Policy directory, flags, environment credentials; talks to `halo-server`, ClickHouse, GitHub, vendor consoles and a model, depending on the command | CONFIG on disk (user ids in `membership.users`); ROI and ledger commands handle ID | Policy files in your git repo; `halo` keeps no store of its own except the signer state file (`pointers.json`: ring, seq, digest) | Credentials only from files or environment variables, never flags or policy; scrubbed from errors (`internal/vendoradmin`, `internal/roi`) |
| **`halod`** | A signed release; asks the registry and vendor hosts | Hostname and OS user, in its status report | Root-owned config, state and managed settings on the machine; the device token (mode 0600) | Reports no prompts or code. `internal/server/store.go` (`Report`) is the whole payload; the drift entries and `lastError` can contain file paths |
| **`halo-proxy`** | Every model call: body, headers, JWT | CONTENT in flight; ID (verified subject, groups); client IP | Nothing of the body. A request log line: method, path, status, bytes, duration, ring, remote address, experiment, variant, upstream, model, DLP note. Counters for budgets | The log never carries bodies, headers or query strings (`cmd/halo-proxy/proxy.go`, comment above `attrs`); optional GenAI spans are off by default and content-free; DLP (below) |
| **`halo-kong`** | The same, inside Kong | Same | Nothing of its own; Kong's own access logs and any Kong logging plugin are outside Halos | Same detection code (`internal/gateway`); responses are not DLP-scanned in Kong |
| **`halo-server`** | OIDC logins, enrollment, device reports, SCIM, gateway lookups, DLP findings, ledger batches, cloud-agent webhooks, kill/freeze/revoke actions | ID throughout: user ids as audit actors and targets, SCIM users (name, display name, emails, groups), devices (user, groups, hostname), access requests, client IPs for failed-auth limits | `--data-dir` JSONL files, or Postgres ([ADR-0021](/halos/adr/0021-ha-control-plane-on-postgres/)): audit chain, devices, requests, revocations, SCIM journal, ledger records (as `session.record` audit entries, cloud-agent tasks among them), webhook delivery ids with a TTL, reports | Ledger records re-validated server-side and the batch refused on any prose or path; tokens stored only as SHA-256; session cookie is signed, not encrypted (it carries the subject and groups) |
| **`halo-shadow`** | Mirror jobs from the gateway | CONTENT: prompts, code and responses of sampled sessions; user identity only as the experiment unit | `pairs.jsonl` (mode 0600) or Postgres `halo_shadow_pairs`; scores to ClickHouse (`halo_shadow_pairs`, hashes and scores only) | AES-256-GCM at rest if `-pair-key-file` is set (off by default); upstreams resolved from policy; client credentials never forwarded; budget; retention |
| **OTel collector and ClickHouse** | OTLP metrics and log events from CLIs (4317, 4318), from `halo-proxy` (4319), optionally from `halo eval online` (4320) | `unit_id` (the user identifier the CLI exports for CLI rows; an HMAC pseudonym for gateway rows), `session_id`, model, cost; CONTENT only if you turn on `logPrompts` | Raw `otel_*` tables written by the exporter; normalized `halo.halo_metrics`, `halo_sessions`, `halo_shadow_pairs`, `halo_session_ledger`, `halo_eval_results`, `halo_delivery_prs` ([schema](https://github.com/dshakes/halos/blob/main/deploy/observability/clickhouse/schema.sql)) | `halo_metrics` keeps named fields only; prompts, tool input and error text are never kept there. The collector does not strip attributes from raw log records, so the raw tables hold whatever the CLI exported |
| **Postgres** | Everything `halo-server` persists in HA mode | As `halo-server` | `halo_journal`, `halo_kv`, `halo_audit`, `halo_audit_head`, `halo_reports`, `halo_report_history`, `halo_docs`, `halo_leases`, `halo_shadow_pairs`, `halo_shadow_budget`, `halo_shadow_reservations`, `halo_budget_buckets`, `halo_budget_batches`, `halo_request_pending`, `halo_revocations` (`internal/pgstore/migrations/`) | A non-loopback host requires `sslmode=verify-full` unless `--database-insecure-tls` is set (`internal/pgstore/pgstore.go`, `CheckTLS`). No column-level encryption: use the database's |
| **OCI registry** | Signed releases, ring pointers, AI-BOM and provenance referrers | CONFIG only; may name users if `membership.users` does; the rendered config carries no literal secrets (the guardrails refuse them) | The registry | Releases are immutable and kept; the guardrails reject literal secrets in MCP headers and env |
| **Eval runner** (`halo eval run`) | A suite of tasks, a Docker daemon | Whatever your tasks contain; CONTENT | Trial results as JSON, optionally `halo_eval_results` in ClickHouse | Trials run with `--network none` by default (`internal/eval/docker.go`); credentials only through `--pass-env`. `halo eval harvest` turns shadow pairs into cases through a mandatory redaction pass with no off switch (`internal/eval/redact.go`) |
| **Ledger ingest** (`halo sessions import`) | Vendor audit APIs (Anthropic Compliance, GitHub audit log), ClickHouse, your JSONL | ID: vendor user, directory user, delegated agent chain, hashed repos and files | Audit chain in `halo-server`; optional ClickHouse copy | Redaction below |
| **ROI ingest** (`halo roi ingest`) | GitHub GraphQL (one fixed read-only query), or a CSV or JSONL export | ID: SCM login (lowercased), optionally the Halos subject | ClickHouse `halo_delivery_prs` or a JSONL file | No titles, bodies or diffs are stored ([ADR-0027](/halos/adr/0027-randomized-roi/)) |
| **DLP** (inside the gateways) | Each request body and each tool result | CONTENT, scanned in memory | Findings only, as audit entries and counters | Below |
| **MCP server** (`halo mcp serve`) | Tool calls from your agent | Whatever its read tools return, including the session ledger and audit tail when `--server` and a session are set | Nothing | Read tools by default; writes need `--allow-writes`. Results go to the calling agent's model provider |

## Redaction controls

| Control | What it does | Default | Reference |
|---|---|---|---|
| **Gateway DLP: secrets** | Detects 12 secret formats in requests; `monitor` counts and audits, `redact` replaces each with `[REDACTED:<detector>:<hash8>]`, `block` answers 400 | `monitor` when configured; `maxScanBytes` 4 MiB | [DLP guide](/halos/guides/dlp/), `internal/policy/dlp.go` |
| **Gateway DLP: findings** | The secret is never stored; entries carry the detector, the first 8 hex of its SHA-256 and the JSON path | always | `internal/gateway/dlp_report.go`, [ADR-0033](/halos/adr/0033-gateway-dlp-and-injection-defense/) |
| **Gateway DLP: responses** | Streamed responses are scanned in `halo-proxy` for secrets the model repeats; monitor only, never delays or cuts the stream | on (`scanResponses`) | [DLP guide](/halos/guides/dlp/#responses) |
| **Ledger redaction** | Every stored string must be a short identifier (no whitespace, quotes or control characters, at most 256 bytes) so prose cannot be stored; repositories and file paths are dropped (`--paths drop`) or stored as `h:` plus an HMAC-SHA256 under your salt (`--paths hash`); the server re-validates and refuses the batch | `--paths drop` | `internal/ledger/ledger.go` (`Normalize`, `Validate`), [session ledger](/halos/guides/session-ledger/#redaction) |
| **Pseudonymous units** | Gateway telemetry identifies a user only as `halo.unit`, an HMAC of the verified subject under a salt | on | `internal/telemetry/gwmetrics/gwmetrics.go`, [evidence plane](/halos/concepts/evidence-plane/) |
| **Telemetry content** | Prompts are exported by the CLIs only when `telemetry.logPrompts` is true; the guardrails warn when it is set on the default (GA) ring | off | `internal/policy/guardrails.go`, [threat model](/halos/reference/threat-model/#residual-risk-and-non-goals) |
| **Shadow encryption** | AES-256-GCM over each pair, `id` and `time` left in clear for pruning | off (needs `-pair-key-file`) | `internal/shadow/shadow.go` |
| **Eval harvest redaction** | Built-in rules, versioned in each case's provenance, applied before anything is written | always | `internal/eval/redact.go`, [ADR-0020](/halos/adr/0020-harvest-shadow-sessions-into-replay-evals/) |
| **Secrets in logs** | Tokens, headers and sink URLs are never logged or returned | always | `TestSecretsNeverLogged` in `cmd/halo-proxy/security_test.go` and `internal/server/security_test.go` |

## Retention defaults

"Unbounded by default" means Halos never deletes the data; you must configure the named control or delete it yourself.

| Store | Default | Control |
|---|---|---|
| Shadow pairs (file or Postgres) | 30 days (`720h`) | `halo-shadow -retention`; Helm `retention`; `0` keeps forever (`cmd/halo-shadow/main.go`) |
| Audit log (`audit.jsonl`, or `halo_audit`) | **Unbounded by default.** Rotation is off, and rotation only splits segments; it never deletes them | `--audit-config` `rotation`, then archive or delete segments yourself, and keep your SIEM copy ([SIEM export](/halos/guides/siem-export/)). Deleting a segment breaks `halo audit verify` from that point unless you keep the chain head |
| Session ledger records in `halo-server` | Same as the audit log (they are audit entries) | as above |
| Other `--data-dir` files: devices, access requests, session revocations, controller state, SCIM journal | **Unbounded**: append-only JSONL, never compacted; Postgres `halo_journal` likewise ([ADR-0021](/halos/adr/0021-ha-control-plane-on-postgres/)) | SCIM `DELETE` removes the directory record and revokes access, but no API erases a user's audit entries or device rows: handle erasure requests by your own procedure (and mind that editing the audit log breaks its chain) |
| Credential revocations | A row is dropped an hour and a minute after its epoch, when nothing it matches can still be valid | none ([security model](/halos/concepts/security-model/#credential-revocation)) |
| Fleet reports | Latest per reporter, plus the last 50 (`MaxHistory`) | none needed |
| Budget counters (Postgres) | Buckets older than 95 days are pruned (`budget.MaxRetention`) | none |
| Sessions and tokens | Console session 12 hours; enrollment token 15 minutes, single use; device token 90 days (`DefaultDeviceTTL`); workload credential 15 minutes by default, 1 hour at most | policy and server flags |
| ClickHouse `halo_metrics`, `halo_sessions` | 180 days | `TTL` in the schema |
| ClickHouse `halo_shadow_pairs` (scores and hashes) | 30 days | `TTL` in the schema |
| ClickHouse `halo_session_ledger` | 400 days | `TTL` in the schema |
| ClickHouse raw `otel_*` tables | 720 hours, set by the collector's exporter (`ttl: 720h`, `internal/telemetry/collector.go`) | regenerate the collector config; applies to tables the exporter creates |
| ClickHouse `halo_eval_results`, `halo_delivery_prs` | **Unbounded** (no `TTL`) | add a `TTL` clause or delete rows; `halo_delivery_prs` holds SCM logins |
| halo-proxy and halo-server logs | Whatever your log pipeline keeps | Kubernetes and log-shipper settings |
| OCI registry | **Unbounded**; every release is kept | registry garbage-collection policy |

## What leaves your boundary

Only to hosts you configured or products you chose to manage. Nothing here is sent unless the matching feature is on.

| Destination | What is sent | When |
|---|---|---|
| **Model providers** (Anthropic, OpenAI, AWS Bedrock, Google Vertex and others you route to) | Prompts, code, tool results and completions, with the gateway's credential | Every model call through the gateway; and a sampled copy through `halo-shadow` to the candidate route. This is the one flow that cannot be turned off without turning the product off |
| **A model for `halo eval online` and `halo copilot`** | Shadow pairs (judge); your policy files and intent (copilot draft), within the stated token and cost ceilings | Only when you run those commands; `halo copilot --offline` uses templates and sends nothing. The MCP copilot tools call no provider |
| **Your calling agent's model provider** | Anything an MCP tool returns | When an agent uses `halo mcp serve` tools |
| **GitHub** | A review branch and PR with policy diffs, the verdict report and, if enabled, the ROI section (controller, `halo exp promote`, MCP `propose_*`); an org Copilot content-exclusion list (`halo admin apply`) | Only to the repository and org you point at; a human merges |
| **GitHub, Anthropic, Google admin and audit APIs** | Read: audit-log events, compliance activities, console settings. Write: Gemini Code Assist logging and channel, Copilot org content exclusion | `halo sessions import`, `halo admin plan`, `halo admin apply` ([vendor admin sync](/halos/guides/vendor-admin-sync/)). Tokens are sent only over https (http only to loopback) |
| **Vendor CDNs and npm** | The machine's IP and User-Agent, when `halod` downloads a CLI | On a version change |
| **Public Sigstore (Fulcio, Rekor)** | The release digest and the signer's OIDC identity, in a **public** transparency log | Only with `--cosign-keyless` on the signing commands (`halo release publish`, `promote`, `refresh`, `halo rollback`), and for the Halos project's own releases. Skip keyless if the signer's identity must not be public |
| **Your SIEM** | Every audit entry, including user ids and, in OCSF form, client IPs | When a sink is configured |

## Using this for a DPIA

- The CONTENT class is in your gateway's memory, the model providers' hands and, if you enable them, shadow pairs and raw OTel rows. Halos keeps no copy of bodies otherwise. Confirm each provider's retention and training terms yourself.
- The ID class is concentrated in `halo-server`: audit actors and targets, SCIM records, devices, ledger records. Minimise at the source (the IdP) and decide the retention of the audit log, which is unbounded by default.
- The ledger and the ROI report can be read as monitoring of individual developers. The ledger is per user by design; the ROI report compares arms. Decide who holds the `auditor` and `admin` roles, and whether works-council or employee-representative consultation applies in your jurisdiction.
- UNVERIFIED: the retention and TTL values above are the defaults in this repository. A deployment that overrides them, or runs a ClickHouse schema older than the one in the repo, differs.
