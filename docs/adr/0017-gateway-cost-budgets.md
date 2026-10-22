---
title: "ADR-0017: Cost budgets and quotas enforced at the gateway"
description: halo-proxy meters token usage from model responses and enforces per-user, group, ring and org budgets, with halo-server holding the authoritative counters.
status: accepted
date: 2026-10-21
---

# ADR-0017: Cost budgets and quotas enforced at the gateway

> **Amended 2026-10-21.** Charging only the usage that was read let a client hang up before the final usage event (OpenAI Responses reports usage only in `response.completed`) and pay nothing. A metered 2xx response whose final usage was not read (client hang-up, upstream cut, no usage object, undecodable encoding) is now charged a pessimistic estimate, counted as `outcome="estimated"`. An upstream that compresses anyway is metered: gzip and deflate are decompressed for the scan only, other encodings are estimated. GenAI telemetry reads usage from the same `gateway.UsageTap`. See [cost budgets](/halos/guides/cost-budgets/#how-accurate-it-is).
>
> **Amended again 2026-10-21 (second security review).** The estimate charged output as wire bytes / 3, about 10x the real output on SSE and uncapped without `max_tokens`. Output is now the generated text in the stream's delta events / 4 (at least one token per delta event; response bytes / 4 for a non-streamed or undecodable body), capped at the request's max output tokens, else `budgets.maxEstimatedOutputTokens` (default 128000). Input of an OpenAI Responses request that names server-side state (`previous_response_id`, `conversation`, a stored `prompt` id) was request bytes / 3, a fraction of the context the provider bills; it is now at least `budgets.serverStateInputTokens` (default 200000). Under an `enforce` budget, the pre-call check sees only what was charged before, so one call can overshoot by its own (estimated) cost; the next is refused. A 2xx call is still never free. Tests: `TestEstimateUsage`, `TestUsageTapOutputText`, `TestServerStateInput`, `TestBudgetChargesAbortedStream`.

- Status: accepted (extends ADR-0011)
- Date: 2026-10-21

## Context and problem statement

Spend is visible only after the fact. `Stopping.maxSpendUSD` stops an experiment, `halo-shadow` caps its own mirror spend, and `halo.cost.usd_per_session` is a metric. Nothing stops one developer, team or ring from spending without limit, and nothing warns before the monthly bill does. Every model call already crosses `halo-proxy`, which knows the verified caller, the ring and the provider model, so the gateway can meter and cap spend.

`halo-proxy` runs as N stateless replicas (HPA 2 to 10). A counter kept in one replica sees a fraction of a caller's traffic.

## Decision drivers

- Identity only from the verified principal (invariant 4). No client header picks the counter.
- Correct across replicas, with a stated bound on overshoot.
- No new infrastructure: no Redis, no database.
- Streaming stays streaming. Usage is read as the response flows, never by buffering it.
- Fail-open versus fail-closed is the operator's explicit choice.
- A refusal is a protocol-correct error the CLI shows, with a time to retry.
- Additive to `halos.dev/v1`: a policy without budgets compiles to the same snapshot bytes.

## Considered options

1. **Per-replica counters.** No coordination. With N replicas a caller can spend N times the limit, and the limit changes with the HPA. Rejected.
2. **Shared store (Redis) with atomic increments per request.** Exact, but a new stateful dependency on the request path, with its own HA and secrets. Rejected for now. The ledger interface leaves room for it.
3. **Authoritative counters in `halo-server`, verdicts cached in the proxy (chosen).** This is the ADR-0011 posture pattern: the gateway asks `halo-server` with the gateway token and caches the verdict. `halo-server` is already a single replica that owns local state (operations guide), so its counters have one writer and need no locking protocol.

## Decision outcome

Chosen: **option 3**.

**Policy** (`Gateway` document, optional, `halos.dev/v1`):

- `pricing`: USD per million tokens keyed by provider model id (`inputPerMTok`, `outputPerMTok`, optional `cacheReadPerMTok`/`cacheWritePerMTok`, which default to the input price). No pricing config existed before. `halo-shadow`'s `--price-in`/`--price-out` flags are per-process estimates, not policy.
- `budgets[]`: `name`, `scope` (`user` per verified subject, `group` per listed group, `ring` per ring, `org` one counter), optional `groups`/`rings` filters, `window` (`day`, `week` from Monday, `month`, all UTC calendar windows; or `rolling` with `period`), `limitUSD` and/or `limitTokens`, `action` (`warn` default, or `enforce`), `alertAt` (default `[0.8]`).
- `halo validate` errors on malformed budgets and warns when a budget has a USD limit and a routed model has no price (its tokens count, its cost is $0), and when `engine` is `kong` or `external` (they do not apply budgets).

**Metering** (`halo-proxy`): for model calls of callers with at least one applicable budget, the response body is wrapped in a tap (`gateway.UsageTap`). The tap scans the stream without changing it: SSE line by line (Anthropic `message_start`/`message_delta`, OpenAI `response.completed`, Gemini chunks), AWS event stream frames (Bedrock invoke and converse streams), or the last 64 KiB of a JSON body. Counts are the field-wise maximum of the cumulative usage objects, normalised so input excludes cached tokens on every wire. Memory per response is bounded at about 1 MiB. Usage is charged when the body ends, including a client disconnect mid-stream (by estimate since the amendment above). `Accept-Encoding` is removed on metered calls so usage normally arrives uncompressed. `count_tokens` is never charged or refused.

**Counters** (`halo-server`):

- `POST /api/v1/gateway/budget/usage` takes a replica's usage records `{subject, groups, ring, usd, tokens, at}` aggregated per caller per minute, in batches with an id. A batch id seen in the last hour is acknowledged and not counted again, so a retry after a lost response is safe.
- `POST /api/v1/gateway/budget/check` returns every counter a principal is charged to, with spend, limits, action, alert thresholds and `resetAt`.
- The server maps records to counters with its own policy. Calendar windows keep one bucket. Rolling windows keep 48 buckets per period, so usage leaves the window in steps of period/48, and an exhausted rolling budget's `resetAt` is when enough old buckets expire.
- Counters persist to `<data-dir>/budgets.json`, written at most every 10 s while usage arrives, and on shutdown. On the Postgres backend ([ADR-0021](/halos/adr/0021-ha-control-plane-on-postgres/)) they are rows instead (`halo_budget_buckets`, usage added in place in one transaction with the batch id, whose primary key makes a retried batch count once even when two replicas receive it), so every `halo-server` replica reads and charges the same counters: N replicas grant one budget. Nothing is lost on a crash there; a usage report the database cannot take answers 503 and the gateway retries it.
- `GET /api/v1/budgets` (admin) and `halo budget status` show every counter.

**Verdicts** (`halo-proxy`, `budgets.url` + `tokenFile`): each replica caches a principal's verdict for `cacheTTL` (default 30 s) and adds the usage it metered since, including usage not yet reported, so one replica refuses its own heavy caller without waiting for a round trip. Reports go out every `flushInterval` (default 5 s) and on graceful shutdown.

- Exhausted `enforce`: 429 with `Retry-After` at the reset, in the caller's wire format: Anthropic `rate_limit_error`, OpenAI Responses `insufficient_quota` (Codex stops instead of retrying), Gemini `RESOURCE_EXHAUSTED`, Bedrock `{"message"}` with `x-amzn-ErrorType: ThrottlingException`.
- Exhausted `warn`, or past an `alertAt` threshold: the request passes with `X-Halo-Budget: <budget>; scope=…; used=…%; state=exceeded|alert; reset=…`, a `budget …` note on the request log line, and a count in `halo_proxy_budget_checks_total{budget,outcome}`.
- **Fail mode is explicit.** If `halo-server` cannot be reached, the last verdict serves for `grace` (default 15 m). After that the verdict is unknown and counted as `outcome="unknown"`. `failMode: open` (default) passes the request; `failMode: closed` answers 503 with `Retry-After: 30`, but only for callers under an `enforce` budget. A `warn` budget never blocks.
- Budgets in policy without `budgets.url` are neither metered nor enforced, and the proxy logs that once.

### Consequences

- Good: budgets hold across any number of replicas, with no new infrastructure and no buffering of streams.
- Good: the refusal is an error each CLI already knows how to show, with a time to retry.
- Bad: enforcement is eventually consistent. A caller can overshoot by what other replicas serve them in one `cacheTTL` + `flushInterval`, plus the requests in flight when the limit is crossed. A request is charged after it completes, so the request that crosses the limit always finishes. Shared counters (group, ring, org) see other callers' usage only on refresh.
- Bad: up to 10 s of counted usage is lost if `halo-server` crashes (not on a graceful restart), and a replica's unreported usage is lost if it is SIGKILLed. Both under-count.
- Bad: accounting trusts the provider's reported usage, and a response without a recognisable usage object is not charged. It is counted in `halo_proxy_budget_responses_total{outcome="no_usage"}`.
- Bad: `halo-kong` does not meter or enforce budgets. Its Go PDK cannot read a streamed response body without buffering it. `halo validate` warns when `engine: kong`.
- Neutral: calendar windows are UTC. A budget renamed in policy starts a new counter, and a removed budget's counters are pruned.
- Neutral: older `halo-proxy` binaries ignore `budgets` in a snapshot. Upgrade the traffic plane first, as the compatibility page already recommends.
