---
title: Cost budgets
description: Cap model spend per user, team, ring or the whole org at the gateway, warn before the cap, and see spend with halo budget status.
---

`halo-proxy` reads token usage from every model response, prices it, and checks the caller's budgets before each model call. `halo-server` holds the counters, so the limits hold across all proxy replicas. The design and its trade-offs are in [ADR-0017](/halos/adr/0017-gateway-cost-budgets/).

## 1. Price the models

Budgets in USD need a price for every provider model your routes use. Key the price by the provider model id: the `model` of a route target, not the alias.

```yaml
# gateway.yaml
pricing:
  claude-sonnet-4-5-20250929:
    inputPerMTok: 3
    outputPerMTok: 15
    cacheReadPerMTok: 0.30
    cacheWritePerMTok: 3.75
  gpt-5-codex:
    inputPerMTok: 1.25
    outputPerMTok: 10
    cacheReadPerMTok: 0.125
```

Prices are USD per million tokens. Output includes reasoning and thinking tokens. A cache price you leave out costs the same as input, so budgets over-count rather than under-count. `halo validate` warns about every routed model without a price. Its tokens still count toward `limitTokens`, but they cost $0.

## 2. Define budgets

```yaml
# gateway.yaml
budgets:
  - name: dev-daily              # every developer: $25 a day, hard stop
    scope: user
    window: day
    limitUSD: 25
    action: enforce
    alertAt: [0.5, 0.8]

  - name: contractors-weekly     # only callers in the contractors group
    scope: user
    groups: [contractors]
    window: week
    limitUSD: 40
    action: enforce

  - name: team-monthly           # one shared counter per listed group
    scope: group
    groups: [platform, ml-research]
    window: month
    limitUSD: 5000               # warn only: header + metric, never blocks

  - name: canary-tokens          # the canary ring, last 24 hours
    scope: ring
    rings: [ring1-canary]
    window: rolling
    period: 24h
    limitTokens: 200000000

  - name: org-monthly
    scope: org
    window: month
    limitUSD: 60000
    alertAt: [0.8, 0.95]
```

| Field | Meaning |
|---|---|
| `scope` | Which counter a request is charged to. `user`: one per verified subject. `group`: one per group in `groups` that the caller belongs to (required). `ring`: one per ring. `org`: one shared counter. |
| `groups`, `rings` | Filters. Only callers in one of these groups or rings are charged. For `scope: group`, `groups` also names the counters. |
| `window` | `day`, `week` (from Monday) or `month`, as calendar windows in UTC, or `rolling` over `period` (1h to 2160h). |
| `limitUSD`, `limitTokens` | Set one or both. The budget is used up when either is reached. Tokens are input + output + cache reads and writes. |
| `action` | `warn` (default) passes the request and reports it. `enforce` refuses model calls with HTTP 429 until the reset. |
| `alertAt` | Soft thresholds as fractions of the limit (default `[0.8]`). |

A request is charged to every budget that applies to the caller. Anonymous callers (identity mode `none` or `allowAnonymous`) have no `user` or `group` counters. The caller, their groups and their ring come only from the verified identity, never from request headers.

Run `halo validate`, then compile and roll out the snapshot as usual.

## 3. Wire the proxy to halo-server

Budgets use the gateway token the posture gate and kill switch already use (`halo-server --gateway-token-file`).

```yaml
# halo-proxy config
budgets:
  url: https://halo.internal.example.com/api/v1/gateway/budget
  tokenFile: /run/secrets/halo-gateway-token
  cacheTTL: 30s        # how long a caller's verdict is reused
  grace: 15m           # last verdict kept while halo-server is unreachable
  flushInterval: 5s    # how often usage is reported
  failMode: open       # or closed
  serverStateInputTokens: 200000    # input charged for a cut Responses call with previous_response_id/conversation/prompt id
  maxEstimatedOutputTokens: 128000  # output estimate cap when the request sets no max tokens
```

If budgets are in policy but `budgets.url` is not set, the proxy logs a warning once and does not meter or enforce them. `halo-kong` and `engine: external` do not apply budgets, and `halo validate` says so.

**Fail mode.** When `halo-server` cannot be reached, the last verdict for a caller serves for `grace`. After that the verdict is unknown and counted as `outcome="unknown"`:

- `open` (default): the request passes. An outage of the control plane never takes developers offline.
- `closed`: callers under at least one `enforce` budget get 503 with `Retry-After: 30`. Callers under only `warn` budgets always pass.

## What developers see

An exhausted `enforce` budget answers in the CLI's own error format, with `Retry-After` set to the window reset:

| CLI wire | Status | Body |
|---|---|---|
| Anthropic Messages (Claude Code) | 429 | `{"type":"error","error":{"type":"rate_limit_error","message":"halos: model budget \"dev-daily\" (user, day) is used up: $25.08 of $25.00. It resets at 2026-10-22T00:00:00Z. …"}}` |
| OpenAI Responses (Codex) | 429 | `{"error":{"type":"insufficient_quota","code":"insufficient_quota","message":"…"}}`. Codex shows it instead of retrying |
| Gemini (Gemini CLI) | 429 | `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"…"}}` |
| Bedrock invoke | 429 | `{"message":"…"}` with `x-amzn-ErrorType: ThrottlingException` |

A used-up `warn` budget, or one past an `alertAt` threshold, lets the request through and adds a response header:

```
X-Halo-Budget: dev-daily; scope=user; used=83%; state=alert; reset=2026-10-22T00:00:00Z
```

Token counting (`count_tokens`) is free: it is never charged or refused.

## See spend

```sh
export HALO_SERVER=https://halo.internal.example.com HALO_SESSION=<admin halo_session cookie>
halo budget status
halo budget status --budget dev-daily --key user:alice@acme.com
halo budget status --output json
```

```
BUDGET                   KEY                                WINDOW       ACTION   SPENT                  LIMIT                    USED  RESETS
dev-daily                user:alice@acme.com                day          enforce  $26.50                 $25.00                   106%  2026-10-22T00:00:00Z
team-monthly             group:ml-research                  month        warn     $3120.44               $5000.00                  62%  2026-11-01T00:00:00Z
org-monthly              org                                month        warn     $41210.97              $60000.00                 69%  2026-11-01T00:00:00Z
```

The same data is at `GET /api/v1/budgets` (admin; `?budget=` and `?key=` filter). It lists every counter with spend in its current window, plus the org and group counters at zero.

## How accurate it is

- **Metering.** Usage comes from the provider's own usage object in each response: SSE events for streams, event-stream frames for Bedrock, the end of the body otherwise. If the upstream compresses the response anyway, gzip and deflate are decompressed for the usage scan only; the client still gets the upstream's bytes.
- **Estimates.** A successful model call is never free. When a response ends before its final usage is read (the client hangs up, for example after OpenAI's `response.output_text.done` and before `response.completed`; the upstream cuts the stream; there is no usage object; or the encoding is one the proxy cannot decode, such as `br`), it is charged a pessimistic estimate and counted in `halo_proxy_budget_responses_total{outcome="estimated"}`:
  - **Input**: as reported so far (Anthropic's `message_start`), else request bytes / 3. An OpenAI Responses request that names server-side state (`previous_response_id`, `conversation`, a stored `prompt` id) carries context the request bytes do not show, so it is charged at least `budgets.serverStateInputTokens` (default 200000, a full long-context window).
  - **Output**: the larger of the output reported so far and the generated text in the stream's delta events / 4 (text, thinking and tool arguments, without SSE framing or JSON escaping; at least one token per delta event). A non-streamed or undecodable body uses response bytes / 4. Capped at the request's `max_tokens` (`max_output_tokens`, `maxOutputTokens`), else `budgets.maxEstimatedOutputTokens` (default 128000).
  - Never zero. A rising `estimated` count is either clients cancelling often or a wire change worth a look.
- **Under an `enforce` budget.** The check before a call sees what has been charged so far; a call is charged when it ends. One call can therefore overshoot the limit by its own cost, estimate included (with server-side state, up to `serverStateInputTokens` of input), and the next call is refused. Lower `serverStateInputTokens` to your models' real context window if the default overcharges.
- **Overshoot.** Enforcement is eventually consistent. A replica adds its own usage to its cached verdict at once, so a caller on one replica is stopped at the next request after crossing the limit. Usage served by other replicas arrives within `flushInterval` and is seen after `cacheTTL`. Shared counters (group, ring, org) see other callers' usage only on refresh. The request that crosses a limit always completes, because it is charged when it finishes.
- **Rolling windows** move in steps of period/48 (30 minutes for 24h).
- **Durability.** `halo-server` writes counters to `<data-dir>/budgets.json` at most every 10 s and on shutdown. Back it up with the rest of the data dir. A crash loses at most 10 s of usage, and a SIGKILLed proxy loses its unreported usage. Both under-count.

## Metrics and alerts

| Metric | Labels |
|---|---|
| `halo_proxy_budget_checks_total` | `budget`, `outcome` = `ok`, `alert`, `exceeded` (warn), `refused` (enforce), `unknown` |
| `halo_proxy_budget_responses_total` | `outcome` = `metered`, `unpriced`, `estimated` |
| `halo_proxy_budget_spend_usd_total` | |
| `halo_proxy_budget_tokens_total` | `kind` = `input`, `output`, `cache_read`, `cache_write` |
| `halo_proxy_budget_reports_total` | `outcome` = `ok`, `failed` |
| `halo_proxy_budget_dropped_total` | |

The alert rules are in [operations](/halos/guides/operations/#alerts).
