---
title: Metrics
description: Normalized halo.* metrics and how each maps to Claude Code, Codex and Gemini CLI telemetry.
---

The collector (generate its config with `halo telemetry collector-config`) maps harness-native signals onto `halo.*` names. Experiments may only reference names in this registry; `halo validate` rejects others. Source of truth: `internal/policy/metrics.go`.

| `halo.*` metric | Unit | Online source | Per-unit sample (one per user or hashed session) |
|---|---|---|---|
| `halo.task.success` | ratio | none: offline `halo eval` only | One eval trial (pass = 1) |
| `halo.cost.usd_per_session` | usd | CLI | Unit's total `halo.cost.usd` / its distinct sessions |
| `halo.tokens.per_session` | tokens | CLI | Unit's input+output `halo.tokens` / its distinct sessions |
| `halo.api.error_rate` | ratio | gateway, else CLI | Failed / total model API requests |
| `halo.edit.accept_rate` | ratio | CLI | Accepted / total edit decisions |
| `halo.latency.p50_ms` | ms | gateway, else CLI | Median over the unit's successful requests (gateway: interpolated from histogram buckets) |
| `halo.latency.p95_ms` | ms | gateway, else CLI | 95th percentile, same basis |
| `halo.session.duration_s` | s | none yet | Not derived |
| `halo.tool.error_rate` | ratio | CLI | Failed / total tool calls |
| `halo.eval.judge.score` | ratio | eval (`halo eval online` on `halo-shadow` pairs) | Mean judge score of one shadow pair's response for that arm (unit = pair) |

"Gateway" is `halo-proxy`'s per-request OTLP export (`halo.gateway.requests`, `halo.gateway.latency_ms`). It assigns ring and variant itself, so it is the only online source for `traffic`-axis experiments; when an experiment has gateway data it is preferred over CLI events, and the two are never mixed in one analysis. The gateway is also the only **trusted** source: the collector stamps `halo.source=gateway` only on its authenticated receiver (`:4319`) and `halo.source=cli` on everything from developer machines, which also cannot carry `halo.gateway.*` at all. The controller auto-kills only on `gateway` evidence. The unit for gateway data is `halo.unit`, `HMAC-SHA256(salt, verified subject)` truncated; anonymous requests are counted but are not units. `halo.gateway.*` metrics are not exposed to Prometheus through the collector (per-unit labels would explode cardinality); scrape `halo-proxy`'s own `/metrics` instead. How each is computed: [evidence plane](/halos/concepts/evidence-plane/#derived-per-unit-metrics).

## Harness mapping

How each harness's native signal feeds the registry metrics:

| `halo.*` metric | Claude Code | Codex | Gemini CLI |
|---|---|---|---|
| `halo.task.success` | eval trial verdict | eval trial verdict | eval trial verdict |
| `halo.cost.usd_per_session` | `claude_code.cost.usage` | `codex.api_request` events (tokens x price) | `gemini_cli.api_response` (tokens x price) |
| `halo.tokens.per_session` | `claude_code.token.usage` | `codex.api_request` events | `gemini_cli.token.usage` (`gen_ai.client.token.usage`) |
| `halo.api.error_rate` | `claude_code.api_error` / (`api_request` + `api_error`) events | `codex.api_request` (status, error) | `gemini_cli.api_error` / (`api_response` + `api_error`) |
| `halo.edit.accept_rate` | `claude_code.code_edit_tool.decision` | `codex.tool_decision` events | `gemini_cli.tool_call` (decision) |
| `halo.latency.p50_ms`, `p95_ms` | `claude_code.api_request` `duration_ms` | `codex.api_request` `duration_ms` (2xx) | `gemini_cli.api_response` `duration_ms` |
| `halo.session.duration_s` | `claude_code.active_time.total` | `codex.session` events | `gemini_cli.session` events |
| `halo.tool.error_rate` | `claude_code.tool_result` (success) | `codex.tool_result` (success) | `gemini_cli.tool_call` (success) |

## Resource attributes

Stamped on all telemetry so experiments can slice by cohort:

| Attribute | Meaning |
|---|---|
| `halo.ring` | Ring name |
| `halo.release` | Release digest |
| `halo.harness` | Adapter name |
| `halo.experiment` | Experiment name (when the user is in one) |
| `halo.variant` | Variant name within that experiment |
| `halo.source` | **Data point** attribute set by the collector, never by the client: `gateway` or `cli`. A client-supplied value is overwritten. `halo exp analyze --output json` reports it as `source` |

For Claude Code these ride on `OTEL_RESOURCE_ATTRIBUTES`. Codex uses its `[otel]` config; Gemini CLI its telemetry settings.

## Controller metrics

`halo-server --controller` serves Prometheus text on `--metrics-listen` (empty disables). **The listener is unauthenticated**: bind it to an internal address and restrict it with a NetworkPolicy.

| Metric | Type | Meaning |
|---|---|---|
| `halo_controller_ticks_total` | counter | Evaluation ticks started |
| `halo_controller_verdicts_total{verdict}` | counter | Verdicts reached, by `continue`, `expired`, `promote`, `rollback` |
| `halo_controller_errors_total` | counter | Failed evaluations, PRs, kills, notifications or state writes |

A rising `halo_controller_errors_total` with flat verdicts usually means ClickHouse or the policy clone is unreachable; the loop retries at 15s, 30s, and so on.

## Metrics listeners

These processes expose Prometheus text on a **separate, unauthenticated** address. None of them share a public listener.

| Process | Flag | Default | Metrics |
|---|---|---|---|
| `halo-proxy` | `--admin-listen` (also `/healthz`) | `127.0.0.1:9090` | `halo_proxy_requests_total{ring,variant,status}`, `halo_proxy_upstream_ttfb_seconds`, `halo_proxy_request_duration_seconds`, `halo_proxy_auth_failures_total`, `halo_proxy_shadow_dropped_total`, `halo_proxy_shadow_failed_total` |
| `halo-shadow` | `-metrics-listen` (env `HALO_SHADOW_METRICS_LISTEN`) | off | `halo_shadow_mirrored_total`, `halo_shadow_dropped_total`, `halo_shadow_errors_total`, `halo_shadow_spend_usd`, `halo_shadow_budget_usd` |
| `halo-server` (controller) | `--metrics-listen` | off | `halo_controller_*` above |

## Verification status

Claude Code metric names follow the vendor's documented set. The CLI log-event mappings (`api_request`, `tool_result` and their Codex and Gemini equivalents) and the Codex and Gemini metric names are checked against synthetic telemetry shaped like the vendors' documentation (`make obs-e2e`), and are **UNVERIFIED** against real CLI telemetry in a real collector. `make uat-clis` does confirm that the real CLIs export the `halo.ring`, `halo.release` and `halo.harness` resource attributes.
