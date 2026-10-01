-- Halos normalised evidence tables (ClickHouse).
--
-- The OTel collector (internal/telemetry) writes raw OTLP into otel_* tables
-- via clickhouseexporter (create_schema: true). Materialised views below
-- project those into halo_metrics, the narrow table that internal/promote and
-- the Grafana dashboards query.
--
-- Verified against clickhouseexporter v0.161.0 (`make obs-e2e` applies this file
-- after the collector creates the tables and queries the result): the views
-- read otel_metrics_sum / _gauge / _histogram (MetricName, Attributes,
-- ResourceAttributes, TimeUnix, Value|Sum|Count|BucketCounts|ExplicitBounds)
-- and otel_logs (LogAttributes, Body). Histograms land Sum as value plus Count and
-- their buckets, so means (sum/count) and quantiles are computable. The
-- collector's cumulativetodelta processor makes every sum/histogram a delta
-- before it lands, so per-unit sums never double count.
--
-- Cohort columns read the resource attribute first (CLIs: OTEL_RESOURCE_ATTRIBUTES)
-- and fall back to the data point attribute (halo-proxy stamps halo.ring /
-- halo.variant / ... per request, and halo.unit = salted hash of the verified
-- subject). attrs['halo.source'] is stamped by the collector per receiver
-- (gateway | cli, never client-supplied); internal/promote only counts
-- halo.gateway.* rows with halo.source = 'gateway'.
-- Apply ORDER: the otel_* tables must exist (collector startup), then this file.

CREATE DATABASE IF NOT EXISTS halo;

-- One row per metric data point. unit_id is the assignment unit (user).
CREATE TABLE IF NOT EXISTS halo.halo_metrics
(
    ts         DateTime64(3),
    metric     LowCardinality(String),           -- halo.* name, e.g. halo.cost.usd
    value      Float64,
    unit_id    String,
    session_id String,
    ring       LowCardinality(String),
    release    String,
    harness    LowCardinality(String),
    model      LowCardinality(String),
    experiment LowCardinality(String),
    variant    LowCardinality(String),
    attrs      Map(String, String),
    count      Float64 DEFAULT 1,               -- observations folded into value (histogram Count)
    bounds     Array(Float64),                  -- histogram ExplicitBounds, else empty
    buckets    Array(UInt64)                    -- histogram BucketCounts, else empty
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (experiment, metric, variant, unit_id, ts)
TTL toDateTime(ts) + INTERVAL 180 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS halo.halo_metrics_from_sum TO halo.halo_metrics AS
SELECT
    TimeUnix                                         AS ts,
    MetricName                                       AS metric,
    Value                                            AS value,
    coalesce(nullif(Attributes['user.id'], ''), nullif(Attributes['halo.unit'], ''), Attributes['installation.id']) AS unit_id,
    Attributes['session.id']                         AS session_id,
    coalesce(nullif(ResourceAttributes['halo.ring'], ''), Attributes['halo.ring'])             AS ring,
    coalesce(nullif(ResourceAttributes['halo.release'], ''), Attributes['halo.release'])       AS release,
    coalesce(nullif(ResourceAttributes['halo.harness'], ''), Attributes['halo.harness'])       AS harness,
    coalesce(nullif(Attributes['model'], ''), Attributes['gen_ai.request.model']) AS model,
    coalesce(nullif(ResourceAttributes['halo.experiment'], ''), Attributes['halo.experiment']) AS experiment,
    coalesce(nullif(ResourceAttributes['halo.variant'], ''), Attributes['halo.variant'])       AS variant,
    Attributes                                       AS attrs
FROM halo.otel_metrics_sum
WHERE startsWith(MetricName, 'halo.');

CREATE MATERIALIZED VIEW IF NOT EXISTS halo.halo_metrics_from_gauge TO halo.halo_metrics AS
SELECT
    TimeUnix                                         AS ts,
    MetricName                                       AS metric,
    Value                                            AS value,
    coalesce(nullif(Attributes['user.id'], ''), nullif(Attributes['halo.unit'], ''), Attributes['installation.id']) AS unit_id,
    Attributes['session.id']                         AS session_id,
    coalesce(nullif(ResourceAttributes['halo.ring'], ''), Attributes['halo.ring'])             AS ring,
    coalesce(nullif(ResourceAttributes['halo.release'], ''), Attributes['halo.release'])       AS release,
    coalesce(nullif(ResourceAttributes['halo.harness'], ''), Attributes['halo.harness'])       AS harness,
    coalesce(nullif(Attributes['model'], ''), Attributes['gen_ai.request.model']) AS model,
    coalesce(nullif(ResourceAttributes['halo.experiment'], ''), Attributes['halo.experiment']) AS experiment,
    coalesce(nullif(ResourceAttributes['halo.variant'], ''), Attributes['halo.variant'])       AS variant,
    Attributes                                       AS attrs
FROM halo.otel_metrics_gauge
WHERE startsWith(MetricName, 'halo.');

CREATE MATERIALIZED VIEW IF NOT EXISTS halo.halo_metrics_from_histogram TO halo.halo_metrics AS
SELECT
    TimeUnix                                         AS ts,
    MetricName                                       AS metric,
    Sum                                              AS value,
    coalesce(nullif(Attributes['user.id'], ''), nullif(Attributes['halo.unit'], ''), Attributes['installation.id']) AS unit_id,
    Attributes['session.id']                         AS session_id,
    coalesce(nullif(ResourceAttributes['halo.ring'], ''), Attributes['halo.ring'])             AS ring,
    coalesce(nullif(ResourceAttributes['halo.release'], ''), Attributes['halo.release'])       AS release,
    coalesce(nullif(ResourceAttributes['halo.harness'], ''), Attributes['halo.harness'])       AS harness,
    coalesce(nullif(Attributes['model'], ''), Attributes['gen_ai.request.model']) AS model,
    coalesce(nullif(ResourceAttributes['halo.experiment'], ''), Attributes['halo.experiment']) AS experiment,
    coalesce(nullif(ResourceAttributes['halo.variant'], ''), Attributes['halo.variant'])       AS variant,
    Attributes                                       AS attrs,
    toFloat64(Count)                                 AS count,
    ExplicitBounds                                   AS bounds,
    BucketCounts                                     AS buckets
FROM halo.otel_metrics_histogram
WHERE startsWith(MetricName, 'halo.');

-- CLI log events -> one row per model API call (halo.api.request) or tool call
-- (halo.tool.call). value = duration in ms; attrs['error'] = '1' on failure.
-- Only the fields below are kept: never prompts, tool input or error text.
--   Claude Code: claude_code.api_request (success) / claude_code.api_error, claude_code.tool_result{success}
--   Gemini CLI:  gemini_cli.api_response (error if status_code >= 400) / gemini_cli.api_error, gemini_cli.tool_call{success}
--   Codex:       codex.api_request (error unless 2xx and no error.message), codex.tool_result{success}
-- Claude Code's event.name is unprefixed ("api_request"); its Body carries the
-- full name. Gemini/Codex put the full name in event.name.
CREATE MATERIALIZED VIEW IF NOT EXISTS halo.halo_metrics_from_logs TO halo.halo_metrics AS
WITH
    if(position(LogAttributes['event.name'], '.') > 0, LogAttributes['event.name'], Body) AS ev,
    coalesce(nullif(LogAttributes['status_code'], ''), LogAttributes['http.response.status_code']) AS status
SELECT
    Timestamp                                        AS ts,
    multiIf(ev IN ('claude_code.api_request', 'claude_code.api_error', 'gemini_cli.api_response', 'gemini_cli.api_error', 'codex.api_request'), 'halo.api.request',
            ev IN ('claude_code.tool_result', 'gemini_cli.tool_call', 'codex.tool_result'), 'halo.tool.call', '') AS metric,
    toFloat64OrZero(coalesce(nullif(LogAttributes['duration_ms'], ''), LogAttributes['duration'])) AS value,
    multiIf(LogAttributes['user.id'] != '', LogAttributes['user.id'],
            LogAttributes['user.account_id'] != '', LogAttributes['user.account_id'],
            LogAttributes['installation.id'] != '', LogAttributes['installation.id'],
            coalesce(nullif(LogAttributes['session.id'], ''), LogAttributes['conversation.id'])) AS unit_id,
    coalesce(nullif(LogAttributes['session.id'], ''), LogAttributes['conversation.id']) AS session_id,
    ResourceAttributes['halo.ring']                  AS ring,
    ResourceAttributes['halo.release']               AS release,
    multiIf(ResourceAttributes['halo.harness'] != '', ResourceAttributes['halo.harness'],
            startsWith(ev, 'claude_code.'), 'claude-code', startsWith(ev, 'gemini_cli.'), 'gemini-cli', 'codex') AS harness,
    coalesce(nullif(LogAttributes['model'], ''), LogAttributes['model_name']) AS model,
    ResourceAttributes['halo.experiment']            AS experiment,
    ResourceAttributes['halo.variant']               AS variant,
    map('event', ev, 'status_code', status,
        'tool_name', coalesce(nullif(LogAttributes['tool_name'], ''), LogAttributes['function_name']),
        'error', toString(toUInt8(multiIf(
            ev IN ('claude_code.api_error', 'gemini_cli.api_error'), 1,
            ev = 'gemini_cli.api_response', toUInt16OrZero(status) >= 400,
            ev = 'codex.api_request', NOT (toUInt16OrZero(status) BETWEEN 200 AND 299 AND LogAttributes['error.message'] = ''),
            metric = 'halo.tool.call', lower(LogAttributes['success']) = 'false',
            0)))) AS attrs
FROM halo.otel_logs
WHERE metric != '';

-- One row per agent session (rolled up from events / gateway logs).
CREATE TABLE IF NOT EXISTS halo.halo_sessions
(
    session_id       String,
    started_at       DateTime64(3),
    ended_at         DateTime64(3),
    unit_id          String,
    ring             LowCardinality(String),
    release          String,
    harness          LowCardinality(String),
    harness_version  LowCardinality(String),
    model            LowCardinality(String),
    experiment       LowCardinality(String),
    variant          LowCardinality(String),
    cost_usd         Float64,
    tokens           UInt64,
    turns            UInt32,
    edits_accepted   UInt32,
    edits_rejected   UInt32,
    tool_errors      UInt32
)
ENGINE = ReplacingMergeTree(ended_at)
PARTITION BY toYYYYMM(started_at)
ORDER BY (session_id)
TTL toDateTime(started_at) + INTERVAL 180 DAY;

-- Offline replay (halo eval) trial results; mirrors internal/eval.Trial.
CREATE TABLE IF NOT EXISTS halo.halo_eval_results
(
    run_id      String,
    ts          DateTime64(3),
    suite       LowCardinality(String),
    task        LowCardinality(String),
    variant     LowCardinality(String),
    harness     LowCardinality(String),
    version     LowCardinality(String),
    model       LowCardinality(String),
    repeat      UInt16,
    pass        UInt8,
    cost_usd    Float64,
    turns       UInt32,
    wall_ms     UInt64,
    tokens      UInt64,
    tool_errors UInt32,
    error       String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (suite, task, variant, run_id, repeat);

-- Shadow traffic: first-turn request mirrored to a candidate, with judge scores.
CREATE TABLE IF NOT EXISTS halo.halo_shadow_pairs
(
    ts               DateTime64(3),
    pair_id          String,
    experiment       LowCardinality(String),
    unit_id          String,
    primary_model    LowCardinality(String),
    candidate_model  LowCardinality(String),
    primary_latency_ms   UInt32,
    candidate_latency_ms UInt32,
    primary_cost_usd     Float64,
    candidate_cost_usd   Float64,
    primary_score        Nullable(Float32),   -- LLM-judge score, 0..1
    candidate_score      Nullable(Float32),
    judge                LowCardinality(String),
    request_hash         String                -- hash only; bodies live in the pair store
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (experiment, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;
