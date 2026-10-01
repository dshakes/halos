---
title: "halo telemetry collector-config"
description: "Generate the OpenTelemetry Collector config (normalises harness metrics to halo.*, exports to ClickHouse)"
---

Generate the OpenTelemetry Collector config (normalises harness metrics to halo.*, exports to ClickHouse)

## Usage

```console
halo telemetry collector-config [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--cli-token-file` |  | string |  | require per-device bearer tokens (one per line in this file, as seen by the collector) on the CLI receiver |
| `--clickhouse` |  | string |  | ClickHouse endpoint, e.g. tcp://clickhouse:9000 (required) |
| `--database` |  | string |  | ClickHouse database (default halo) |
| `--eval-endpoint` |  | string |  | eval receiver listen address (default 0.0.0.0:4320) |
| `--eval-receiver` |  | bool | false | add the online-eval OTLP/HTTP receiver (halo.eval.* only, stamped halo.source=eval), bearer token from env HALO_OTLP_EVAL_TOKEN |
| `--gateway-endpoint` |  | string |  | halo-proxy OTLP/HTTP listen address, bearer token from env HALO_OTLP_GATEWAY_TOKEN (default 0.0.0.0:4319) |
| `--grpc-endpoint` |  | string |  | OTLP/gRPC listen address (default 0.0.0.0:4317) |
| `--http-endpoint` |  | string |  | OTLP/HTTP listen address (default 0.0.0.0:4318) |
| `--out` | `-o` | string | - | output file ('-' = stdout) |
| `--prometheus-endpoint` |  | string |  | Prometheus scrape listen address (default 0.0.0.0:8889) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo telemetry`](/halos/reference/cli/telemetry/)
