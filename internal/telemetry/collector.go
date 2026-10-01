// Package telemetry generates the OpenTelemetry Collector configuration that
// receives OTLP from Claude Code, Codex and Gemini CLI, normalises their
// harness-specific metrics into the halo.* schema, and exports to ClickHouse and
// Prometheus.
//
// Verified end to end by `make obs-e2e` (scripts/obs-e2e.sh): the config loads
// in otelcol-contrib 0.161.0 (`validate`), the transform renames metrics and
// stamps halo.harness, and clickhouseexporter writes the rows that
// deploy/observability/clickhouse/schema.sql projects into halo_metrics. Codex
// telemetry is event-oriented and its native metrics are not mapped; Codex only
// matches when it reports gen_ai.client.token.usage with halo.harness=codex set.
// API/tool events from all three CLIs arrive on the logs pipeline and are turned
// into halo.api.request / halo.tool.call rows by the schema's log view.
//
// Metrics fan out to two pipelines: ClickHouse gets cumulativetodelta (so
// per-unit sums never double count cumulative counters); Prometheus keeps the
// native temporality, takes only the halo.* resource attributes as labels, and
// drops halo-proxy's halo.gateway.* metrics, whose per-unit halo.unit attribute
// would explode label cardinality (halo-proxy serves its own /metrics).
//
// Evidence trust: there are two OTLP receivers. `otlp` (CLI, 4317/4318) must be
// reachable from developer machines, so anything on it is client-controlled: it
// drops every halo.gateway.* metric and overwrites the data point attribute
// halo.source with "cli". `otlp/gateway` (OTLP/HTTP, 4319) requires the
// halo-proxy bearer token (${env:HALO_OTLP_GATEWAY_TOKEN}; the collector refuses
// to start without it) and stamps halo.source="gateway". internal/promote only
// counts halo.gateway.* rows carrying halo.source=gateway, and the controller
// only auto-kills on gateway-sourced evidence. Optionally the CLI receiver
// requires per-device bearer tokens (Options.CLITokenFile, one per line,
// hot-reloaded); either way its request size is capped.
//
// Optionally (Options.EvalReceiver) a third receiver, `otlp/eval` (OTLP/HTTP,
// 4320), takes `halo eval online` quality readings behind its own token
// (${env:HALO_OTLP_EVAL_TOKEN}, never the gateway token): it keeps only
// halo.eval.* metrics (so it can never carry halo.gateway.* evidence) and
// stamps halo.source="eval", which nothing auto-kills on.
package telemetry

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// Mapping renames one harness-native metric to its normalised halo.* name.
type Mapping struct {
	Harness string // value stamped into resource attribute halo.harness if absent
	From    string
	To      string
}

// Mappings is the single source of truth for metric normalisation.
var Mappings = []Mapping{
	{"claude-code", "claude_code.cost.usage", "halo.cost.usd"},
	{"claude-code", "claude_code.token.usage", "halo.tokens"},
	{"claude-code", "claude_code.code_edit_tool.decision", "halo.edit.decision"},
	{"claude-code", "claude_code.session.count", "halo.sessions"},
	{"claude-code", "claude_code.lines_of_code.count", "halo.loc"},
	{"claude-code", "claude_code.pull_request.count", "halo.pull_requests"},
	{"claude-code", "claude_code.commit.count", "halo.commits"},
	{"claude-code", "claude_code.active_time.total", "halo.active_time.seconds"},
	{"gemini-cli", "gen_ai.client.token.usage", "halo.tokens"},
	{"gemini-cli", "gen_ai.client.operation.duration", "halo.operation.duration"},
	{"gemini-cli", "gemini_cli.session.count", "halo.sessions"},
	{"gemini-cli", "gemini_cli.tool.call.count", "halo.tool.calls"},
}

// Options configures the generated collector.
type Options struct {
	GRPCEndpoint        string // CLI OTLP/gRPC listen address, default 0.0.0.0:4317
	HTTPEndpoint        string // CLI OTLP/HTTP listen address, default 0.0.0.0:4318
	GatewayHTTPEndpoint string // halo-proxy OTLP/HTTP listen address (bearer token), default 0.0.0.0:4319
	// CLITokenFile, if set, makes the CLI receiver require a bearer token listed
	// in this file (one per line; the collector re-reads it on change).
	CLITokenFile string
	// EvalReceiver adds the authenticated online-eval receiver on
	// EvalHTTPEndpoint (default 0.0.0.0:4320), token from EvalTokenEnv.
	EvalReceiver       bool
	EvalHTTPEndpoint   string
	ClickHouseEndpoint string // required, e.g. tcp://clickhouse:9000
	ClickHouseDatabase string // default halo
	PrometheusEndpoint string // scrape listen address, default 0.0.0.0:8889
}

// GatewayTokenEnv is the collector environment variable holding the bearer
// token halo-proxy presents on the gateway receiver.
const GatewayTokenEnv = "HALO_OTLP_GATEWAY_TOKEN" //nolint:gosec // env var name, not a credential

// EvalTokenEnv is the collector environment variable holding the bearer token
// `halo eval online` presents on the eval receiver. It must differ from the
// gateway token: eval jobs must never be able to write gateway evidence.
const EvalTokenEnv = "HALO_OTLP_EVAL_TOKEN" //nolint:gosec // env var name, not a credential

// Trusted per-receiver values of the halo.source data point attribute.
const (
	SourceGateway = "gateway"
	SourceCLI     = "cli"
	SourceEval    = "eval"
)

// maxCLIRequestMiB caps one CLI export request (HTTP body / gRPC message).
const maxCLIRequestMiB = 4

func (o *Options) defaults() error {
	if o.ClickHouseEndpoint == "" {
		return errors.New("telemetry: ClickHouseEndpoint is required")
	}
	for p, d := range map[*string]string{
		&o.GRPCEndpoint: "0.0.0.0:4317", &o.HTTPEndpoint: "0.0.0.0:4318", &o.GatewayHTTPEndpoint: "0.0.0.0:4319",
		&o.ClickHouseDatabase: "halo", &o.PrometheusEndpoint: "0.0.0.0:8889", &o.EvalHTTPEndpoint: "0.0.0.0:4320",
	} {
		if *p == "" {
			*p = d
		}
	}
	return nil
}

// statements builds the OTTL statements. Harness is stamped first (only when
// the client did not already set halo.harness), then the metric is renamed. The
// resource attributes halo.ring / halo.release / halo.experiment / halo.variant come
// from OTEL_RESOURCE_ATTRIBUTES on the client and are left untouched.
func statements() []string {
	var out []string
	for _, m := range Mappings {
		out = append(out, fmt.Sprintf(
			`set(resource.attributes["halo.harness"], %q) where name == %q and resource.attributes["halo.harness"] == nil`,
			m.Harness, m.From))
	}
	for _, m := range Mappings {
		out = append(out, fmt.Sprintf(`set(name, %q) where name == %q`, m.To, m.From))
	}
	return out
}

// sourceStamp overwrites halo.source on every data point with the receiver's
// trusted value (a client-supplied one is replaced, never kept) and removes any
// client-supplied resource attribute of that name.
func sourceStamp(src string) map[string]any {
	return map[string]any{
		"error_mode": "ignore",
		"metric_statements": []any{map[string]any{
			"context": "datapoint",
			"statements": []string{
				fmt.Sprintf(`set(datapoint.attributes["halo.source"], %q)`, src),
				`delete_key(resource.attributes, "halo.source")`,
			},
		}},
	}
}

// Generate renders the collector configuration as YAML. Output is
// deterministic (map keys sorted by the YAML encoder).
func Generate(o Options) ([]byte, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	cliHTTP := map[string]any{"endpoint": o.HTTPEndpoint, "max_request_body_size": maxCLIRequestMiB << 20}
	cliGRPC := map[string]any{"endpoint": o.GRPCEndpoint, "max_recv_msg_size_mib": maxCLIRequestMiB}
	extensions := map[string]any{
		"health_check":            map[string]any{"endpoint": "0.0.0.0:13133"},
		"bearertokenauth/gateway": map[string]any{"token": "${env:" + GatewayTokenEnv + "}"},
	}
	if o.CLITokenFile != "" {
		extensions["bearertokenauth/cli"] = map[string]any{"filename": o.CLITokenFile}
		cliHTTP["auth"] = map[string]any{"authenticator": "bearertokenauth/cli"}
		cliGRPC["auth"] = map[string]any{"authenticator": "bearertokenauth/cli"}
	}
	if o.EvalReceiver {
		extensions["bearertokenauth/eval"] = map[string]any{"token": "${env:" + EvalTokenEnv + "}"}
	}
	extNames := make([]string, 0, len(extensions))
	for n := range extensions {
		extNames = append(extNames, n)
	}
	sort.Strings(extNames)
	cfg := map[string]any{
		"extensions": extensions,
		"receivers": map[string]any{
			"otlp": map[string]any{"protocols": map[string]any{"grpc": cliGRPC, "http": cliHTTP}},
			"otlp/gateway": map[string]any{"protocols": map[string]any{"http": map[string]any{
				"endpoint": o.GatewayHTTPEndpoint,
				"auth":     map[string]any{"authenticator": "bearertokenauth/gateway"},
			}}},
		},
		"processors": map[string]any{
			"memory_limiter": map[string]any{"check_interval": "1s", "limit_percentage": 80, "spike_limit_percentage": 25},
			"batch":          map[string]any{"timeout": "5s", "send_batch_size": 8192},
			// Defaults (all monotonic sums and histograms; initial_value auto)
			// are the documented gateway-deployment setting. Delta input is untouched.
			"cumulativetodelta": map[string]any{},
			// Clients must never inject gateway evidence: drop halo.gateway.* on
			// every CLI pipeline (and keep it out of Prometheus label space).
			"filter/drop-gateway": map[string]any{
				"error_mode": "ignore",
				"metrics":    map[string]any{"metric": []string{`IsMatch(name, "^halo\\.gateway\\.")`}},
			},
			"transform/source-cli":     sourceStamp(SourceCLI),
			"transform/source-gateway": sourceStamp(SourceGateway),
			"transform/halo": map[string]any{
				"error_mode": "ignore",
				"metric_statements": []any{map[string]any{
					"context":    "metric",
					"statements": statements(),
				}},
			},
		},
		"exporters": map[string]any{
			"clickhouse": map[string]any{ //nolint:gosec // config key name, not a credential
				"endpoint":         o.ClickHouseEndpoint,
				"database":         o.ClickHouseDatabase,
				"username":         "${env:CLICKHOUSE_USER}",
				"password":         "${env:CLICKHOUSE_PASSWORD}",
				"create_schema":    true,
				"ttl":              "720h",
				"timeout":          "10s",
				"retry_on_failure": map[string]any{"enabled": true, "initial_interval": "5s", "max_interval": "30s", "max_elapsed_time": "300s"},
			},
			"prometheus": map[string]any{
				"endpoint":                 o.PrometheusEndpoint,
				"resource_constant_labels": map[string]any{"included": []string{"halo.*"}},
			},
		},
		"service": map[string]any{
			"extensions": extNames,
			"pipelines": map[string]any{
				"metrics/clickhouse": map[string]any{
					"receivers":  []string{"otlp"},
					"processors": []string{"memory_limiter", "filter/drop-gateway", "cumulativetodelta", "transform/source-cli", "transform/halo", "batch"},
					"exporters":  []string{"clickhouse"},
				},
				"metrics/gateway": map[string]any{
					"receivers":  []string{"otlp/gateway"},
					"processors": []string{"memory_limiter", "cumulativetodelta", "transform/source-gateway", "batch"},
					"exporters":  []string{"clickhouse"},
				},
				"metrics/prometheus": map[string]any{
					"receivers":  []string{"otlp"},
					"processors": []string{"memory_limiter", "filter/drop-gateway", "transform/halo", "batch"},
					"exporters":  []string{"prometheus"},
				},
				"logs": map[string]any{
					"receivers":  []string{"otlp"},
					"processors": []string{"memory_limiter", "batch"},
					"exporters":  []string{"clickhouse"},
				},
			},
		},
	}
	if o.EvalReceiver {
		cfg["receivers"].(map[string]any)["otlp/eval"] = map[string]any{"protocols": map[string]any{"http": map[string]any{
			"endpoint":              o.EvalHTTPEndpoint,
			"max_request_body_size": maxCLIRequestMiB << 20,
			"auth":                  map[string]any{"authenticator": "bearertokenauth/eval"},
		}}}
		procs := cfg["processors"].(map[string]any)
		procs["filter/eval-only"] = map[string]any{
			"error_mode": "ignore",
			"metrics":    map[string]any{"metric": []string{`not IsMatch(name, "^halo\\.eval\\.")`}},
		}
		procs["transform/source-eval"] = sourceStamp(SourceEval)
		cfg["service"].(map[string]any)["pipelines"].(map[string]any)["metrics/eval"] = map[string]any{
			"receivers":  []string{"otlp/eval"},
			"processors": []string{"memory_limiter", "filter/eval-only", "transform/source-eval", "batch"},
			"exporters":  []string{"clickhouse"},
		}
	}
	var buf bytes.Buffer
	buf.WriteString("# Generated by Halos (internal/telemetry). Do not edit by hand.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("telemetry: encode collector config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("telemetry: encode collector config: %w", err)
	}
	return buf.Bytes(), nil
}
