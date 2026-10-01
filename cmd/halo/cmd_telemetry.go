package main

import (
	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/telemetry"
)

func (a *app) cmdTelemetry() *cobra.Command {
	tc := &cobra.Command{Use: "telemetry", Short: "Telemetry pipeline artifacts"}
	var o telemetry.Options
	var out string
	cc := &cobra.Command{
		Use: "collector-config", Short: "Generate the OpenTelemetry Collector config (normalises harness metrics to halo.*, exports to ClickHouse)", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			b, err := telemetry.Generate(o)
			if err != nil {
				return err
			}
			return a.emitBytes(out, b)
		},
	}
	f := cc.Flags()
	f.StringVar(&o.ClickHouseEndpoint, "clickhouse", "", "ClickHouse endpoint, e.g. tcp://clickhouse:9000 (required)")
	f.StringVar(&o.ClickHouseDatabase, "database", "", "ClickHouse database (default halo)")
	f.StringVar(&o.GRPCEndpoint, "grpc-endpoint", "", "OTLP/gRPC listen address (default 0.0.0.0:4317)")
	f.StringVar(&o.HTTPEndpoint, "http-endpoint", "", "OTLP/HTTP listen address (default 0.0.0.0:4318)")
	f.StringVar(&o.GatewayHTTPEndpoint, "gateway-endpoint", "", "halo-proxy OTLP/HTTP listen address, bearer token from env "+telemetry.GatewayTokenEnv+" (default 0.0.0.0:4319)")
	f.StringVar(&o.CLITokenFile, "cli-token-file", "", "require per-device bearer tokens (one per line in this file, as seen by the collector) on the CLI receiver")
	f.StringVar(&o.PrometheusEndpoint, "prometheus-endpoint", "", "Prometheus scrape listen address (default 0.0.0.0:8889)")
	f.StringVarP(&out, "out", "o", "-", "output file ('-' = stdout)")
	tc.AddCommand(cc)
	return tc
}
