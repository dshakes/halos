package telemetry

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestGenerateGolden(t *testing.T) {
	got, err := Generate(Options{ClickHouseEndpoint: "tcp://clickhouse:9000"})
	if err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/collector.golden.yaml"
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("collector config differs from %s (run with -update to accept):\n%s", golden, got)
	}
}

func TestGenerateStructure(t *testing.T) {
	got, err := Generate(Options{ClickHouseEndpoint: "tcp://ch:9000", ClickHouseDatabase: "acme", GRPCEndpoint: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Exporters  map[string]map[string]any `yaml:"exporters"`
		Receivers  map[string]any            `yaml:"receivers"`
		Processors map[string]any            `yaml:"processors"`
		Service    struct {
			Pipelines map[string]struct {
				Processors []string `yaml:"processors"`
				Exporters  []string `yaml:"exporters"`
			} `yaml:"pipelines"`
		} `yaml:"service"`
	}
	if err := yaml.Unmarshal(got, &cfg); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}
	if cfg.Exporters["clickhouse"]["database"] != "acme" || cfg.Exporters["clickhouse"]["endpoint"] != "tcp://ch:9000" {
		t.Fatalf("options not applied: %v", cfg.Exporters["clickhouse"])
	}
	// Every pipeline component must be defined.
	for name, p := range cfg.Service.Pipelines {
		for _, e := range p.Exporters {
			if _, ok := cfg.Exporters[e]; !ok {
				t.Errorf("pipeline %s: undefined exporter %s", name, e)
			}
		}
		for _, pr := range p.Processors {
			if _, ok := cfg.Processors[pr]; !ok {
				t.Errorf("pipeline %s: undefined processor %s", name, pr)
			}
		}
	}
	s := string(got)
	for _, m := range []string{
		`claude_code.cost.usage`, `halo.cost.usd`, `claude_code.token.usage`, `claude_code.code_edit_tool.decision`,
		`halo.edit.decision`, `gen_ai.client.token.usage`, `halo.tokens`,
	} {
		if !strings.Contains(s, m) {
			t.Errorf("config missing mapping for %s", m)
		}
	}
	// Harness stamping must precede renames (rename removes the source name).
	if strings.Index(s, `halo.harness`) > strings.Index(s, `set(name,`) {
		t.Error("halo.harness must be set before metrics are renamed")
	}
}

// Evidence trust: the gateway receiver authenticates and stamps
// halo.source=gateway; the CLI receiver drops halo.gateway.*, overwrites
// halo.source=cli and caps request size; per-device CLI tokens are opt-in.
func TestGenerateEvidenceTrust(t *testing.T) {
	type pipeline struct {
		Receivers  []string `yaml:"receivers"`
		Processors []string `yaml:"processors"`
	}
	type config struct {
		Extensions map[string]map[string]any `yaml:"extensions"`
		Receivers  map[string]struct {
			Protocols map[string]map[string]any `yaml:"protocols"`
		} `yaml:"receivers"`
		Processors map[string]any `yaml:"processors"`
		Service    struct {
			Extensions []string            `yaml:"extensions"`
			Pipelines  map[string]pipeline `yaml:"pipelines"`
		} `yaml:"service"`
	}
	auth := func(p map[string]any) any {
		a, _ := p["auth"].(map[string]any)
		return a["authenticator"]
	}
	for _, tc := range []struct {
		name     string
		opts     Options
		cliToken bool
	}{
		{"default", Options{ClickHouseEndpoint: "tcp://ch:9000"}, false},
		{"per-device CLI tokens", Options{ClickHouseEndpoint: "tcp://ch:9000", CLITokenFile: "/etc/otelcol/cli-tokens"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Generate(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			var c config
			if err := yaml.Unmarshal(b, &c); err != nil {
				t.Fatal(err)
			}
			gw := c.Receivers["otlp/gateway"].Protocols
			if len(gw) != 1 || gw["http"]["endpoint"] != "0.0.0.0:4319" || auth(gw["http"]) != "bearertokenauth/gateway" {
				t.Errorf("gateway receiver must be OTLP/HTTP on 4319 behind bearer auth: %v", gw)
			}
			if c.Extensions["bearertokenauth/gateway"]["token"] != "${env:"+GatewayTokenEnv+"}" {
				t.Errorf("gateway token extension: %v", c.Extensions)
			}
			cli := c.Receivers["otlp"].Protocols
			if cli["http"]["max_request_body_size"] != maxCLIRequestMiB<<20 || cli["grpc"]["max_recv_msg_size_mib"] != maxCLIRequestMiB {
				t.Errorf("CLI receiver must cap request size: %v", cli)
			}
			for _, p := range []string{"http", "grpc"} {
				if got := auth(cli[p]); (got == "bearertokenauth/cli") != tc.cliToken {
					t.Errorf("CLI %s auth = %v, want token=%v", p, got, tc.cliToken)
				}
			}
			if _, ok := c.Extensions["bearertokenauth/cli"]; ok != tc.cliToken {
				t.Errorf("bearertokenauth/cli defined=%v, want %v", ok, tc.cliToken)
			}
			for n := range c.Extensions {
				if !strings.Contains(strings.Join(c.Service.Extensions, ","), n) {
					t.Errorf("extension %s defined but not enabled in service.extensions", n)
				}
			}
			idx := func(ps []string, n string) int {
				for i, p := range ps {
					if p == n {
						return i
					}
				}
				return -1
			}
			for name, p := range c.Service.Pipelines {
				gateway := len(p.Receivers) == 1 && p.Receivers[0] == "otlp/gateway"
				if !gateway && idx(p.Receivers, "otlp/gateway") >= 0 {
					t.Errorf("%s mixes gateway and CLI receivers", name)
				}
				switch {
				case gateway:
					if idx(p.Processors, "transform/source-gateway") < 0 {
						t.Errorf("%s: gateway pipeline must stamp halo.source=gateway", name)
					}
				case strings.HasPrefix(name, "metrics"):
					if f := idx(p.Processors, "filter/drop-gateway"); f < 0 || f > idx(p.Processors, "transform/halo") {
						t.Errorf("%s: CLI pipeline must drop halo.gateway.* before renaming: %v", name, p.Processors)
					}
					if idx(p.Processors, "transform/source-gateway") >= 0 {
						t.Errorf("%s: CLI pipeline stamps gateway source", name)
					}
				}
			}
			if cl := c.Service.Pipelines["metrics/clickhouse"]; idx(cl.Processors, "transform/source-cli") < 0 {
				t.Error("CLI ClickHouse pipeline must overwrite halo.source=cli")
			}
			if c.Service.Pipelines["metrics/gateway"].Receivers == nil {
				t.Error("no gateway pipeline")
			}
			s := string(b)
			for _, want := range []string{`set(datapoint.attributes["halo.source"], "cli")`, `set(datapoint.attributes["halo.source"], "gateway")`, `delete_key(resource.attributes, "halo.source")`} {
				if !strings.Contains(s, want) {
					t.Errorf("config lacks %s", want)
				}
			}
		})
	}
}

func TestMappingsAreNormalised(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Mappings {
		if !strings.HasPrefix(m.To, "halo.") || strings.HasPrefix(m.From, "halo.") {
			t.Errorf("bad mapping %+v", m)
		}
		if seen[m.From] {
			t.Errorf("duplicate source metric %s", m.From)
		}
		seen[m.From] = true
	}
}

func TestGenerateRequiresClickHouse(t *testing.T) {
	if _, err := Generate(Options{}); err == nil {
		t.Fatal("want error when ClickHouseEndpoint is empty")
	}
}
