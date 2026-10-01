package all_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/halos-dev/halos/internal/harness"
	_ "github.com/halos-dev/halos/internal/harness/all"
	"github.com/halos-dev/halos/internal/harness/hutil/hutiltest"
)

// A client-axis variant release carries halo.experiment/halo.variant in the
// CLI's telemetry resource attributes where the CLI supports it (claude-code),
// and every other adapter warns instead of silently dropping the attribution.
// Neither is ever a request header: the gateway assigns x-halo-experiment.
func TestExperimentAttribution(t *testing.T) {
	for _, name := range harness.Names() {
		t.Run(name, func(t *testing.T) {
			ad, _ := harness.Get(name)
			p, g := hutiltest.Fixture()
			p.Telemetry.Protocol = "http/protobuf" // copilot renders telemetry only over http
			p.Telemetry.Attributes = map[string]string{"halo.experiment": "spoofed"}
			c := harness.Context{Gateway: g, Ring: "ga", Release: "1.2.0-x-cli.treatment", OS: harness.Linux, Experiment: "cli", Variant: "treatment"}
			files, warns, err := ad.Render(p, c)
			if err != nil {
				t.Fatal(err)
			}
			all := ""
			for _, f := range files {
				all += string(f.Data)
			}
			if strings.Contains(strings.ToLower(all), "x-halo-experiment") || strings.Contains(strings.ToLower(all), "x-halo-variant") {
				t.Fatalf("experiment sent as a request header:\n%s", all)
			}
			if name != "claude-code" {
				if !strings.Contains(strings.Join(warns, "\n"), "not attributed to experiment cli") {
					t.Fatalf("no attribution warning: %v", warns)
				}
				return
			}
			var m struct{ Env map[string]string }
			if err := json.Unmarshal(files[0].Data, &m); err != nil {
				t.Fatal(err)
			}
			attrs := m.Env["OTEL_RESOURCE_ATTRIBUTES"]
			if !strings.Contains(attrs, "halo.experiment=cli,") || !strings.Contains(attrs, "halo.variant=treatment") || strings.Contains(attrs, "spoofed") {
				t.Fatalf("OTEL_RESOURCE_ATTRIBUTES = %q", attrs)
			}
			// the ring release (no experiment) never claims one, even if a profile attribute tries
			c.Experiment, c.Variant = "", ""
			files, _, _ = ad.Render(p, c)
			if strings.Contains(string(files[0].Data), "halo.experiment") {
				t.Fatalf("ring release claims an experiment:\n%s", files[0].Data)
			}
		})
	}
}
