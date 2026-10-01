package all_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
)

// A client-axis variant release carries halo.experiment/halo.variant in every
// CLI's telemetry resource attributes: claude-code via managed env, the others
// via their /etc/profile.d wrapper on Linux (they all honor
// OTEL_RESOURCE_ATTRIBUTES; test/uat), with a warning elsewhere. Neither is
// ever a request header: the gateway assigns x-halo-experiment.
func TestExperimentAttribution(t *testing.T) {
	attrRe := regexp.MustCompile(`OTEL_RESOURCE_ATTRIBUTES"?[:=] ?["']([^"']*)`)
	for _, name := range harness.Names() {
		t.Run(name, func(t *testing.T) {
			ad, _ := harness.Get(name)
			p, g := hutiltest.Fixture()
			p.Telemetry.Protocol = "http/protobuf" // copilot renders telemetry only over http
			p.Telemetry.Attributes = map[string]string{"halo.experiment": "spoofed"}
			c := harness.Context{Gateway: g, Ring: "ga", Release: "1.2.0-x-cli.treatment", OS: harness.Linux, Experiment: "cli", Variant: "treatment"}
			render := func() string {
				files, _, err := ad.Render(p, c)
				if err != nil {
					t.Fatal(err)
				}
				all := ""
				for _, f := range files {
					all += string(f.Data)
				}
				return all
			}
			all := render()
			if strings.Contains(strings.ToLower(all), "x-halo-experiment") || strings.Contains(strings.ToLower(all), "x-halo-variant") {
				t.Fatalf("experiment sent as a request header:\n%s", all)
			}
			m := attrRe.FindStringSubmatch(all)
			if m == nil {
				t.Fatalf("no OTEL_RESOURCE_ATTRIBUTES rendered:\n%s", all)
			}
			attrs := m[1]
			if !strings.Contains(attrs, "halo.experiment=cli,") || !strings.Contains(attrs, "halo.variant=treatment") || !strings.Contains(attrs, "halo.harness="+name) || strings.Contains(attrs, "spoofed") {
				t.Fatalf("OTEL_RESOURCE_ATTRIBUTES = %q", attrs)
			}
			// the ring release (no experiment) never claims one, even if a profile attribute tries
			c.Experiment, c.Variant = "", ""
			if all := render(); strings.Contains(all, "halo.experiment") {
				t.Fatalf("ring release claims an experiment:\n%s", all)
			}
			if name == "claude-code" {
				return
			}
			c.OS = harness.Darwin
			_, warns, _ := ad.Render(p, c)
			if !strings.Contains(strings.Join(warns, "\n"), "no telemetry resource-attribute setting off Linux") {
				t.Fatalf("darwin: no attribution warning: %v", warns)
			}
		})
	}
}
