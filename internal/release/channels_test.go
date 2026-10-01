package release

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/halos-dev/halos/internal/harness"
	"github.com/halos-dev/halos/internal/policy"
)

// ctxAdapter renders what it is given (pin + experiment context) as JSON; the
// real claude-code stamping is tested in internal/harness/claudecode.
type ctxAdapter struct{}

func (ctxAdapter) Name() string                             { return "ctxfake" }
func (ctxAdapter) Capabilities() []harness.Capability       { return nil }
func (ctxAdapter) InstallCommand(string, harness.OS) string { return "" }
func (ctxAdapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	b, err := json.Marshal(map[string]string{"pin": p.Harnesses["ctxfake"].Version, "experiment": c.Experiment, "variant": c.Variant, "release": c.Release})
	return []harness.File{{Path: "/etc/ctxfake/managed-settings.json", Mode: 0o644, Data: b}}, nil, err
}

func init() { harness.Register(ctxAdapter{}) }

func clientOrg(status string) *policy.Org {
	p := func(name, ver string) *policy.Profile {
		return &policy.Profile{
			Meta: policy.Meta{Name: name}, Harnesses: map[string]policy.HarnessSpec{"ctxfake": {Version: ver}},
			Permissions: policy.Permissions{DisableBypass: true}, Telemetry: policy.Telemetry{Enabled: true, OTLPEndpoint: "https://otel.example"},
		}
	}
	return &policy.Org{
		Name:     "acme",
		Profiles: map[string]*policy.Profile{"base": p("base", "2.1.280"), "next": p("next", "2.1.312")},
		Rings:    []*policy.Ring{{Meta: policy.Meta{Name: "ga"}, Profile: "base", Membership: policy.Membership{Default: true}}},
		Experiments: []*policy.Experiment{{
			Meta: policy.Meta{Name: "cli-upgrade"}, Type: policy.ExperimentAB, Axis: policy.AxisClient, Status: status, Rings: []string{"ga"}, Salt: "s1",
			Variants: []policy.Variant{{Name: "control", Weight: 3, Control: true, Profile: "base"}, {Name: "treatment", Weight: 1, Profile: "next"}},
		}},
	}
}

func settingsOf(t *testing.T, r *Release) map[string]any {
	t.Helper()
	for _, f := range r.Manifest.Harnesses["ctxfake"].Files["linux"] {
		if strings.HasSuffix(f.Path, "managed-settings.json") {
			var m map[string]any
			if err := json.Unmarshal(r.Blobs[f.SHA256], &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatal("no managed-settings.json")
	return nil
}

func TestBuildRingClientExperiment(t *testing.T) {
	rel, variants, err := BuildRing(clientOrg("running"), "ga", Options{Version: "1.2.0", Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Experiment{{Name: "cli-upgrade", Salt: "s1", Variants: []ExperimentVariant{
		{Name: "control", Weight: 3, Channel: "ga.x-cli-upgrade.control"},
		{Name: "treatment", Weight: 1, Channel: "ga.x-cli-upgrade.treatment"},
	}}}
	if got, _ := json.Marshal(rel.Manifest.Experiments); string(got) != string(must(json.Marshal(want))) {
		t.Fatalf("manifest experiments = %s", got)
	}
	if rel.Manifest.Experiment != "" || settingsOf(t, rel)["pin"] != "2.1.280" || settingsOf(t, rel)["experiment"] != "" {
		t.Fatalf("ring release must be the plain ring profile: %+v", rel.Manifest)
	}
	if got := rel.Manifest.Channels("ga"); len(got) != 2 || rel.Manifest.Channels("other") != nil {
		t.Fatalf("Channels = %v", got)
	}
	// round-trips through the signed tar
	opened, err := Open(rel.Tar)
	if err != nil || len(opened.Manifest.Experiments) != 1 || opened.Manifest.Experiments[0].Variants[1].Weight != 1 {
		t.Fatalf("reopen: %v %+v", err, opened.Manifest.Experiments)
	}
	if len(variants) != 2 {
		t.Fatalf("want 2 variant releases, got %d", len(variants))
	}
	for _, v := range variants {
		m := v.Manifest
		pin := map[string]string{"control": "2.1.280", "treatment": "2.1.312"}[m.Variant]
		if m.Ring != "ga" || m.Experiment != "cli-upgrade" || m.Version != "1.2.0-x-cli-upgrade."+m.Variant || len(m.Experiments) != 0 {
			t.Fatalf("variant manifest %+v", m)
		}
		if s := settingsOf(t, v); s["pin"] != pin || s["experiment"] != "cli-upgrade" || s["variant"] != m.Variant || s["release"] != m.Version {
			t.Fatalf("%s rendered with %v", m.Variant, s)
		}
	}

	paused, pv, err := BuildRing(clientOrg("paused"), "ga", Options{Version: "1.2.1", Org: "acme"})
	if err != nil || len(pv) != 0 || len(paused.Manifest.Experiments) != 0 {
		t.Fatalf("paused: %v %d %+v", err, len(pv), paused.Manifest.Experiments)
	}
	if _, _, err := BuildRing(clientOrg("running"), "nope", Options{}); err == nil {
		t.Fatal("unknown ring accepted")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
