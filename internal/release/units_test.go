package release

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// unitAdapter renders the profile fields a unit overlay changes, plus a
// CLAUDE.md-like file only when instructions are set.
type unitAdapter struct{}

func (unitAdapter) Name() string                             { return "unitfake" }
func (unitAdapter) Capabilities() []harness.Capability       { return nil }
func (unitAdapter) InstallCommand(string, harness.OS) string { return "" }
func (unitAdapter) Render(p *policy.Profile, _ harness.Context) ([]harness.File, []string, error) {
	b, err := json.Marshal(map[string]any{"sandbox": p.Permissions.Sandbox, "deny": p.Permissions.Deny, "models": p.Models.Allowed})
	out := []harness.File{{Path: "/etc/unitfake/settings.json", Mode: 0o644, Data: b}}
	if p.Instructions != "" {
		out = append(out, harness.File{Path: "/etc/unitfake/MEMORY.md", Mode: 0o644, Data: []byte(p.Instructions)})
	}
	return out, nil, err
}

func init() { harness.Register(unitAdapter{}) }

func unitOrg(width, depth int) *policy.Org {
	o := &policy.Org{
		Name: "acme",
		Profiles: map[string]*policy.Profile{"base": {
			Meta: policy.Meta{Name: "base"}, Harnesses: map[string]policy.HarnessSpec{"unitfake": {Version: "1.0.0"}},
			Models:      policy.Models{Default: "a", Allowed: []string{"a", "b"}},
			Permissions: policy.Permissions{DisableBypass: true, Sandbox: "workspace-write", Deny: []string{"Read(.env)"}},
			Telemetry:   policy.Telemetry{Enabled: true},
		}},
		Rings: []*policy.Ring{{Meta: policy.Meta{Name: "ga"}, Profile: "base", Membership: policy.Membership{Default: true}}},
	}
	for i := range width {
		parent := ""
		for d := range depth {
			name := fmt.Sprintf("bu%02d-l%d", i, d)
			o.Units = append(o.Units, &policy.Unit{Meta: policy.Meta{Name: name}, Parent: parent, Owners: []string{"@acme/" + name},
				Members: policy.UnitMembers{Groups: []string{name}},
				Overlay: policy.Overlay{Permissions: policy.Permissions{Deny: []string{"Read(" + name + ")"}}}})
			parent = name
		}
	}
	return o
}

func unitFile(t *testing.T, r *Release, e *UnitEntry, path string) []byte {
	t.Helper()
	for _, f := range e.Files["unitfake"]["linux"] {
		if f.Path == path {
			return r.Blobs[f.SHA256]
		}
	}
	return nil
}

func TestBuildUnits(t *testing.T) {
	o := unitOrg(1, 1)
	o.Units = append(o.Units,
		&policy.Unit{Meta: policy.Meta{Name: "narrow"}, Members: policy.UnitMembers{Users: []string{"n"}},
			Overlay: policy.Overlay{Models: policy.Models{Allowed: []string{"a"}}, Permissions: policy.Permissions{Sandbox: "read-only"}, Instructions: "be careful"}},
		&policy.Unit{Meta: policy.Meta{Name: "noop"}, Members: policy.UnitMembers{Users: []string{"x"}}})
	rel, err := Build(o, "base", "ga", Options{Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	m := rel.Manifest
	if got := len(m.Units); got != 3 || m.Units[0].Name != "bu00-l0" || m.Units[1].Name != "narrow" {
		t.Fatalf("units = %+v", m.Units)
	}
	// The narrow unit's files are whole files: the shorter model list and the
	// added memory file both ship, which a delta could not express.
	e := m.MatchUnit(policy.Subject{ID: "n"})
	if e == nil || e.Name != "narrow" {
		t.Fatalf("MatchUnit = %+v", e)
	}
	var s map[string]any
	if err := json.Unmarshal(unitFile(t, rel, e, "/etc/unitfake/settings.json"), &s); err != nil {
		t.Fatal(err)
	}
	if s["sandbox"] != "read-only" || len(s["models"].([]any)) != 1 || len(s["deny"].([]any)) != 1 {
		t.Fatalf("narrow unit settings %v", s)
	}
	if string(unitFile(t, rel, e, "/etc/unitfake/MEMORY.md")) != "be careful" {
		t.Fatal("unit-added file missing")
	}
	if noop := m.MatchUnit(policy.Subject{ID: "x"}); noop == nil || len(noop.Files) != 0 {
		t.Fatalf("a unit that changes nothing ships no files: %+v", noop)
	}
	opened, err := Open(rel.Tar)
	if err != nil || len(opened.Manifest.Units) != 3 {
		t.Fatalf("reopen: %v %+v", err, opened.Manifest.Units)
	}
	// no units: the manifest (and so the digest) is unchanged
	plain := unitOrg(0, 0)
	pr, err := Build(plain, "base", "ga", Options{Version: "1"})
	if err != nil || pr.Manifest.Units != nil {
		t.Fatalf("no-unit build: %v %+v", err, pr.Manifest.Units)
	}
	// a broken hierarchy fails the build
	o.Units = append(o.Units, &policy.Unit{Meta: policy.Meta{Name: "orphan"}, Parent: "missing", Members: policy.UnitMembers{Users: []string{"o"}}})
	if _, err := Build(o, "base", "ga", Options{Version: "1"}); err == nil {
		t.Fatal("unknown parent accepted")
	}
}

func TestBuildLargeOrg(t *testing.T) {
	o := unitOrg(50, 3)
	if issues := o.Validate(); slices.ContainsFunc(issues, func(i policy.Issue) bool {
		return strings.HasPrefix(i.Path, "units[") // the fake harness and missing gateway are not under test
	}) {
		t.Fatalf("synthetic units invalid: %v", issues)
	}
	start := time.Now()
	rel, err := Build(o, "base", "ga", Options{Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("build of 150 units took %v", took)
	}
	if len(rel.Manifest.Units) != 150 {
		t.Fatalf("%d units in manifest", len(rel.Manifest.Units))
	}
	e := rel.Manifest.MatchUnit(policy.Subject{ID: "u", Groups: []string{"bu37-l0", "bu37-l1", "bu37-l2"}})
	if e == nil || e.Name != "bu37-l2" {
		t.Fatalf("MatchUnit = %+v", e)
	}
	var s struct{ Deny []string }
	if err := json.Unmarshal(unitFile(t, rel, e, "/etc/unitfake/settings.json"), &s); err != nil {
		t.Fatal(err)
	}
	if want := []string{"Read(.env)", "Read(bu37-l0)", "Read(bu37-l1)", "Read(bu37-l2)"}; !slices.Equal(s.Deny, want) {
		t.Fatalf("deny = %v, want %v", s.Deny, want)
	}
}

func BenchmarkBuildLargeOrg(b *testing.B) {
	o := unitOrg(50, 3)
	for b.Loop() {
		if _, err := Build(o, "base", "ga", Options{Version: "1"}); err != nil {
			b.Fatal(err)
		}
	}
}
