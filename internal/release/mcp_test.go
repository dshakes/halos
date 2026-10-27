package release

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// mcpAdapter renders the MCP server names and the managedOnly lock.
type mcpAdapter struct{}

func (mcpAdapter) Name() string                             { return "mcpfake" }
func (mcpAdapter) Capabilities() []harness.Capability       { return nil }
func (mcpAdapter) InstallCommand(string, harness.OS) string { return "" }
func (mcpAdapter) Render(p *policy.Profile, _ harness.Context) ([]harness.File, []string, error) {
	var names []string
	for _, s := range p.MCP.Servers {
		names = append(names, s.Name)
	}
	b, err := json.Marshal(map[string]any{"servers": names, "managedOnly": p.MCP.ManagedOnly})
	return []harness.File{{Path: "/etc/mcpfake/mcp.json", Mode: 0o644, Data: b}}, nil, err
}

func init() { harness.Register(mcpAdapter{}) }

// TestBuildMCPRegistry: a ring release renders the registry servers its ring
// gets, its units the ones they add, and the manifest pins them for halod.
func TestBuildMCPRegistry(t *testing.T) {
	o := &policy.Org{
		Name:     "acme",
		Profiles: map[string]*policy.Profile{"base": {Meta: policy.Meta{Name: "base"}, Harnesses: map[string]policy.HarnessSpec{"mcpfake": {}}}},
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "canary"}, Profile: "base", Membership: policy.Membership{Groups: []string{"canary"}}},
			{Meta: policy.Meta{Name: "ga"}, Profile: "base", Membership: policy.Membership{Default: true}},
		},
		Units: []*policy.Unit{{Meta: policy.Meta{Name: "pay"}, Members: policy.UnitMembers{Groups: []string{"pay"}}}},
		MCP: &policy.MCPRegistry{Servers: []policy.RegistryServer{
			{ID: "wiki", URL: "https://wiki.example/mcp", Rings: []string{"canary", "ga"}},
			{ID: "lint", Package: &policy.MCPPackage{Type: policy.MCPPackageNPM, Identifier: "lint-mcp", Version: "1.2.3"}, Rings: []string{"canary"}},
			{ID: "ledger", URL: "https://ledger.example/mcp", Units: []string{"pay"}},
		}},
	}
	settings := func(t *testing.T, r *Release, files []FileEntry) map[string]any {
		t.Helper()
		var m map[string]any
		if len(files) != 1 || json.Unmarshal(r.Blobs[files[0].SHA256], &m) != nil {
			t.Fatalf("files %+v", files)
		}
		return m
	}
	for _, tc := range []struct {
		ring, mode string
		want       []any
		pins       []string
	}{
		{"ga", "", []any{"wiki"}, []string{"wiki", "ledger"}},
		{"canary", "", []any{"wiki", "lint"}, []string{"wiki", "lint", "ledger"}},
		{"ga", policy.MCPModeWarn, []any{"wiki"}, []string{"wiki", "ledger"}},
	} {
		o.MCP.Mode = tc.mode
		rel, err := Build(o, "base", tc.ring, Options{Version: "1", OSes: []harness.OS{harness.Linux}})
		if err != nil {
			t.Fatal(err)
		}
		m := rel.Manifest
		got := settings(t, rel, m.Harnesses["mcpfake"].Files["linux"])
		if !slices.Equal(got["servers"].([]any), tc.want) || got["managedOnly"] != (tc.mode != policy.MCPModeWarn) {
			t.Errorf("%s %q: rendered %v, want servers %v", tc.ring, tc.mode, got, tc.want)
		}
		var pins []string
		for _, p := range m.MCPServers {
			pins = append(pins, p.ID)
		}
		wantMode := policy.MCPModeAllowlist
		if tc.mode == policy.MCPModeWarn {
			wantMode = policy.MCPModeWarn
		}
		if !slices.Equal(pins, tc.pins) || m.MCPMode != wantMode {
			t.Errorf("%s %q: manifest mode %q pins %v, want %q %v", tc.ring, tc.mode, m.MCPMode, pins, wantMode, tc.pins)
		}
		u := m.MatchUnit(policy.Subject{ID: "p", Groups: []string{"pay"}})
		uf := settings(t, rel, u.Files["mcpfake"]["linux"])
		if want := append(slices.Clone(tc.want), "ledger"); !slices.Equal(uf["servers"].([]any), want) {
			t.Errorf("%s: unit pay renders %v, want %v", tc.ring, uf["servers"], want)
		}
	}
	if p := mustPin(t, o, "canary", "lint"); !slices.Equal(p.Command, []string{"npx", "-y", "lint-mcp@1.2.3"}) {
		t.Errorf("lint pin command = %v", p.Command)
	}
	// No registry: the manifest carries nothing new, so digests are unchanged.
	o.MCP = nil
	rel, err := Build(o, "base", "ga", Options{Version: "1", OSes: []harness.OS{harness.Linux}})
	if err != nil || rel.Manifest.MCPMode != "" || rel.Manifest.MCPServers != nil {
		t.Fatalf("no registry: %v %q %v", err, rel.Manifest.MCPMode, rel.Manifest.MCPServers)
	}
}

func mustPin(t *testing.T, o *policy.Org, ring, id string) policy.MCPPin {
	t.Helper()
	for _, p := range o.MCP.MCPPins(ring) {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("no pin %s in ring %s", id, ring)
	return policy.MCPPin{}
}
