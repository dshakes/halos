package copilot

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

func renderSettings(t *testing.T, mut func(*policy.Profile)) (map[string]any, string) {
	t.Helper()
	p, g := hutiltest.Fixture()
	if mut != nil {
		mut(p)
	}
	files, warns, err := Adapter{}.Render(p, harness.Context{Gateway: g, OS: harness.Linux})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(files[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	return m, strings.Join(warns, "\n")
}

func TestPluginsAndMCPDeny(t *testing.T) {
	m, warns := renderSettings(t, nil)
	if got := m["enabledPlugins"]; !reflect.DeepEqual(got, map[string]any{"audit@acme-plugins": true, "risky@acme-plugins": false}) {
		t.Errorf("enabledPlugins = %v", got)
	}
	if got, _ := m["strictKnownMarketplaces"].([]any); len(got) != 2 {
		t.Errorf("strictKnownMarketplaces = %v", m["strictKnownMarketplaces"])
	}
	if got := m["deniedMcpServers"]; !reflect.DeepEqual(got, []any{map[string]any{"serverName": "filesystem"}}) {
		t.Errorf("deniedMcpServers = %v", got)
	}
	for _, w := range []string{
		`mcp.denied "filesystem" is matched by name only`,
		`"extensions.blockedMarketplaces"`, `"extensions.skills.deny"`, `"extensions.subagents.deny"`,
		`"extensions.outputStyle"`, `"extensions.statusLine"`, `"login"`,
	} {
		if !strings.Contains(warns, w) {
			t.Errorf("missing warning %q in\n%s", w, warns)
		}
	}
	for _, k := range []string{"outputStyle", "statusLine", "forceLoginMethod", "skillOverrides"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s rendered with no documented Copilot key", k)
		}
	}
}

func TestMCPDenyByURLAndManagedOnly(t *testing.T) {
	tests := []struct {
		name     string
		mut      func(*policy.Profile)
		key      string
		want     any
		wantWarn bool
	}{
		{"deny by url", func(p *policy.Profile) { p.MCP.Denied = []string{"https://evil.example.com/mcp"} },
			"deniedMcpServers", []any{map[string]any{"serverUrl": "https://evil.example.com/mcp"}}, false},
		{"managedOnly without servers blocks all", func(p *policy.Profile) { p.MCP.Servers = nil; p.MCP.Denied = nil },
			"allowedMcpServers", []any{}, false},
		{"name deny warns", func(p *policy.Profile) { p.MCP.Denied = []string{"x"} },
			"deniedMcpServers", []any{map[string]any{"serverName": "x"}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, warns := renderSettings(t, tc.mut)
			if got := m[tc.key]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s = %#v, want %#v", tc.key, got, tc.want)
			}
			if got := strings.Contains(warns, "matched by name only"); got != tc.wantWarn {
				t.Errorf("name-only warning = %v, want %v", got, tc.wantWarn)
			}
		})
	}
}
