package gemini

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

// renderJSON renders the fixture profile (mutated) with or without its gateway.
func renderJSON(t *testing.T, gateway bool, mut func(*policy.Profile)) (map[string]any, string) {
	t.Helper()
	p, g := hutiltest.Fixture()
	if mut != nil {
		mut(p)
	}
	c := harness.Context{OS: harness.Linux}
	if gateway {
		c.Gateway = g
	}
	files, warns, err := Adapter{}.Render(p, c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(files[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	return m, strings.Join(warns, "\n")
}

func TestSkillsSubagentsAndMCPExclude(t *testing.T) {
	m, warns := renderJSON(t, true, nil)
	if got := m["skills"]; !reflect.DeepEqual(got, map[string]any{"disabled": []any{"deploy"}}) {
		t.Errorf("skills = %v", got)
	}
	if got := m["agents"]; !reflect.DeepEqual(got, map[string]any{"overrides": map[string]any{"Explore": map[string]any{"enabled": false}}}) {
		t.Errorf("agents = %v", got)
	}
	mcp := m["mcp"].(map[string]any)
	if !reflect.DeepEqual(mcp["excluded"], []any{"filesystem"}) || !reflect.DeepEqual(mcp["allowed"], []any{"docs", "lint"}) {
		t.Errorf("mcp = %v", mcp)
	}
	// Everything Gemini cannot express must warn, never vanish (invariant 2).
	for _, w := range []string{
		"mcp.allowed and mcp.excluded match server names only",
		`"extensions.marketplaces"`, `"extensions.blockedMarketplaces"`, `"extensions.plugins.enabled"`, `"extensions.plugins.blocked"`,
		`"extensions.skills.pluginOnly"`, `"extensions.outputStyle"`, `"extensions.statusLine"`,
	} {
		if !strings.Contains(warns, w) {
			t.Errorf("missing warning %q in\n%s", w, warns)
		}
	}
	for _, k := range []string{"outputStyle", "statusLine", "plugins"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s rendered with no documented Gemini key", k)
		}
	}
}

func TestMCPDenyEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		mut      func(*policy.Profile)
		want     any // value of mcp.excluded
		wantWarn string
	}{
		{"url denial is not renderable", func(p *policy.Profile) { p.MCP.Denied = []string{"https://evil.example.com"} },
			nil, `mcp.denied "https://evil.example.com" is a URL`},
		{"name and url mixed", func(p *policy.Profile) { p.MCP.Denied = []string{"a", "https://evil.example.com"} },
			[]any{"a"}, "is a URL"},
		{"managedOnly without servers warns", func(p *policy.Profile) { p.MCP.Servers = nil; p.MCP.Denied = nil },
			nil, "mcp.managedOnly without mcp.servers is not rendered"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, warns := renderJSON(t, true, tc.mut)
			mcp, _ := m["mcp"].(map[string]any)
			if got := mcp["excluded"]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mcp.excluded = %#v, want %#v", got, tc.want)
			}
			if !strings.Contains(warns, tc.wantWarn) {
				t.Errorf("warnings missing %q in\n%s", tc.wantWarn, warns)
			}
		})
	}
}

func TestLoginEnforcedType(t *testing.T) {
	tests := []struct {
		name     string
		gateway  bool
		login    string
		want     any
		wantWarn string
	}{
		{"subscription without gateway", false, policy.LoginSubscription, "oauth-personal", ""},
		{"api without gateway", false, policy.LoginAPI, "gemini-api-key", ""},
		{"api with gateway", true, policy.LoginAPI, "gemini-api-key", ""},
		{"subscription conflicts with gateway", true, policy.LoginSubscription, "gemini-api-key", "login subscription conflicts with the gateway"},
		{"unset without gateway", false, "", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, warns := renderJSON(t, tc.gateway, func(p *policy.Profile) { p.Login = tc.login })
			sec, _ := m["security"].(map[string]any)
			auth, _ := sec["auth"].(map[string]any)
			if got := auth["enforcedType"]; got != tc.want {
				t.Errorf("enforcedType = %v, want %v", got, tc.want)
			}
			if tc.wantWarn != "" && !strings.Contains(warns, tc.wantWarn) {
				t.Errorf("warnings missing %q in\n%s", tc.wantWarn, warns)
			}
		})
	}
}
