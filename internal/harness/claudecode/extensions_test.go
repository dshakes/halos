package claudecode

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

func TestExtensionsRendered(t *testing.T) {
	files, _, err := render(nil, harness.Linux)
	if err != nil {
		t.Fatal(err)
	}
	m := settings(t, files)
	deny, _ := m["permissions"].(map[string]any)["deny"].([]any)
	for _, want := range []string{"Read(./.env)", "Skill(skill:deploy)", "Agent(Explore)"} {
		if !containsAny(deny, want) {
			t.Errorf("permissions.deny %v missing %q", deny, want)
		}
	}
	checks := map[string]any{
		"outputStyle":                   "Explanatory",
		"forceLoginMethod":              "console",
		"strictPluginOnlyCustomization": []any{"skills"},
		"enabledPlugins":                map[string]any{"audit@acme-plugins": true, "risky@acme-plugins": false},
		"statusLine":                    map[string]any{"type": "command", "command": "/opt/halo/statusline.sh", "padding": float64(1)},
		"blockedMarketplaces":           []any{map[string]any{"source": "github", "repo": "untrusted/plugins"}},
		"strictKnownMarketplaces": []any{
			map[string]any{"source": "github", "repo": "acme/plugins", "ref": "v1"},
			map[string]any{"source": "hostPattern", "hostPattern": `^git\.example\.com$`},
		},
	}
	for k, want := range checks {
		if !reflect.DeepEqual(m[k], want) {
			t.Errorf("%s = %#v, want %#v", k, m[k], want)
		}
	}
}

func containsAny(list []any, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestExtensionsEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		mut      func(*policy.Profile)
		wantKey  string
		want     any
		wantWarn string
	}{
		{"subscription login", func(p *policy.Profile) { p.Login = policy.LoginSubscription }, "forceLoginMethod", "claudeai", ""},
		{"blocked beats enabled", func(p *policy.Profile) {
			p.Extensions.Plugins = policy.Plugins{Enabled: []string{"a@m"}, Blocked: []string{"a@m"}}
		}, "enabledPlugins", map[string]any{"a@m": false}, ""},
		{"agents and skills plugin-only", func(p *policy.Profile) { p.Extensions.Subagents.PluginOnly = true },
			"strictPluginOnlyCustomization", []any{"skills", "agents"}, ""},
		{"pluginOnly without allowlist warns", func(p *policy.Profile) { p.Extensions.Marketplaces = nil },
			"strictPluginOnlyCustomization", []any{"skills"}, "pluginOnly without extensions.marketplaces"},
		{"statusLine without padding", func(p *policy.Profile) { p.Extensions.StatusLine.Padding = 0 },
			"statusLine", map[string]any{"type": "command", "command": "/opt/halo/statusline.sh"}, ""},
		{"unset extensions render nothing", func(p *policy.Profile) { p.Extensions = policy.Extensions{}; p.Login = "" },
			"outputStyle", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) { tc.mut(p) }, harness.Linux)
			if err != nil {
				t.Fatal(err)
			}
			if got := settings(t, files)[tc.wantKey]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s = %#v, want %#v", tc.wantKey, got, tc.want)
			}
			if tc.wantWarn != "" && !strings.Contains(strings.Join(warns, "\n"), tc.wantWarn) {
				t.Errorf("warnings %v missing %q", warns, tc.wantWarn)
			}
		})
	}
}

// Nothing in the extensions block may reach a key the unset profile lacks.
func TestExtensionsAbsentWhenUnset(t *testing.T) {
	files, _, err := render(func(p *policy.Profile, _ *policy.Gateway) { p.Extensions = policy.Extensions{}; p.Login = "" }, harness.Linux)
	if err != nil {
		t.Fatal(err)
	}
	m := settings(t, files)
	for _, k := range []string{"strictKnownMarketplaces", "blockedMarketplaces", "enabledPlugins", "strictPluginOnlyCustomization", "outputStyle", "statusLine", "forceLoginMethod"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s rendered for an unset profile", k)
		}
	}
	for _, r := range m["permissions"].(map[string]any)["deny"].([]any) {
		if s, _ := r.(string); strings.HasPrefix(s, "Skill(") || strings.HasPrefix(s, "Agent(") {
			t.Errorf("unexpected rule %q", s)
		}
	}
}
