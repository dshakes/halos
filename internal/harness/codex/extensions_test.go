package codex

import (
	"reflect"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

func decode(t *testing.T, files []harness.File, path string) map[string]any {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			var m map[string]any
			if err := toml.Unmarshal(f.Data, &m); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			return m
		}
	}
	t.Fatalf("no file %s in %v", path, files)
	return nil
}

func TestExtensionsRequirements(t *testing.T) {
	files, warns, err := render(nil, harness.Linux)
	if err != nil {
		t.Fatal(err)
	}
	req := decode(t, files, requirementsPath)
	want := map[string]any{
		"restrict_to_allowed_sources": true,
		"allowed_sources": map[string]any{
			"source_1": map[string]any{"source": "git", "url": "https://github.com/acme/plugins.git", "ref": "v1"},
			"source_2": map[string]any{"source": "host_pattern", "host_pattern": `^git\.example\.com$`},
		},
	}
	if !reflect.DeepEqual(req["marketplaces"], want) {
		t.Errorf("marketplaces = %#v, want %#v", req["marketplaces"], want)
	}
	if !reflect.DeepEqual(req["allowed_login_methods"], []any{"api"}) {
		t.Errorf("allowed_login_methods = %v", req["allowed_login_methods"])
	}
	cfg := decode(t, files, managedConfigPath)
	plugins, _ := cfg["plugins"].(map[string]any)
	if !reflect.DeepEqual(plugins["audit@acme-plugins"], map[string]any{"enabled": true}) ||
		!reflect.DeepEqual(plugins["risky@acme-plugins"], map[string]any{"enabled": false}) {
		t.Errorf("plugins = %v", plugins)
	}
	all := strings.Join(warns, "\n")
	// Everything Codex cannot express must warn, never vanish (invariant 2).
	for _, w := range []string{
		"are rendered as config.toml defaults",
		`"extensions.blockedMarketplaces"`, `"extensions.skills.deny"`, `"extensions.skills.pluginOnly"`,
		`"extensions.subagents.deny"`, `"extensions.outputStyle"`, `"extensions.statusLine"`,
	} {
		if !strings.Contains(all, w) {
			t.Errorf("missing warning %q in\n%s", w, all)
		}
	}
}

func TestExtensionsMarketplaceSources(t *testing.T) {
	tests := []struct {
		name     string
		mkts     []policy.Marketplace
		wantSrcs int
		wantWarn string
	}{
		{"git url", []policy.Marketplace{{Source: policy.MarketplaceGit, URL: "https://git.example.com/p.git", Ref: "main"}}, 1, ""},
		{"url source skipped with warning", []policy.Marketplace{
			{Source: policy.MarketplaceURL, URL: "https://x.example.com/m.json"},
			{Source: policy.MarketplaceGitHub, Repo: "a/b"},
		}, 1, `marketplace source "url" has no requirements.toml equivalent`},
		{"nothing expressible renders no restriction", []policy.Marketplace{{Source: policy.MarketplaceURL, URL: "https://x.example.com/m.json"}}, 0, "marketplace restriction not rendered"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) { p.Extensions.Marketplaces = tc.mkts }, harness.Linux)
			if err != nil {
				t.Fatal(err)
			}
			mk, _ := decode(t, files, requirementsPath)["marketplaces"].(map[string]any)
			srcs, _ := mk["allowed_sources"].(map[string]any)
			if len(srcs) != tc.wantSrcs {
				t.Errorf("sources = %v, want %d", srcs, tc.wantSrcs)
			}
			if tc.wantSrcs == 0 && mk != nil {
				t.Errorf("restrict_to_allowed_sources with no sources would lock out every marketplace: %v", mk)
			}
			if tc.wantWarn != "" && !strings.Contains(strings.Join(warns, "\n"), tc.wantWarn) {
				t.Errorf("warnings %v missing %q", warns, tc.wantWarn)
			}
		})
	}
}

func TestExtensionsLoginAndWindows(t *testing.T) {
	files, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) { p.Login = policy.LoginSubscription }, harness.Windows)
	if err != nil {
		t.Fatal(err)
	}
	req := decode(t, files, requirementsPathWin)
	if !reflect.DeepEqual(req["allowed_login_methods"], []any{"chatgpt"}) {
		t.Errorf("allowed_login_methods = %v", req["allowed_login_methods"])
	}
	for _, f := range files {
		if f.Path == managedConfigPath {
			t.Errorf("managed_config.toml rendered on Windows")
		}
	}
	if !strings.Contains(strings.Join(warns, "\n"), "not rendered on Windows (no system-wide managed_config.toml)") {
		t.Errorf("no Windows plugin warning in %v", warns)
	}
}
