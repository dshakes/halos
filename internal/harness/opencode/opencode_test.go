package opencode

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

func render(t *testing.T, p *policy.Profile, c harness.Context) ([]harness.File, string) {
	t.Helper()
	files, warns, err := Adapter{}.Render(p, c)
	if err != nil {
		t.Fatal(err)
	}
	return files, strings.Join(warns, "\n")
}

func decode(t *testing.T, f harness.File) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(f.Data, &m); err != nil {
		t.Fatalf("%s: %v\n%s", f.Path, err, f.Data)
	}
	return m
}

func TestRenderGolden(t *testing.T) {
	for _, tc := range []struct {
		os     harness.OS
		cfg    string
		instr  string
		golden string
	}{
		{harness.Linux, "/etc/opencode/opencode.json", "/etc/opencode/halos-instructions.md", "linux_opencode.json"},
		{harness.Darwin, "/Library/Application Support/opencode/opencode.json", "/Library/Application Support/opencode/halos-instructions.md", "darwin_opencode.json"},
		{harness.Windows, `C:\ProgramData\opencode\opencode.json`, `C:\ProgramData\opencode\halos-instructions.md`, "windows_opencode.json"},
	} {
		t.Run(string(tc.os), func(t *testing.T) {
			p, g := hutiltest.Fixture()
			p.Harnesses["opencode"] = policy.HarnessSpec{Version: "1.19.3", Model: "halo-haiku"}
			files, warns := render(t, p, harness.Context{Gateway: g, Ring: "ring1", Release: "v7", OS: tc.os})
			if len(files) != 2 || files[0].Path != tc.cfg || files[1].Path != tc.instr {
				t.Fatalf("files = %v", files)
			}
			if string(files[1].Data) != p.Instructions {
				t.Errorf("instructions = %q", files[1].Data)
			}
			hutiltest.Golden(t, tc.golden, files[0].Data)
			for _, want := range []string{
				"cannot self-enforce version; halod enforces",
				`"hooks.items" is not supported`, `"telemetry.enabled" is not supported`, `"egress.allowedDomains" is not supported`, `"env" is not supported`,
				`"permissions.mode" is not supported`, `"permissions.sandbox" is not supported`, `"mcp.managedOnly" is not supported`,
				"permissions.disableBypass cannot be enforced", "OPENCODE_PERMISSION", "no MCP allowlist",
				"gateway.auth.helperCommand is not supported",
			} {
				if !strings.Contains(warns, want) {
					t.Errorf("missing warning %q in\n%s", want, warns)
				}
			}
		})
	}
}

func TestRenderedShape(t *testing.T) {
	p, g := hutiltest.Fixture()
	p.Harnesses["opencode"] = policy.HarnessSpec{Version: "1.19.3", Model: "halo-haiku"}
	files, _ := render(t, p, harness.Context{Gateway: g, Ring: "ring1", Release: "v7", OS: harness.Linux})
	m := decode(t, files[0])

	if m["model"] != "halos/halo-haiku" || m["autoupdate"] != false {
		t.Errorf("model/autoupdate = %v / %v", m["model"], m["autoupdate"])
	}
	if got := m["enabled_providers"].([]any); len(got) != 1 || got[0] != "halos" {
		t.Errorf("enabled_providers = %v", got)
	}
	prov := m["provider"].(map[string]any)["halos"].(map[string]any)
	opts := prov["options"].(map[string]any)
	if prov["npm"] != "@ai-sdk/anthropic" || opts["baseURL"] != "https://gw.example.com/v1" || opts["apiKey"] != "{env:HALO_GATEWAY_TOKEN}" {
		t.Errorf("provider = %v", prov)
	}
	hdr := opts["headers"].(map[string]any)
	if hdr["x-halo-ring"] != "ring1" || hdr["x-halo-release"] != "v7" {
		t.Errorf("headers = %v", hdr)
	}
	models := prov["models"].(map[string]any)
	if len(models) != 2 || models["halo-sonnet"] == nil || models["halo-haiku"] == nil {
		t.Errorf("models = %v", models)
	}
	mcp := m["mcp"].(map[string]any)
	if mcp["docs"].(map[string]any)["type"] != "remote" || mcp["lint"].(map[string]any)["type"] != "local" || mcp["filesystem"].(map[string]any)["enabled"] != false {
		t.Errorf("mcp = %v", mcp)
	}
	if ins := m["instructions"].([]any); len(ins) != 1 || ins[0] != "/etc/opencode/halos-instructions.md" {
		t.Errorf("instructions = %v", ins)
	}
}

// OpenCode applies permission rules in key order, last match wins, so the
// rendered order (baseline, allow, ask, deny) is part of the meaning.
func TestPermissionOrderDenyWins(t *testing.T) {
	p := &policy.Profile{Permissions: policy.Permissions{
		Allow: []string{"Bash(go test:*)", "Bash(rm -rf build)"},
		Ask:   []string{"Bash(make deploy)"},
		Deny:  []string{"Bash(rm:*)", "Read(./.env)", "Edit(./secrets/**)", "Write(**/*.key)", "Grep", "Read(~/.ssh/**)", "Edit(/etc/**)"},
	}}
	files, warns := render(t, p, harness.Context{OS: harness.Linux})
	data := string(files[0].Data)
	if !strings.Contains(warns, "no gateway configured") {
		t.Errorf("warns = %s", warns)
	}
	order := []string{`"*": "ask"`, `"go test": "allow"`, `"go test *": "allow"`, `"rm -rf build": "allow"`, `"make deploy": "ask"`, `"rm": "deny"`, `"rm *": "deny"`}
	last := -1
	for _, want := range order {
		i := strings.Index(data, want)
		if i < 0 || i < last {
			t.Fatalf("%q out of order or missing (at %d, previous %d) in\n%s", want, i, last, data)
		}
		last = i
	}
	m := decode(t, files[0])["permission"].(map[string]any)
	if r := m["read"].(map[string]any); r["*"] != nil || r[".env"] != "deny" {
		t.Errorf("read = %v (want only .env deny: reads stay at OpenCode's default)", r)
	}
	if e := m["edit"].(map[string]any); e["*"] != "ask" || e["secrets/**"] != "deny" || e["**/*.key"] != "deny" || e["*.key"] != "deny" || len(e) != 4 {
		t.Errorf("edit = %v", e)
	}
	// home and absolute paths are invisible to read/edit patterns (worktree-relative)
	if x := m["external_directory"].(map[string]any); x["~/.ssh/**"] != "deny" || x["/etc/**"] != "deny" || len(x) != 2 {
		t.Errorf("external_directory = %v", x)
	}
	if g := m["grep"].(map[string]any); g["*"] != "deny" {
		t.Errorf("grep = %v", g)
	}
}

// A pattern listed in both allow and deny ends up denied.
func TestPermissionDuplicatePatternDenied(t *testing.T) {
	p := &policy.Profile{Permissions: policy.Permissions{Allow: []string{"Bash(curl)"}, Deny: []string{"Bash(curl)"}}}
	files, _ := render(t, p, harness.Context{OS: harness.Linux})
	b := decode(t, files[0])["permission"].(map[string]any)["bash"].(map[string]any)
	if b["curl"] != "deny" {
		t.Errorf("bash = %v", b)
	}
}

func TestPermissionUnmappedRuleWarns(t *testing.T) {
	for _, rule := range []string{"WebFetch(domain:example.com)", "mcp__github__create_issue", "Bash(unclosed", "(x)"} {
		p := &policy.Profile{Permissions: policy.Permissions{Deny: []string{rule}}}
		files, warns := render(t, p, harness.Context{OS: harness.Linux})
		if !strings.Contains(warns, "permission rule "+`"`+rule+`"`+" has no verified OpenCode equivalent") {
			t.Errorf("%s: warns = %s", rule, warns)
		}
		if len(files) != 0 {
			t.Errorf("%s: rendered %s with nothing to render", rule, files[0].Data)
		}
	}
}

func TestNeverBypass(t *testing.T) {
	p, g := hutiltest.Fixture()
	p.Permissions.Allow = append(p.Permissions.Allow, "Bash")
	files, _ := render(t, p, harness.Context{Gateway: g, OS: harness.Linux})
	m := decode(t, files[0])
	if _, ok := m["permission"].(string); ok {
		t.Errorf("permission = %v", m["permission"])
	}
	perm := m["permission"].(map[string]any)
	if perm["*"] != nil {
		t.Errorf("top-level * rule: %v", perm)
	}
	if strings.Contains(string(files[0].Data), "dangerously") || strings.Contains(string(files[0].Data), "bypassPermissions") {
		t.Errorf("bypass in output:\n%s", files[0].Data)
	}
}

func TestProtocols(t *testing.T) {
	for _, tc := range []struct{ proto, pkg string }{
		{"", "@ai-sdk/anthropic"},
		{"anthropic-messages", "@ai-sdk/anthropic"},
		{"openai-responses", "@ai-sdk/openai"},
	} {
		p, g := hutiltest.Fixture()
		if tc.proto != "" {
			g.Protocols["opencode"] = tc.proto
		}
		files, _ := render(t, p, harness.Context{Gateway: g, OS: harness.Linux})
		got := decode(t, files[0])["provider"].(map[string]any)["halos"].(map[string]any)["npm"]
		if got != tc.pkg {
			t.Errorf("protocol %q: npm = %v, want %s", tc.proto, got, tc.pkg)
		}
	}
	for _, bad := range []string{"gemini", "bedrock-invoke"} {
		p, g := hutiltest.Fixture()
		g.Protocols["opencode"] = bad
		if _, _, err := (Adapter{}).Render(p, harness.Context{Gateway: g, OS: harness.Linux}); err == nil || !strings.Contains(err.Error(), "unsupported gateway protocol") {
			t.Errorf("protocol %q: err = %v", bad, err)
		}
	}
}

func TestExternalGatewayUsesProviderModelID(t *testing.T) {
	p, g := hutiltest.Fixture()
	g.Engine = policy.EngineExternal
	g.Models = map[string]policy.ModelRoute{
		"halo-sonnet": {Upstream: "x", Model: "claude-sonnet-5-5"},
		"halo-haiku":  {Upstream: "x", Model: "claude-haiku-5-5"},
	}
	files, _ := render(t, p, harness.Context{Gateway: g, OS: harness.Linux})
	m := decode(t, files[0])
	if m["model"] != "halos/claude-sonnet-5-5" {
		t.Errorf("model = %v", m["model"])
	}
	models := m["provider"].(map[string]any)["halos"].(map[string]any)["models"].(map[string]any)
	if !slices.Equal(sortedKeys(models), []string{"claude-haiku-5-5", "claude-sonnet-5-5"}) {
		t.Errorf("models = %v", models)
	}
}

func sortedKeys(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func TestWithoutGateway(t *testing.T) {
	for _, tc := range []struct {
		name  string
		model string
		want  string // substring of the rendered config, "" = no config at all
		warn  string
	}{
		{"alias", "halo-sonnet", "", `models.default "halo-sonnet" is not rendered without a gateway`},
		{"provider/model", "anthropic/claude-sonnet-5-5", `"model": "anthropic/claude-sonnet-5-5"`, "no gateway configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &policy.Profile{Models: policy.Models{Default: tc.model, Allowed: []string{tc.model}}}
			files, warns := render(t, p, harness.Context{Ring: "ring1", OS: harness.Linux})
			if !strings.Contains(warns, tc.warn) || !strings.Contains(warns, "models.allowed is not rendered without a gateway") || !strings.Contains(warns, "ring/release request headers need a gateway") {
				t.Errorf("warns = %s", warns)
			}
			switch {
			case tc.want == "" && len(files) != 0:
				t.Errorf("rendered %s", files[0].Data)
			case tc.want != "" && (len(files) != 1 || !strings.Contains(string(files[0].Data), tc.want)):
				t.Errorf("files = %v", files)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*policy.Profile, *policy.Gateway)
		want   string
	}{
		{"mcp neither", func(p *policy.Profile, _ *policy.Gateway) { p.MCP.Servers = []policy.MCPServer{{Name: "x"}} }, "neither url nor command"},
		{"mcp defined and denied", func(p *policy.Profile, _ *policy.Gateway) { p.MCP.Denied = []string{"docs"} }, "both defined and denied"},
		{"gateway without model", func(p *policy.Profile, _ *policy.Gateway) { p.Models = policy.Models{} }, "names no model"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, g := hutiltest.Fixture()
			tc.mutate(p, g)
			if _, _, err := (Adapter{}).Render(p, harness.Context{Gateway: g, OS: harness.Linux}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestOverridesMergedLast(t *testing.T) {
	p, g := hutiltest.Fixture()
	p.Harnesses["opencode"] = policy.HarnessSpec{Overrides: map[string]any{"username": "acme", "compaction": map[string]any{"auto": false}}}
	files, _ := render(t, p, harness.Context{Gateway: g, OS: harness.Linux})
	m := decode(t, files[0])
	if m["username"] != "acme" || m["compaction"].(map[string]any)["auto"] != false {
		t.Errorf("overrides not merged: %v", m)
	}
}

func TestMeta(t *testing.T) {
	m := Adapter{}.Meta()
	if m.Binary != "opencode" || m.Installer != harness.InstallerNPM || m.NPMPackage != "opencode-ai" || !slices.Equal(m.UAPrefixes, []string{"opencode/"}) {
		t.Errorf("meta = %+v", m)
	}
	if got := (Adapter{}).InstallCommand("1.19.3", harness.Linux); got != "npm install -g opencode-ai@1.19.3" {
		t.Errorf("install = %q", got)
	}
	// every file the adapter renders must sit under a ManagedDirs entry
	p, g := hutiltest.Fixture()
	for _, os := range []harness.OS{harness.Darwin, harness.Linux, harness.Windows} {
		files, _ := render(t, p, harness.Context{Gateway: g, OS: os})
		for _, f := range files {
			ok := false
			for _, d := range m.ManagedDirs[os] {
				ok = ok || strings.HasPrefix(f.Path, d)
			}
			if !ok {
				t.Errorf("%s: %s is outside ManagedDirs %v", os, f.Path, m.ManagedDirs[os])
			}
		}
	}
}
