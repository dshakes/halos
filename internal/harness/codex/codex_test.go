package codex

import (
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

func render(mut func(*policy.Profile, *policy.Gateway), os harness.OS) ([]harness.File, []string, error) {
	p, g := hutiltest.Fixture()
	if mut != nil {
		mut(p, g)
	}
	return Adapter{}.Render(p, harness.Context{Gateway: g, Ring: "canary", Release: "sha256:abc", OS: os})
}

func TestGoldenAndSemantics(t *testing.T) {
	files, warns, err := render(nil, harness.Linux)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d", len(files))
	}
	for _, f := range files {
		var m map[string]any
		if err := toml.Unmarshal(f.Data, &m); err != nil {
			t.Fatalf("%s not toml: %v", f.Path, err)
		}
		if strings.Contains(string(f.Data), "danger-full-access") {
			t.Errorf("%s contains danger-full-access", f.Path)
		}
		hutiltest.Golden(t, f.Path[strings.LastIndex(f.Path, "/")+1:], f.Data)
	}
	all := strings.Join(warns, "\n")
	for _, want := range []string{"self-enforce version", `"off" mapped to workspace-write`, `"models.allowed"`, `"permissions.allow"`, `"hooks.items"`, `"egress.allowedDomains"`, `"instructions"`, `"env"`, `"mcp.denied"`, `"telemetry.attributes"`} {
		if !strings.Contains(all, want) {
			t.Errorf("missing warning %q in\n%s", want, all)
		}
	}
	var m map[string]any
	_ = toml.Unmarshal(files[0].Data, &m)
	if m["model_providers"].(map[string]any)["halos"].(map[string]any)["base_url"] != "https://gw.example.com/v1" {
		t.Errorf("base_url: %v", m["model_providers"])
	}
}

func TestErrorsAndWindows(t *testing.T) {
	files, warns, err := render(nil, harness.Windows)
	if err != nil || len(files) != 1 || files[0].Path != requirementsPathWin || !strings.Contains(strings.Join(warns, "\n"), "Windows") {
		t.Errorf("windows: files=%v warns=%v err=%v", files, warns, err)
	}
	for name, mut := range map[string]func(*policy.Profile, *policy.Gateway){
		"protocol": func(_ *policy.Profile, g *policy.Gateway) { g.Protocols["codex"] = "gemini" },
		"mode":     func(p *policy.Profile, _ *policy.Gateway) { p.Permissions.Mode = "bogus" },
		"sandbox":  func(p *policy.Profile, _ *policy.Gateway) { p.Permissions.Sandbox = "danger-full-access" },
		"mcp":      func(p *policy.Profile, _ *policy.Gateway) { p.MCP.Servers[1].Command = nil },
	} {
		if _, _, err := render(mut, harness.Linux); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestInstall(t *testing.T) {
	if got := (Adapter{}).InstallCommand("0.9.0", harness.Linux); got != "npm install -g @openai/codex@0.9.0" {
		t.Error(got)
	}
}

func TestOTLPHTTPProtocol(t *testing.T) {
	for proto, want := range map[string]string{"http/protobuf": "binary", "http/json": "json"} {
		files, _, err := render(func(p *policy.Profile, _ *policy.Gateway) { p.Telemetry.Protocol = proto }, harness.Linux)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := toml.Unmarshal(files[0].Data, &m); err != nil {
			t.Fatal(err)
		}
		h := m["otel"].(map[string]any)["exporter"].(map[string]any)["otlp-http"].(map[string]any)
		if h["protocol"] != want {
			t.Errorf("%s: protocol = %v, want %s", proto, h["protocol"], want)
		}
	}
}
