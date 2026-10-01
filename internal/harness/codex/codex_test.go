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
	if len(files) != 3 || files[1].Path != profileD {
		t.Fatalf("files = %d", len(files))
	}
	hutiltest.Golden(t, "halos-codex.sh", files[1].Data)
	for _, f := range []harness.File{files[0], files[2]} {
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
	for _, want := range []string{"self-enforce version", `"off" mapped to workspace-write`, `"models.allowed"`, `"permissions.allow"`, `"hooks.items"`, `"egress.allowedDomains"`, `"instructions"`, `"env"`, `"mcp.denied"`} {
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
		if h["endpoint"] != "https://otel.example.com:4317/v1/logs" {
			t.Errorf("%s: endpoint = %v, want the /v1/logs signal URL", proto, h["endpoint"])
		}
		if h["protocol"] != want {
			t.Errorf("%s: protocol = %v, want %s", proto, h["protocol"], want)
		}
	}
}

// Real codex 0.58.0 refuses to start without otel.exporter.*.headers and reads
// no requirements.toml (test/uat); 0.77.0 added allowed_sandbox_modes.
func TestOTLPHeadersAndRequirementsVersion(t *testing.T) {
	for _, proto := range []string{"grpc", "http/protobuf"} {
		files, _, err := render(func(p *policy.Profile, _ *policy.Gateway) { p.Telemetry.Protocol = proto }, harness.Linux)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := toml.Unmarshal(files[0].Data, &m); err != nil {
			t.Fatal(err)
		}
		for _, e := range m["otel"].(map[string]any)["exporter"].(map[string]any) {
			if _, ok := e.(map[string]any)["headers"]; !ok {
				t.Errorf("%s: exporter has no headers table:\n%s", proto, files[0].Data)
			}
		}
	}
	for _, v := range []string{"0.58.0", "0.77.0", "0.98.0", "0.99.0", "latest"} {
		_, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) {
			p.Harnesses = map[string]policy.HarnessSpec{name: {Version: v}}
		}, harness.Linux)
		if err != nil {
			t.Fatal(err)
		}
		exec := strings.Contains(strings.Join(warns, "\n"), "refuses to run `codex exec`")
		if wantExec := v == "0.77.0" || v == "0.98.0"; exec != wantExec {
			t.Errorf("version %s: codex exec warning = %v, want %v", v, exec, wantExec)
		}
	}
	for v, want := range map[string]bool{"0.58.0": true, "0.76.9": true, "0.77.0": false, "1.2.0": false, "latest": false} {
		_, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) {
			p.Harnesses = map[string]policy.HarnessSpec{name: {Version: v}}
		}, harness.Linux)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(strings.Join(warns, "\n"), "does not enforce requirements.toml"); got != want {
			t.Errorf("version %s: warning = %v, want %v", v, got, want)
		}
	}
}

// codex 0.77.0 refuses to start when allowed_sandbox_modes lacks read-only (test/uat).
func TestAllowedSandboxModesIncludeReadOnly(t *testing.T) {
	for sb, want := range map[string]string{"workspace-write": "read-only,workspace-write", "read-only": "read-only", "off": "read-only,workspace-write"} {
		files, _, err := render(func(p *policy.Profile, _ *policy.Gateway) { p.Permissions.Sandbox = sb }, harness.Linux)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := toml.Unmarshal(files[len(files)-1].Data, &m); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, x := range m["allowed_sandbox_modes"].([]any) {
			got = append(got, x.(string))
		}
		if strings.Join(got, ",") != want {
			t.Errorf("sandbox %s: allowed_sandbox_modes = %v, want %s", sb, got, want)
		}
	}
}

// harnesses.codex.model replaces the shared models.default for codex only.
func TestHarnessModel(t *testing.T) {
	files, _, err := render(func(p *policy.Profile, _ *policy.Gateway) {
		p.Harnesses = map[string]policy.HarnessSpec{name: {Version: "0.99.0", Model: "codex-default"}}
	}, harness.Linux)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := toml.Unmarshal(files[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	if m["model"] != "codex-default" {
		t.Errorf("model = %v, want codex-default", m["model"])
	}
}
