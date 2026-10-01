package gemini

import (
	"encoding/json"
	"strings"
	"testing"

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

func TestGolden(t *testing.T) {
	for _, os := range []harness.OS{harness.Darwin, harness.Linux, harness.Windows} {
		files, warns, err := render(nil, os)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(files[0].Data, &m); err != nil {
			t.Fatal(err)
		}
		// The gateway's base URL is only honored with gemini-api-key auth (test/uat).
		if got := m["security"].(map[string]any)["auth"].(map[string]any)["enforcedType"]; got != "gemini-api-key" {
			t.Errorf("enforcedType = %v, want gemini-api-key with a gateway", got)
		}
		if (os == harness.Linux) != (len(files) == 2) {
			t.Errorf("%s: files = %d", os, len(files))
		}
		all := strings.Join(warns, "\n")
		for _, want := range []string{`"permissions.allow"`, `"hooks.items"`, `"instructions"`, `"models.allowed"`, "ring/release"} {
			if !strings.Contains(all, want) {
				t.Errorf("%s: missing warning %q", os, want)
			}
		}
		for i, f := range files {
			hutiltest.Golden(t, string(os)+"_"+string(rune('0'+i))+".golden", f.Data)
		}
	}
}

func TestErrorsAndOverride(t *testing.T) {
	if _, _, err := render(func(_ *policy.Profile, g *policy.Gateway) { g.Protocols["gemini-cli"] = "openai-responses" }, harness.Linux); err == nil {
		t.Error("want protocol error")
	}
	if _, _, err := render(func(p *policy.Profile, _ *policy.Gateway) { p.MCP.Servers[1].Command = nil }, harness.Linux); err == nil {
		t.Error("want mcp error")
	}
	files, _, err := render(func(p *policy.Profile, _ *policy.Gateway) {
		p.Harnesses["gemini-cli"] = policy.HarnessSpec{Overrides: map[string]any{"security": map[string]any{"auth": map[string]any{"enforcedType": "oauth-personal"}}}}
	}, harness.Linux)
	if err != nil || !strings.Contains(string(files[0].Data), "enforcedType") {
		t.Errorf("override missing: %v", err)
	}
}

func TestNoGatewayNoEnforcedAuthAndDisableYolo(t *testing.T) {
	p, _ := hutiltest.Fixture()
	files, _, err := Adapter{}.Render(p, harness.Context{OS: harness.Linux})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(files[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	sec := m["security"].(map[string]any)
	// disableBypass -> security.disableYoloMode (honored on 0.34.0; the system
	// file's admin.secureModeEnabled is not: test/uat).
	if sec["disableYoloMode"] != true || m["admin"] != nil || sec["auth"] != nil {
		t.Errorf("settings without a gateway: %s", files[0].Data)
	}
}

func TestGatewayRendersGeminiAPIKeyFromHelper(t *testing.T) {
	files, warns, err := render(func(_ *policy.Profile, g *policy.Gateway) {
		g.Auth.HelperCommand = "/usr/local/bin/acme-token --aud 'x'"
	}, harness.Linux)
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, f := range files {
		if f.Path == "/etc/profile.d/halos-gemini.sh" {
			script = string(f.Data)
		}
	}
	// The helper is shell-quoted into sh -c: never a literal token, never interpolated raw.
	want := `export GEMINI_API_KEY="$(sh -c '/usr/local/bin/acme-token --aud '\''x'\''' 2>/dev/null)"`
	if !strings.Contains(script, want) || !strings.Contains(script, "GOOGLE_GEMINI_BASE_URL=") {
		t.Fatalf("script:\n%s", script)
	}
	for _, w := range warns {
		if strings.Contains(w, "GEMINI_API_KEY is not rendered") {
			t.Errorf("unexpected warning %q", w)
		}
	}

	files, warns, _ = render(func(_ *policy.Profile, g *policy.Gateway) { g.Auth.HelperCommand = "" }, harness.Linux)
	for _, f := range files {
		if strings.Contains(string(f.Data), "GEMINI_API_KEY") {
			t.Errorf("GEMINI_API_KEY rendered without a helper: %s", f.Data)
		}
	}
	if !strings.Contains(strings.Join(warns, "\n"), "GEMINI_API_KEY is not rendered") {
		t.Errorf("want a warning, got %v", warns)
	}
}

// gemini-cli < 0.34.0 posts all OTLP/HTTP signals to the bare endpoint (test/uat).
func TestOTLPHTTPVersionWarning(t *testing.T) {
	for v, want := range map[string]bool{"0.12.0": true, "0.33.9": true, "0.34.0": false} {
		_, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) {
			p.Telemetry.Protocol = "http/protobuf"
			p.Harnesses = map[string]policy.HarnessSpec{name: {Version: v}}
		}, harness.Linux)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(strings.Join(warns, "\n"), "verbatim"); got != want {
			t.Errorf("%s: warning = %v, want %v", v, got, want)
		}
	}
}
