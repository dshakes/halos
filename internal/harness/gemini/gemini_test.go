package gemini

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/halos-dev/halos/internal/harness"
	"github.com/halos-dev/halos/internal/harness/hutil/hutiltest"
	"github.com/halos-dev/halos/internal/policy"
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
		if _, ok := m["security"]; ok {
			t.Error("security emitted without override")
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
