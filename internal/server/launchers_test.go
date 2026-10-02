package server

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// An enabled launcher the server cannot run is never offered: developers do not
// see it, admins see what is missing, and the API still answers 409.
func TestLauncherAvailability(t *testing.T) {
	bare := newEnv(t, func(c *Config) { c.Portal = Portal{} })
	me := decode[Me](t, bare.as(dev, "GET", "/api/v1/me", ""))
	if len(me.Launchers) != 0 || me.LauncherSetup != nil {
		t.Fatalf("unconfigured launchers offered to a developer: %v %v", me.Launchers, me.LauncherSetup)
	}
	if l := decode[Catalog](t, bare.as(dev, "GET", "/api/v1/catalog", "")).Launchers; len(l) != 0 {
		t.Errorf("catalog launchers: %v", l)
	}
	setup := decode[Me](t, bare.as(admin, "GET", "/api/v1/me", "")).LauncherSetup
	if len(setup) != 4 || setup[1].Launcher != "codespaces" || setup[1].Missing != "codespacesURL" {
		t.Fatalf("admin setup notes: %+v", setup)
	}
	w := bare.as(dev, "POST", "/api/v1/launch/codespaces", "")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "launcher not configured: codespacesURL") {
		t.Errorf("API clients keep the 409: %d %s", w.Code, w.Body.String())
	}

	// A plain-HTTP (dev) setup: the laptop works, the Dev Container Feature cannot (https + TLS only).
	plain := newEnv(t, func(c *Config) {
		c.Portal.HalodURL, c.Portal.RegistryPlainHTTP, c.Portal.HalodSHA256["linux-arm64"] = "http://localhost:18082/halod-{os}-{arch}", true, sha
	})
	m := decode[Me](t, plain.as(admin, "GET", "/api/v1/me", ""))
	if !slices.Contains(m.Launchers, "laptop") || slices.Contains(m.Launchers, "devcontainer") || len(m.LauncherSetup) != 1 ||
		!strings.Contains(m.LauncherSetup[0].Missing, "https halodURL") || !strings.Contains(m.LauncherSetup[0].Missing, "TLS registry") {
		t.Fatalf("plain-http portal: %+v", m)
	}
}

// The devcontainer snippet only uses options the Feature declares, with the declared types.
func TestDevcontainerSnippetMatchesFeature(t *testing.T) {
	var feat struct {
		Options map[string]struct {
			Type string `json:"type"`
		} `json:"options"`
	}
	b, err := os.ReadFile("../../features/halos/devcontainer-feature.json")
	if err != nil || json.Unmarshal(b, &feat) != nil {
		t.Fatalf("feature: %v", err)
	}
	e := newEnv(t, nil)
	var spec struct {
		Features map[string]map[string]any `json:"features"`
	}
	if err := json.Unmarshal([]byte(decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/devcontainer", "")).Snippet), &spec); err != nil {
		t.Fatal(err)
	}
	for k, v := range spec.Features["ghcr.io/acme/features/halos:0"] {
		var got string
		switch v.(type) {
		case string:
			got = "string"
		case bool:
			got = "boolean"
		}
		if got == "" || feat.Options[k].Type != got {
			t.Errorf("option %q=%v: feature declares %q", k, v, feat.Options[k].Type)
		}
	}
}

// Each harness card lists only the aliases its wire can reach (the check `halo validate` runs).
func TestHarnessModelsFollowWire(t *testing.T) {
	gw := &policy.Gateway{
		Models: map[string]policy.ModelRoute{
			"sonnet":         {Upstream: "anthropic", Model: "claude-sonnet"},
			"codex-default":  {Upstream: "openai", Model: "gpt"},
			"gemini-default": {Upstream: "google", Model: "gemini"},
		},
		Upstreams: map[string]policy.Upstream{"anthropic": {Kind: "anthropic"}, "openai": {Kind: "openai"}, "google": {Kind: "gemini"}},
	}
	p := &policy.Profile{Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: "1"}, "codex": {Version: "1", Model: "codex-default"}}}
	p.Models.Default = "sonnet"
	ps := summarize(p, gw)
	if got := ps.HarnessModels["claude-code"]; !slices.Equal(got, []string{"sonnet"}) {
		t.Errorf("claude-code models: %v", got)
	}
	if got := ps.HarnessModels["codex"]; !slices.Equal(got, []string{"codex-default"}) {
		t.Errorf("codex models: %v", got)
	}
	if ps.HarnessDefault["codex"] != "codex-default" || ps.HarnessDefault["claude-code"] != "sonnet" {
		t.Errorf("defaults: %v", ps.HarnessDefault)
	}
}
