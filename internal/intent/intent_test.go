package intent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/dshakes/halos/internal/harness/all" // register adapters for release.Build
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

const simpleRoot = `apiVersion: halos.dev/v1
kind: Halos
org: acme
tools: {claude-code: 2.1.280, codex: {version: 0.99.0, model: codex}}
provider: anthropic
models:
  default: claude-sonnet-4-5
  strong: claude-opus-4-1
  codex: openai/gpt-5-codex
gateway: https://ai.acme.example
identity: {issuer: https://login.acme.example, audience: halos, adminGroups: [ai-platform]}
`

var (
	relDigest  = "sha256:" + strings.Repeat("b", 64)
	baseDigest = "sha256:" + strings.Repeat("a", 64)
)

func simpleRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policy.RootFile), []byte(simpleRoot), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// copyRepo copies a policy example into a temp dir.
func copyRepo(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	return dst
}

func open(t *testing.T, dir string) *Repo {
	t.Helper()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// applyValid validates c (no errors allowed), applies it and reloads.
func applyValid(t *testing.T, c *Change) *Repo {
	t.Helper()
	issues, err := c.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if policy.HasErrors(issues) {
		t.Fatalf("change does not validate: %v\n%s", issues, c.Patch())
	}
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	return open(t, c.Dir)
}

func paths(c *Change) []string { return sortedKeys(c.Files) }

func TestUpgradeStartSimple(t *testing.T) {
	dir := simpleRepo(t)
	r := open(t, dir)
	c, err := r.UpgradeStart(Upgrade{Tool: "claude-code", Version: "2.1.300", Release: relDigest, Baseline: baseDigest})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"experiments/claude-code-2.1.300-canary.yaml", "profiles/claude-code-2.1.300.yaml",
		"rings/ring0-team.yaml", "rings/ring1-canary.yaml", "rings/ring2-early.yaml", "rings/ring3-ga.yaml", "rollouts/claude-code-2.1.300.yaml"}
	if got := paths(c); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v", got, want)
	}
	created, changed := c.Paths()
	if len(created) != len(want) || len(changed) != 0 {
		t.Fatalf("created %v changed %v", created, changed)
	}
	if p := c.Patch(); !strings.Contains(p, "+kind: Rollout") || !strings.Contains(p, "+++ b/rollouts/claude-code-2.1.300.yaml") {
		t.Fatalf("dry-run patch:\n%s", p)
	}
	if _, err := os.Stat(filepath.Join(dir, "rollouts")); err == nil {
		t.Fatal("UpgradeStart wrote files before Apply")
	}
	after := applyValid(t, c)
	ro := after.Org.Rollouts[0]
	var steps []string
	for _, s := range ro.Steps {
		steps = append(steps, s.Name)
	}
	if got := strings.Join(steps, ","); got != "ring0-team,canary-5,canary-25,canary-50,ring1-canary,ring2-early,ring3-ga" {
		t.Errorf("steps = %s", got)
	}
	if ro.Experiment != "claude-code-2.1.300-canary" || ro.Change.Release != relDigest || ro.Baseline.Release != baseDigest {
		t.Errorf("rollout = %+v", ro)
	}
	for _, g := range after.Org.Rings { // ring stubs keep the generated membership
		if g.Profile != policy.SimpleProfile {
			t.Errorf("ring %s lost its profile: %+v", g.Name, g)
		}
	}
	if _, err := after.UpgradeStart(Upgrade{Tool: "claude-code", Version: "2.1.300", Release: relDigest, Baseline: baseDigest}); err == nil {
		t.Error("duplicate rollout accepted")
	}
}

func TestUpgradeStartFastPresetNoExperiment(t *testing.T) {
	dir := simpleRepo(t)
	if err := os.WriteFile(filepath.Join(dir, policy.RootFile), []byte(simpleRoot+"rollout: fast\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := open(t, dir).UpgradeStart(Upgrade{Tool: "codex", Version: "0.77.0", Release: relDigest, Baseline: baseDigest})
	if err != nil {
		t.Fatal(err)
	}
	ro := applyValid(t, c).Org.Rollouts[0]
	if ro.Experiment != "" || len(ro.Steps) != 2 || !ro.Steps[1].Gates.Approval {
		t.Errorf("fast rollout = %+v", ro)
	}
}

func TestUpgradeStartFullMode(t *testing.T) {
	dir := copyRepo(t, "../../examples/acme-corp")
	c, err := open(t, dir).UpgradeStart(Upgrade{Tool: "claude-code", Version: "2.1.310", Release: relDigest, Baseline: baseDigest})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths(c) {
		if strings.HasPrefix(p, "rings/") {
			t.Errorf("full mode wrote ring stub %s; the rings already exist", p)
		}
	}
	applyValid(t, c)
	if !strings.Contains(strings.Join(c.Notes, "\n"), "profile engineering harnesses.claude-code.version") {
		t.Errorf("notes: %v", c.Notes)
	}
}

func TestUpgradeStartErrors(t *testing.T) {
	r := open(t, simpleRepo(t))
	tests := []struct {
		name string
		u    Upgrade
		want string
	}{
		{"bad release", Upgrade{Tool: "claude-code", Version: "2.1.300", Release: "latest", Baseline: baseDigest}, "--release"},
		{"bad baseline", Upgrade{Tool: "claude-code", Version: "2.1.300", Release: relDigest, Baseline: "sha256:abc"}, "--baseline"},
		{"same digests", Upgrade{Tool: "claude-code", Version: "2.1.300", Release: relDigest, Baseline: relDigest}, "is the baseline"},
		{"not enabled", Upgrade{Tool: "gemini-cli", Version: "0.13.0", Release: relDigest, Baseline: baseDigest}, "not enabled"},
		{"same version", Upgrade{Tool: "claude-code", Version: "2.1.280", Release: relDigest, Baseline: baseDigest}, "already at"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.UpgradeStart(tt.u); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestSwitchModel(t *testing.T) {
	t.Run("in place simple", func(t *testing.T) {
		c, err := open(t, simpleRepo(t)).SwitchModel(ModelSwitch{Alias: "default", Model: "claude-sonnet-5"})
		if err != nil {
			t.Fatal(err)
		}
		if got := paths(c); len(got) != 1 || got[0] != policy.RootFile {
			t.Fatalf("files = %v", got)
		}
		if !strings.Contains(string(c.Files[policy.RootFile]), "identity: {issuer:") {
			t.Error("halos.yaml rewritten beyond the edited value")
		}
		if m := applyValid(t, c).Org.Gateway.Models["default"]; m.Model != "claude-sonnet-5" || m.Upstream != "anthropic" {
			t.Errorf("route = %+v", m)
		}
	})
	t.Run("in place default provider prefix", func(t *testing.T) {
		c, err := open(t, simpleRepo(t)).SwitchModel(ModelSwitch{Alias: "strong", Model: "anthropic/claude-opus-5"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(c.Files[policy.RootFile]), "strong: claude-opus-5\n") {
			t.Errorf("default-provider prefix not dropped:\n%s", c.Files[policy.RootFile])
		}
	})
	t.Run("canary simple", func(t *testing.T) {
		c, err := open(t, simpleRepo(t)).SwitchModel(ModelSwitch{Alias: "strong", Model: "claude-opus-5", Canary: true})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(paths(c), ","); got != "experiments/strong-claude-opus-5.yaml,gateway.yaml,rollouts/strong-claude-opus-5.yaml" {
			t.Fatalf("files = %s", got)
		}
		if gw := string(c.Files["gateway.yaml"]); !strings.Contains(gw, "  "+policy.LabelGeneratedBy+": "+policy.GeneratedFor("strong-claude-opus-5")+"\n") {
			t.Errorf("gateway override not labelled for its rollout:\n%s", gw)
		}
		after := applyValid(t, c)
		ro := after.Org.Rollouts[0]
		if ro.Axis != policy.AxisTraffic || ro.Change.Alias != "strong" || !ro.Steps[len(ro.Steps)-1].Gates.Approval {
			t.Errorf("rollout = %+v", ro)
		}
		if g := after.Org.Gateway; g.BaseURL != "https://ai.acme.example" || g.Models["strong"].Model != "claude-opus-4-1" {
			t.Errorf("gateway stub changed the effective route: %+v", g.Models)
		}
	})
	t.Run("in place full mode", func(t *testing.T) {
		c, err := open(t, copyRepo(t, "../../examples/acme-corp")).SwitchModel(ModelSwitch{Alias: "haiku", Model: "claude-haiku-5"})
		if err != nil {
			t.Fatal(err)
		}
		if m := applyValid(t, c).Org.Gateway.Models["haiku"]; m.Model != "claude-haiku-5" {
			t.Errorf("route = %+v", m)
		}
	})
	for name, m := range map[string]ModelSwitch{
		"unknown alias":    {Alias: "nope", Model: "x"},
		"unknown upstream": {Alias: "default", Model: "bedrock/x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := open(t, simpleRepo(t)).SwitchModel(m); err == nil {
				t.Fatal("want error")
			}
		})
	}
	t.Run("failover in full mode", func(t *testing.T) {
		_, err := open(t, copyRepo(t, "../../examples/acme-corp")).SwitchModel(ModelSwitch{Alias: "opus", Model: "x"})
		if err == nil || !strings.Contains(err.Error(), "failover") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestEnable(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	mcp := &policy.MCPServer{Name: "github", URL: "https://api.githubcopilot.com/mcp/", Headers: map[string]string{"Authorization": "Bearer ${GITHUB_MCP_TOKEN}"}}
	hook := &policy.Hook{Event: "PostToolUse", Matcher: "Edit|Write", Command: "/usr/local/bin/fmt"}
	for _, tt := range []struct {
		name string
		e    Enable
		rule func(policy.ToggleRule) bool
	}{
		{"percent", Enable{MCP: mcp, For: "10%"}, func(r policy.ToggleRule) bool { return r.Percent != nil && *r.Percent == 10 }},
		{"ring", Enable{MCP: mcp, For: "ring1-canary"}, func(r policy.ToggleRule) bool { return len(r.Rings) == 1 && r.Rings[0] == "ring1-canary" }},
		{"group", Enable{Name: "fmt", Hook: hook, For: "group:platform-eng"}, func(r policy.ToggleRule) bool { return len(r.Groups) == 1 && r.Groups[0] == "platform-eng" }},
		{"user", Enable{Name: "fmt", Hook: hook, For: "user:alice@acme.example"}, func(r policy.ToggleRule) bool { return len(r.Users) == 1 && r.Users[0] == "alice@acme.example" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.e.Now = now
			c, err := open(t, simpleRepo(t)).Enable(tt.e)
			if err != nil {
				t.Fatal(err)
			}
			tg := applyValid(t, c).Org.Toggles[0]
			if tg.Owner != "ai-platform" || tg.Expires != "2026-12-29" || len(tg.Client.Harnesses) != 2 || !tt.rule(tg.Rules[0]) {
				t.Errorf("toggle = %+v rules %+v", tg, tg.Rules)
			}
		})
	}
	t.Run("all simple twice", func(t *testing.T) {
		dir := simpleRepo(t)
		c, err := open(t, dir).Enable(Enable{Name: "fmt", Hook: hook, For: "all", Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if got := paths(c); len(got) != 1 || got[0] != "profiles/default.yaml" {
			t.Fatalf("files = %v", got)
		}
		r := applyValid(t, c)
		if c, err = r.Enable(Enable{MCP: mcp, Now: now}); err != nil {
			t.Fatal(err)
		}
		if _, changed := c.Paths(); len(changed) != 1 {
			t.Fatalf("second enable should update the stub, got %v", changed)
		}
		p := applyValid(t, c).Org.Profiles[policy.SimpleProfile]
		if len(p.Hooks.Hooks) != 1 || len(p.MCP.Servers) != 1 || !p.MCP.ManagedOnly || !p.Permissions.DisableBypass {
			t.Errorf("profile = %+v", p)
		}
		if _, err := open(t, dir).Enable(Enable{MCP: mcp, Now: now}); err == nil {
			t.Error("duplicate server accepted")
		}
	})
	t.Run("all full mode keeps inherited servers", func(t *testing.T) {
		c, err := open(t, copyRepo(t, "../../examples/acme-corp")).Enable(Enable{MCP: &policy.MCPServer{Name: "wiki", URL: "https://wiki.acme.example/mcp"}, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		p, err := applyValid(t, c).Org.ResolveProfile("engineering")
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, s := range p.MCP.Servers {
			names = append(names, s.Name)
		}
		if got := strings.Join(names, ","); got != "acme-docs,acme-tickets,wiki" {
			t.Errorf("servers = %s", got)
		}
	})
	for name, e := range map[string]Enable{
		"bad target":   {MCP: mcp, For: "ring9"},
		"bad percent":  {MCP: mcp, For: "200%"},
		"both":         {MCP: mcp, Hook: hook},
		"invalid name": {Name: "Bad Name", Hook: hook, For: "10%"},
	} {
		t.Run(name, func(t *testing.T) {
			e.Now = now
			if _, err := open(t, simpleRepo(t)).Enable(e); err == nil {
				t.Fatal("want error")
			}
		})
	}
	t.Run("literal secret header fails validation", func(t *testing.T) {
		c, err := open(t, simpleRepo(t)).Enable(Enable{MCP: &policy.MCPServer{Name: "leaky", URL: "https://x.example/mcp",
			Headers: map[string]string{"Authorization": "Bearer not-a-real-token"}}, For: "10%", Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if issues, err := c.Validate(); err != nil || !policy.HasErrors(issues) {
			t.Fatalf("literal secret validated: %v %v", issues, err)
		}
	})
}

func orgJSON(t *testing.T, dir string) string {
	t.Helper()
	org, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(org)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExplainAndEjectRoundTrip(t *testing.T) {
	dir := simpleRepo(t)
	c, err := open(t, dir).UpgradeStart(Upgrade{Tool: "claude-code", Version: "2.1.300", Release: relDigest, Baseline: baseDigest})
	if err != nil {
		t.Fatal(err)
	}
	r := applyValid(t, c)
	if c, err = r.Enable(Enable{Name: "fmt", Hook: &policy.Hook{Event: "Stop", Command: "/bin/true"}, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r = applyValid(t, c)

	ex, err := r.Explain("")
	if err != nil {
		t.Fatal(err)
	}
	src := map[string]string{}
	for _, d := range ex {
		src[string(d.Kind)+"/"+d.Name] = d.Source
	}
	for k, want := range map[string]string{
		"Gateway/acme-gateway":                  "halos.yaml (simple mode)",
		"Profile/default":                       "halos.yaml (simple mode), overlaid by profiles/default.yaml",
		"Ring/ring2-early":                      "halos.yaml (simple mode), overlaid by rings/ring2-early.yaml",
		"Rollout/claude-code-2.1.300":           "rollouts/claude-code-2.1.300.yaml",
		"Profile/claude-code-2.1.300":           "profiles/claude-code-2.1.300.yaml",
		"Experiment/claude-code-2.1.300-canary": "experiments/claude-code-2.1.300-canary.yaml",
	} {
		if src[k] != want {
			t.Errorf("source of %s = %q, want %q", k, src[k], want)
		}
	}
	if rings, _ := r.Explain("ring"); len(rings) != 4 {
		t.Errorf("explain --kind ring = %d docs", len(rings))
	}

	before := orgJSON(t, dir)
	if c, err = r.Eject(); err != nil {
		t.Fatal(err)
	}
	created, changed := c.Paths()
	if strings.Join(created, ",") != "gateway.yaml" || len(changed) != 6 { // halos.yaml, profiles/default.yaml, 4 ring stubs
		t.Errorf("created %v changed %v", created, changed)
	}
	after := applyValid(t, c)
	if after.Simple() {
		t.Fatal("halos.yaml still has simple keys")
	}
	if got := orgJSON(t, dir); got != before {
		t.Errorf("eject changed the policy:\nbefore %s\nafter  %s", before, got)
	}
	if _, err := after.Eject(); err == nil {
		t.Error("second eject should refuse")
	}
}

// gatewayEngine is a simple key too: ejecting a repo that sets it leaves no
// simple mode behind and keeps the engine on the generated Gateway.
func TestEjectGatewayEngine(t *testing.T) {
	for _, engine := range []string{"kong", policy.EngineExternal} {
		dir := simpleRepo(t)
		f := filepath.Join(dir, policy.RootFile)
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, append(b, []byte("gatewayEngine: "+engine+"\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		before := orgJSON(t, dir)
		c, err := open(t, dir).Eject()
		if err != nil {
			t.Fatal(err)
		}
		if after := applyValid(t, c); after.Simple() {
			t.Fatalf("%s: halos.yaml still has simple keys", engine)
		}
		if got := orgJSON(t, dir); got != before || !strings.Contains(got, `"engine":"`+engine+`"`) {
			t.Errorf("%s: eject changed the policy or lost the engine:\nbefore %s\nafter  %s", engine, before, got)
		}
	}
}

func TestEjectRefusesToClobber(t *testing.T) {
	dir := simpleRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "gateway.yaml"), []byte("# notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, dir).Eject(); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err = %v", err)
	}
	dir = simpleRepo(t)
	multi := "apiVersion: halos.dev/v1\nkind: Ring\nname: ring3-ga\n---\napiVersion: halos.dev/v1\nkind: Ring\nname: ring9-lab\norder: 9\nprofile: default\nmembership: {groups: [lab]}\n"
	if err := os.WriteFile(filepath.Join(dir, "rings.yaml"), []byte(multi), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, dir).Eject(); err == nil || !strings.Contains(err.Error(), "other documents") {
		t.Fatalf("err = %v", err)
	}
}

func TestInitFileValidates(t *testing.T) {
	dir := t.TempDir()
	b := InitFile(InitOptions{Org: "globex", Tools: map[string]string{"claude-code": "2.1.280"}, Provider: "bedrock",
		Models:  map[string]string{"strong": "anthropic.claude-opus-4-1", "default": "anthropic.claude-sonnet-4-5"},
		Gateway: "https://ai.globex.example", Issuer: "https://login.globex.example", Safety: "strict", Rollout: "careful"})
	if !strings.Contains(string(b), "models:\n  default: anthropic.claude-sonnet-4-5\n") {
		t.Errorf("default model not first:\n%s", b)
	}
	if err := os.WriteFile(filepath.Join(dir, policy.RootFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	org, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if issues := org.Validate(); policy.HasErrors(issues) {
		t.Fatal(issues)
	}
	if len(org.Rings) != 5 {
		t.Errorf("careful preset rings = %d", len(org.Rings))
	}
}

// TestInitEveryToolOnEveryProvider: whatever the tool and provider, init's
// halos.yaml validates, every routed tool starts on a model whose upstream
// natively answers its wire, and every ring builds a release.
func TestInitEveryToolOnEveryProvider(t *testing.T) {
	tools := map[string]string{"claude-code": "2.1.280", "codex": "0.99.0", "gemini-cli": "0.34.0", "copilot-cli": "0.0.400"}
	sets := [][]string{{"claude-code"}, {"codex"}, {"gemini-cli"}, {"copilot-cli"}, {"claude-code", "codex", "gemini-cli", "copilot-cli"}}
	for _, prov := range []string{"anthropic", "bedrock", "vertex", "openai", "gemini", "multi"} {
		for _, set := range sets {
			t.Run(prov+"/"+strings.Join(set, "+"), func(t *testing.T) {
				o := InitOptions{Org: "acme", Provider: prov, Tools: map[string]string{}, Gateway: "https://ai.acme.example", Safety: "standard", Rollout: "standard"}
				if prov == "vertex" {
					o.Project = "acme-ai"
				}
				for _, tool := range set {
					o.Tools[tool] = tools[tool]
				}
				notes, err := o.Complete(nil)
				if err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				src := InitFile(o)
				if err := os.WriteFile(filepath.Join(dir, policy.RootFile), src, 0o644); err != nil {
					t.Fatal(err)
				}
				org, err := policy.Load(dir)
				if err != nil {
					t.Fatalf("%v\n%s", err, src)
				}
				if issues := org.Validate(); policy.HasErrors(issues) {
					t.Fatalf("%v\n%s", issues, src)
				}
				p := org.Profiles[policy.SimpleProfile]
				added := 0
				for tool, h := range p.Harnesses {
					alias := h.Model
					if alias == "" {
						alias = p.Models.Default
					} else {
						added++
					}
					kind := org.Gateway.Upstreams[org.Gateway.Models[alias].Primary().Upstream].Kind
					if !policy.ServesNatively(tool, kind) {
						t.Errorf("%s starts on %s (%s), which cannot answer its wire\n%s", tool, alias, kind, src)
					}
				}
				if len(notes) != added {
					t.Errorf("%d notes for %d added aliases: %v", len(notes), added, notes)
				}
				for _, r := range org.Rings {
					if _, err := release.Build(org, r.Profile, r.Name, release.Options{Version: "1.0.0"}); err != nil {
						t.Fatalf("render ring %s: %v\n%s", r.Name, err, src)
					}
				}
			})
		}
	}
}

func TestInitToolModelOverrides(t *testing.T) {
	o := InitOptions{Provider: "anthropic", Tools: map[string]string{"codex": "0.99.0", "gemini-cli": "0.34.0"}, Models: map[string]string{"codex": "gpt-5.1-codex"}}
	var asked []string
	notes, err := o.Complete(func(q, def string) (string, error) {
		asked = append(asked, def)
		return "gemini-3-pro", nil // unprefixed answer: runs on the tool's vendor
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.Models["codex"] != "openai/gpt-5.1-codex" || o.Models["gemini-cli"] != "gemini/gemini-3-pro" || o.Models["default"] != "claude-sonnet-4-5" {
		t.Errorf("models = %v", o.Models)
	}
	if len(asked) != 1 || asked[0] != "gemini/gemini-2.5-pro" || len(notes) != 1 || !strings.Contains(notes[0], "gemini-cli") {
		t.Errorf("asked %v notes %v", asked, notes)
	}
	o = InitOptions{Provider: "openai", Tools: map[string]string{"codex": "0.99.0"}}
	if notes, _ := o.Complete(nil); len(notes) != 0 || len(o.ToolModels) != 0 {
		t.Errorf("matching provider added %v %v", notes, o.ToolModels)
	}
	o = InitOptions{Provider: "vertex", Tools: map[string]string{"claude-code": "2.1.280"}}
	if _, err := o.Complete(nil); err == nil || !strings.Contains(err.Error(), "--project") {
		t.Errorf("vertex without project: %v", err)
	}
}
