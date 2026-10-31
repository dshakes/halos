package mcpserver

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectStdio runs the server and a client over two pipes carrying
// newline-delimited JSON-RPC, byte for byte what `halo mcp serve` does on
// stdio, in this process.
func connectStdio(t *testing.T, o Options) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	c2sR, c2sW := io.Pipe() // client -> server
	s2cR, s2cW := io.Pipe() // server -> client
	ss, err := s.Connect(ctx, &mcp.IOTransport{Reader: c2sR, Writer: s2cW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e"}, nil).Connect(ctx, &mcp.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// agent follows next_steps the way an agent with no docs would: it takes the
// args the previous answer suggested for the tool it wants to call next.
type agent struct {
	t    *testing.T
	cs   *mcp.ClientSession
	last map[string]any
}

// do calls tool with the args the last answer suggested for it (plus extra),
// failing when the last answer did not point at the tool.
func (a *agent) do(tool string, extra map[string]any) map[string]any {
	a.t.Helper()
	args := map[string]any{}
	if a.last != nil {
		var found bool
		for _, s := range a.last["next_steps"].([]any) {
			if st := s.(map[string]any); st["tool"] == tool {
				found = true
				if sa, ok := st["args"].(map[string]any); ok {
					args = sa
				}
				break
			}
		}
		if !found {
			a.t.Fatalf("previous next_steps do not point at %s: %v", tool, a.last["next_steps"])
		}
	}
	for k, v := range extra {
		args[k] = v
	}
	res := raw(a.t, a.cs, tool, args)
	if res.IsError {
		a.t.Fatalf("%s %v failed: %s", tool, args, res.Content[0].(*mcp.TextContent).Text)
	}
	a.last = envelopeOf(a.t, tool, res)
	return a.last
}

func TestOnboardingFlowOverStdio(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	t.Run("company path", func(t *testing.T) {
		dir := t.TempDir()
		cs := connectStdio(t, Options{PolicyDir: dir, Onboard: fakeMachine()})

		// The prompt is the agent's only briefing: it must name the first call.
		pr, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "onboard", Arguments: map[string]string{"path": "company"}})
		if err != nil {
			t.Fatal(err)
		}
		text := pr.Messages[0].Content.(*mcp.TextContent).Text
		for _, want := range []string{"doctor", "detect_harnesses", "onboard_company", `{"org"`, "dry_run"} {
			if !strings.Contains(text, want) {
				t.Errorf("onboard prompt lacks %q", want)
			}
		}

		a := &agent{t: t, cs: cs}
		if d := a.do("doctor", nil); d["ok"] != true {
			t.Fatalf("doctor: %v", d)
		}
		h := a.do("detect_harnesses", nil)
		if h["suggested_provider"] != "anthropic" {
			t.Fatalf("detect: %v", h)
		}
		p := a.do("init_policy", nil)
		if p["valid"] != true || p["dryRun"] != true {
			t.Fatalf("init_policy dry run: %v", p)
		}
		// Company path with only the org: everything else is defaulted and echoed.
		c := a.do("onboard_company", map[string]any{"org": "Acme Corp"})
		if c["valid"] != true || c["dryRun"] != true {
			t.Fatalf("onboard_company dry run: %v", c)
		}
		as := c["assumed"].(map[string]any)
		for _, k := range []string{"gateway_kind", "issuer", "gateway", "registry", "policy_repo", "portal_url", "delivery", "tools"} {
			if as[k] == nil {
				t.Errorf("assumed lacks %s: %v", k, as)
			}
		}
		if as["gateway_kind"] != "halo-proxy" || as["registry"] != "ghcr.io/acme-corp/halos-releases" {
			t.Errorf("assumed: %v", as)
		}
		if got := stepTools(c); !slices.Contains(got, "validate") || !slices.Contains(got, "plan") {
			t.Errorf("onboard_company next_steps = %v, want validate and plan", got)
		}
		if _, err := os.Stat(filepath.Join(dir, "halos.yaml")); !os.IsNotExist(err) {
			t.Fatal("dry runs wrote halos.yaml")
		}

		// Forgiving shapes: one string for delivery, name@version items for tools.
		c = a.do("onboard_company", map[string]any{"org": "acme", "dry_run": true, "delivery": "mdm,devcontainer", "tools": []any{"claude-code@2.1.280"}})
		if as := c["assumed"].(map[string]any); as["delivery"] != nil || as["tools"] != nil {
			t.Errorf("supplied answers reported as assumed: %v", as)
		}

		// A real write is refused while example.com placeholders are assumed
		// (and, on this read-only server, before that).
		res := raw(t, cs, "onboard_company", map[string]any{"org": "acme", "dry_run": false})
		if !res.IsError {
			t.Fatal("read-only server wrote")
		}
		m := envelopeOf(t, "onboard_company", res)
		if k := m["error"].(map[string]any)["kind"]; k != "writes_disabled" {
			t.Errorf("kind = %v", k)
		}
	})

	t.Run("my machine path writes and validates", func(t *testing.T) {
		dir := t.TempDir()
		cs := connectStdio(t, Options{PolicyDir: dir, AllowWrites: true, Onboard: fakeMachine()})
		a := &agent{t: t, cs: cs}
		a.do("doctor", nil)
		a.do("detect_harnesses", nil)
		if p := a.do("init_policy", nil); p["dryRun"] != true {
			t.Fatalf("init_policy defaulted to a write: %v", p)
		}
		if _, err := os.Stat(filepath.Join(dir, "halos.yaml")); !os.IsNotExist(err) {
			t.Fatal("dry run wrote halos.yaml")
		}
		// The human said yes: take the write step the dry run suggested.
		if w := a.do("init_policy", nil); w["dryRun"] != false {
			t.Fatalf("write step did not write: %v", w)
		}
		if v := a.do("validate", nil); v["ok"] != true {
			t.Fatalf("validate: %v", v)
		}
		pl := a.do("plan", nil)
		if pl["changed"] == nil {
			t.Fatalf("plan: %v", pl)
		}
		if got := stepTools(pl); !slices.Contains(got, "local_install") {
			t.Errorf("plan next_steps = %v, want local_install", got)
		}
		// Nothing outside the policy dir and the temp HOME was touched.
		if _, err := os.Stat(filepath.Join(dir, "halos.yaml")); err != nil {
			t.Fatalf("halos.yaml: %v", err)
		}
	})
}
