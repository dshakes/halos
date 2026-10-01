package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func togglesServer(t *testing.T, admin bool) (*Server, http.Handler, *recOpener) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repo := portalPolicy(t) // the writer's clone: a copy of the example policy
	op := &recOpener{}
	w := &GitPolicyWriter{RepoDir: repo, ServedDir: t.TempDir(), Opener: op, Git: func(_ context.Context, a ...string) (string, error) {
		if a[0] == "rev-parse" {
			return repo, nil
		}
		return "", nil
	}}
	s, err := New(Config{
		PolicyDir: "../../examples/acme-corp", Token: tok, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DevUser: "alice@test", DevAdmin: admin, KillKey: priv, GatewayToken: gwTok, Writer: w,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, s.Handler(), op
}

func TestToggleList(t *testing.T) {
	_, h, _ := togglesServer(t, true)
	w := do(h, "GET", "/api/v1/toggles", "", "")
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var out struct {
		Toggles     []ToggleView
		KillEnabled bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	by := map[string]ToggleView{}
	for _, v := range out.Toggles {
		by[v.Name] = v
	}
	if len(by) != 3 || !out.KillEnabled {
		t.Fatalf("toggles = %v killEnabled=%v", by, out.KillEnabled)
	}
	gh := by["github-mcp"]
	if gh.Axis != policy.AxisClient || gh.Owner == "" || gh.Default || len(gh.Rules) != 1 || gh.Rules[0].Percent == nil || *gh.Rules[0].Percent != 10 || gh.Kill != nil {
		t.Fatalf("github-mcp = %+v", gh)
	}
	if ps := gh.Payload.Harnesses["claude-code"]; len(ps.MCPServers) != 1 || !strings.HasPrefix(ps.MCPServers[0], "github https://") {
		t.Fatalf("payload = %+v", gh.Payload)
	}
	if r := by["sonnet-next-route"].Payload.Routes["sonnet"]; r != "anthropic-direct/claude-sonnet-5-5" {
		t.Fatalf("route = %q", r)
	}
	if strings.Contains(w.Body.String(), "GITHUB_MCP_TOKEN") || strings.Contains(w.Body.String(), "Bearer") {
		t.Fatalf("payload summary leaks header values: %s", w.Body)
	}

	// Killing shows up with who/why, and in the history.
	if c := do(h, "POST", "/api/v1/toggles/github-mcp/kill", "", `{"reason":"bad scope"}`); c.Code != 200 {
		t.Fatalf("kill: %d", c.Code)
	}
	w = do(h, "GET", "/api/v1/toggles", "", "")
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	for _, v := range out.Toggles {
		if v.Name == "github-mcp" && (v.Kill == nil || v.Kill.By != "alice@test" || v.Kill.Reason != "bad scope" || v.Kill.At.IsZero()) {
			t.Fatalf("kill state = %+v", v.Kill)
		}
		if v.Name != "github-mcp" && v.Kill != nil {
			t.Fatalf("%s wrongly killed", v.Name)
		}
	}
}

func TestToggleDetailAndPreview(t *testing.T) {
	_, h, _ := togglesServer(t, true)
	get := func(q string) (int, struct {
		Toggle  ToggleView
		History []AuditEntry
		Preview *TogglePreview
	}) {
		w := do(h, "GET", "/api/v1/toggles/format-hook"+q, "", "")
		var out struct {
			Toggle  ToggleView
			History []AuditEntry
			Preview *TogglePreview
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := get("")
	if code != 200 || out.Toggle.Name != "format-hook" || out.Preview != nil || out.History == nil {
		t.Fatalf("detail: %d %+v", code, out)
	}
	code, out = get("?user=dana@acme.com&ring=ring1-canary&groups=acme-platform-eng")
	if code != 200 || out.Preview == nil || !out.Preview.Decision.On || len(out.Preview.Decision.Trace) == 0 || out.Preview.Subject.Ring != "ring1-canary" {
		t.Fatalf("preview: %d %+v", code, out.Preview)
	}
	if _, out = get("?user=dana@acme.com&ring=ring1-canary"); out.Preview.Decision.On {
		t.Fatal("non-member previewed as on")
	}
	// the ring is resolved from the user when omitted
	if _, out = get("?user=dana@acme.com&groups=acme-platform-eng"); out.Preview == nil || out.Preview.Subject.Ring == "" {
		t.Fatalf("ring not resolved: %+v", out.Preview)
	}
	// a killed toggle previews as off, flagged killed
	do(h, "POST", "/api/v1/toggles/format-hook/kill", "", `{"reason":"x"}`)
	if _, out = get("?user=dana@acme.com&ring=ring1-canary&groups=acme-platform-eng"); out.Preview.Decision.On || !out.Preview.Decision.Killed {
		t.Fatalf("killed preview: %+v", out.Preview.Decision)
	}
	if len(out.History) != 1 || out.History[0].Action != "toggle.kill" || out.History[0].Details["reason"] != "x" {
		t.Fatalf("history = %+v", out.History)
	}
	if w := do(h, "GET", "/api/v1/toggles/nope", "", ""); w.Code != 404 {
		t.Fatalf("unknown toggle: %d", w.Code)
	}
	if w := do(h, "GET", "/api/v1/toggles/format-hook?user=u&ring=ghost", "", ""); w.Code != 422 {
		t.Fatalf("unknown ring: %d", w.Code)
	}
}

func TestToggleAuthz(t *testing.T) {
	_, h, _ := togglesServer(t, false) // signed in, not an admin
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/toggles", ""},
		{"GET", "/api/v1/toggles/github-mcp", ""},
		{"POST", "/api/v1/toggles/github-mcp/propose", `{"reason":"x","default":true}`},
		{"POST", "/api/v1/toggles/github-mcp/kill", `{"reason":"x"}`},
	} {
		if w := do(h, tc.method, tc.path, "", tc.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s as non-admin: %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestToggleProposal(t *testing.T) {
	_, h, op := togglesServer(t, true)
	post := func(name, body string) (int, string) {
		w := do(h, "POST", "/api/v1/toggles/"+name+"/propose", "", body)
		return w.Code, w.Body.String()
	}
	code, body := post("github-mcp", `{"reason":"ramp to 25","rule":"ring1-ten-percent","percent":25,"addGroups":["acme-ai-champions"]}`)
	if code != 200 || !strings.Contains(body, "https://git.example/pr/9") {
		t.Fatalf("propose: %d %s", code, body)
	}
	r := op.req
	f := string(r.Files["toggles/github-mcp.yaml"])
	if !strings.HasPrefix(r.Branch, "halos/toggle-github-mcp-") || !strings.Contains(r.Title, "github-mcp") ||
		!strings.Contains(f, "percent: 25") || !strings.Contains(f, "acme-ai-champions") ||
		!strings.Contains(r.Body, "alice@test") || !strings.Contains(r.Body, "ramp to 25") || !strings.Contains(r.Body, "+    percent: 25") || r.Edit == nil {
		t.Fatalf("PR = %+v\nfile:\n%s", r, f)
	}
	if !strings.Contains(f, "# GitHub MCP") && !strings.Contains(f, "yaml-language-server") {
		t.Fatalf("comments lost:\n%s", f)
	}

	// the audit trail records it
	w := do(h, "GET", "/api/v1/toggles/github-mcp", "", "")
	if !strings.Contains(w.Body.String(), "toggle.propose") || !strings.Contains(w.Body.String(), "https://git.example/pr/9") {
		t.Fatalf("propose not audited: %s", w.Body)
	}

	// validation failures never open a PR
	op.req.Branch = ""
	for name, tc := range map[string]struct {
		toggle, body string
		want         int
	}{
		"no reason":                              {"github-mcp", `{"default":true}`, 422},
		"nothing to change":                      {"github-mcp", `{"reason":"x"}`, 422},
		"unknown toggle":                         {"nope", `{"reason":"x","default":true}`, 404},
		"percent out of range":                   {"github-mcp", `{"reason":"x","rule":"ring1-ten-percent","percent":150}`, 422},
		"unknown rule":                           {"github-mcp", `{"reason":"x","rule":"nope","percent":5}`, 422},
		"unknown ring fails validate":            {"github-mcp", `{"reason":"x","rule":"ring1-ten-percent","addRings":["ghost"]}`, 422},
		"removing the last ring widens the rule": {"github-mcp", `{"reason":"x","rule":"ring1-ten-percent","removeRings":["ring1-canary"]}`, 422},
		"bad expiry":                             {"github-mcp", `{"reason":"x","expires":"soon"}`, 422},
		"bad json":                               {"github-mcp", `{`, 400},
		"no-op change":                           {"github-mcp", `{"reason":"x","default":false}`, 422},
	} {
		if code, body := post(tc.toggle, tc.body); code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, code, body, tc.want)
		}
	}
	if op.req.Branch != "" {
		t.Fatalf("a rejected proposal opened a PR: %+v", op.req)
	}
}

func TestToggleProposalNeedsWriter(t *testing.T) {
	s, _, _ := togglesServer(t, true)
	s.cfg.Writer = nil
	w := do(s.Handler(), "POST", "/api/v1/toggles/github-mcp/propose", "", `{"reason":"x","default":true}`)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("no writer: %d %s", w.Code, w.Body)
	}
}
