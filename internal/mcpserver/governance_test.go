package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// freezeNow appends a one-off freeze window covering now to dir's halos.yaml
// (working tree only: loads see it, commits start from HEAD).
func freezeNow(t *testing.T, dir string) {
	t.Helper()
	now := time.Now().UTC()
	p := filepath.Join(dir, "halos.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// drop the example's governance sample (indented or blank lines), keep later sections
	s := regexp.MustCompile(`(?m)^governance:\n(?:[ \t].*\n|\n)*`).ReplaceAllString(string(b), "")
	s += "governance:\n  freezes:\n    - name: year-end\n      reason: year-end freeze\n      start: \"" + now.Add(-time.Hour).Format(time.RFC3339) +
		"\"\n      end: \"" + now.Add(time.Hour).Format(time.RFC3339) + "\"\n"
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestWriteToolsRespectFreezes: during a freeze, promotion and advance
// proposals are refused with the window and next open time; dry runs say so;
// rollbacks always go through (ADR-0030).
func TestWriteToolsRespectFreezes(t *testing.T) {
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	dir := copyExample(t)
	freezeNow(t, dir)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})

	for _, c := range []struct{ tool string }{{"propose_rollout_advance"}, {"propose_promotion"}} {
		args := map[string]any{"name": "opus-5-5-upgrade", "reason": "go", "dry_run": false}
		if c.tool == "propose_promotion" {
			args = map[string]any{"experiment": "opus-5-5-canary", "ring": "ring1-canary", "release": "sha256:" + strings.Repeat("a", 64), "reason": "go", "dry_run": false}
		}
		if _, err := call(t, cs, c.tool, args); err == nil || !strings.Contains(err.Error(), "year-end (year-end freeze)") || !strings.Contains(err.Error(), "next open") {
			t.Fatalf("%s during a freeze: %v", c.tool, err)
		}
		delete(args, "dry_run")
		out, err := call(t, cs, c.tool, args)
		if err != nil || !strings.Contains(out["note"].(string), "refused if applied now") {
			t.Fatalf("%s dry run: %v %v", c.tool, out, err)
		}
	}
	out, err := call(t, cs, "propose_rollout_rollback", map[string]any{"name": "opus-5-5-upgrade", "reason": "regression", "dry_run": false})
	if err != nil || out["applied"] != true {
		t.Fatalf("rollback during a freeze: %v %v", out, err)
	}
}

// TestIncidentFreezeFromServer: with --server, the incident freeze and the
// step's approvals come from halo-server.
func TestIncidentFreezeFromServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/freeze":
			_, _ = w.Write([]byte(`{"incident":{"name":"incident","reason":"SEV1 checkout","by":"oncall@acme","incident":true},"rings":{}}`))
		case "/api/v1/rollouts/opus-5-5-upgrade/approvals":
			_, _ = w.Write([]byte(`{"approvals":[]}`))
		case "/api/v1/me":
			_, _ = w.Write([]byte(`{"id":"dev@acme"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("HALO_SESSION", "s")
	dir := copyExample(t)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true, Server: srv.URL})
	_, err := call(t, cs, "propose_rollout_advance", map[string]any{"name": "opus-5-5-upgrade", "reason": "go", "dry_run": false})
	if err == nil || !strings.Contains(err.Error(), "incident (SEV1 checkout) until lifted") {
		t.Fatalf("advance during an incident freeze: %v", err)
	}
	out, err := call(t, cs, "rollout_status", map[string]any{"name": "opus-5-5-upgrade"})
	if err != nil || out["evidence"].(map[string]any)["freeze"] == nil {
		t.Fatalf("rollout_status shows the freeze: %v %v", out, err)
	}
}
