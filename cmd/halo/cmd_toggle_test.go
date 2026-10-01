package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToggleListEvalStale(t *testing.T) {
	code, out, errs := halo(t, "toggle", "list", "--policy-dir", example, "--output", "json")
	if code != 0 {
		t.Fatalf("list: %d %s", code, errs)
	}
	var list struct {
		Toggles []struct{ Name, Axis, Owner string }
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list.Toggles) != 3 {
		t.Fatalf("list json: %v %s", err, out)
	}

	code, out, errs = halo(t, "toggle", "eval", "--policy-dir", example, "--user", "dana@acme.com", "--ring", "ring1-canary", "--groups", "acme-platform-eng", "--output", "json")
	if code != 0 {
		t.Fatalf("eval: %d %s", code, errs)
	}
	var ev struct {
		Subject struct{ Ring string }
		Toggles []struct {
			Name  string
			On    bool
			Rule  int
			Why   string
			Trace []string
		}
	}
	if err := json.Unmarshal([]byte(out), &ev); err != nil {
		t.Fatal(err)
	}
	on := map[string]bool{}
	for _, d := range ev.Toggles {
		on[d.Name] = d.On
		if d.Why == "" || len(d.Trace) == 0 {
			t.Errorf("%s: no explanation", d.Name)
		}
	}
	if !on["format-hook"] || on["sonnet-next-route"] { // group member in ring1: hook on, ring0-only route off
		t.Fatalf("decisions: %v", on)
	}

	code, out, _ = halo(t, "toggle", "eval", "--policy-dir", example, "--user", "dana@acme.com", "--ring", "ring0-harness-team")
	if code != 0 || !strings.Contains(out, "sonnet-next-route") || !strings.Contains(out, "ring ok") {
		t.Fatalf("text eval (%d):\n%s", code, out)
	}
	if code, _, _ := halo(t, "toggle", "eval", "--policy-dir", example, "--user", "u", "--ring", "nope"); code == 0 {
		t.Fatal("unknown ring accepted")
	}

	// Expire one toggle in a copy: only it is stale, and validate warns (not errors).
	dir := copyDir(t, example)
	p := filepath.Join(dir, "toggles", "format-hook.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), `expires: "2026-11-30"`, `expires: "2020-01-01"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = halo(t, "toggle", "stale", "--policy-dir", dir, "--output", "json")
	var st struct{ Stale []struct{ Name string } }
	if err := json.Unmarshal([]byte(out), &st); err != nil || code != 0 || len(st.Stale) != 1 || st.Stale[0].Name != "format-hook" {
		t.Fatalf("stale: %d %v %s", code, err, out)
	}
	if code, out, _ := halo(t, "validate", "--policy-dir", dir); code != 0 || !strings.Contains(out, "stale") {
		t.Fatalf("validate must warn about the stale toggle and still pass: %d\n%s", code, out)
	}
}

func TestToggleKillCallsServer(t *testing.T) {
	var gotPath, gotCookie, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("halo_session")
		gotPath, gotBody = r.Method+" "+r.URL.Path, ""
		if c != nil {
			gotCookie = c.Value
		}
		b := make([]byte, 512)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
		_, _ = w.Write([]byte(`{"toggle":"github-mcp","killed":true,"changed":true}`))
	}))
	defer srv.Close()
	t.Setenv("HALO_SESSION", "sess-value")

	if code, _, errs := halo(t, "toggle", "kill", "github-mcp", "--server", srv.URL); code == 0 || !strings.Contains(errs, "--reason") {
		t.Fatalf("kill without reason: %d %s", code, errs)
	}
	code, out, errs := halo(t, "toggle", "kill", "github-mcp", "--server", srv.URL, "--reason", "bad token scope", "--output", "json")
	if code != 0 {
		t.Fatalf("kill: %d %s", code, errs)
	}
	if gotPath != "POST /api/v1/toggles/github-mcp/kill" || gotCookie != "sess-value" || !strings.Contains(gotBody, "bad token scope") {
		t.Fatalf("request = %q cookie %q body %q", gotPath, gotCookie, gotBody)
	}
	if !strings.Contains(out, `"killed": true`) {
		t.Fatalf("output: %s", out)
	}
	if code, _, _ := halo(t, "toggle", "kill", "github-mcp", "--server", srv.URL, "--unkill"); code != 0 || gotPath != "POST /api/v1/toggles/github-mcp/unkill" {
		t.Fatalf("unkill: %d %s", code, gotPath)
	}
	// The session cookie never goes over plain http to a non-loopback host.
	if code, _, errs := halo(t, "toggle", "kill", "x", "--server", "http://halo.example.com", "--reason", "r"); code == 0 || !strings.Contains(errs, "https") {
		t.Fatalf("plain http accepted: %d %s", code, errs)
	}
	t.Setenv("HALO_SESSION", "")
	if code, _, _ := halo(t, "toggle", "kill", "x", "--server", srv.URL, "--reason", "r"); code == 0 {
		t.Fatal("kill without a session accepted")
	}
	// A server refusal surfaces as an error.
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "admin role required", http.StatusForbidden)
	}))
	defer deny.Close()
	t.Setenv("HALO_SESSION", "s")
	if code, _, errs := halo(t, "toggle", "kill", "x", "--server", deny.URL, "--reason", "r"); code == 0 || !strings.Contains(errs, "403") {
		t.Fatalf("403 not surfaced: %d %s", code, errs)
	}
}
