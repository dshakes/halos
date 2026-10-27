package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/server"
)

// TestAgentsRevoke drives the real halo-server API (dev admin) end to end:
// revoke by jti and by subject, list, and the flag and transport checks.
func TestAgentsRevoke(t *testing.T) {
	s, err := server.New(server.Config{PolicyDir: t.TempDir(), Token: "t", DevUser: "ops@acme.example", DevAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	t.Setenv("HALO_SESSION", "sess")

	if code, out, errs := halo(t, "agents", "revoke", "--server", srv.URL, "--jti", "abc123", "--reason", "leaked in a CI log"); code != 0 || !strings.Contains(out, "jti abc123") || !strings.Contains(out, "leaked in a CI log") {
		t.Fatalf("revoke jti: %d %s %s", code, out, errs)
	}
	if code, out, errs := halo(t, "agents", "revoke", "--server", srv.URL, "--subject", "agent:planner", "--reason", "compromised"); code != 0 || !strings.Contains(out, "subject agent:planner (issued at or before") {
		t.Fatalf("revoke subject: %d %s %s", code, out, errs)
	}
	code, out, errs := halo(t, "agents", "revocations", "--server", srv.URL, "--output", "json")
	if code != 0 || !strings.Contains(out, `"jti": "abc123"`) || !strings.Contains(out, `"subject": "agent:planner"`) || !strings.Contains(out, `"by": "ops@acme.example"`) {
		t.Fatalf("list: %d %s %s", code, out, errs)
	}
	for name, args := range map[string][]string{
		"neither":        {"--reason", "x"},
		"both":           {"--jti", "a", "--subject", "agent:planner", "--reason", "x"},
		"no reason":      {"--jti", "a"},
		"plain http":     {"--jti", "a", "--reason", "x", "--server", "http://halo.example.com"},
		"server refuses": {"--subject", "agent:Bad Name", "--reason", "x"},
	} {
		if !slices.Contains(args, "--server") {
			args = append(args, "--server", srv.URL)
		}
		if code, _, errs := halo(t, append([]string{"agents", "revoke"}, args...)...); code == 0 {
			t.Errorf("%s: accepted (%s)", name, errs)
		}
	}
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "admin permission required", http.StatusForbidden)
	}))
	t.Cleanup(deny.Close)
	if code, _, errs := halo(t, "agents", "revocations", "--server", deny.URL); code == 0 || !strings.Contains(errs, "403") {
		t.Fatalf("403 not surfaced: %d %s", code, errs)
	}
	t.Setenv("HALO_SESSION", "")
	if code, _, errs := halo(t, "agents", "revocations", "--server", srv.URL); code == 0 || !strings.Contains(errs, "HALO_SESSION") {
		t.Fatalf("no session: %d %s", code, errs)
	}
}
