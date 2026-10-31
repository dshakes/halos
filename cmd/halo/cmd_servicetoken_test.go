package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/server"
)

// TestServiceTokenCLI drives create, list and revoke against a real
// halo-server (dev admin), and checks the token is printed once.
func TestServiceTokenCLI(t *testing.T) {
	s, err := server.New(server.Config{PolicyDir: t.TempDir(), Token: "t", DevUser: "ops@acme.example", DevAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	t.Setenv("HALO_TOKEN", "")
	t.Setenv("HALO_SESSION", "sess")

	code, out, errs := halo(t, "service-token", "create", "--server", srv.URL, "--name", "ci-kill", "--role", "operator", "--ttl", "720h", "--owner", "platform")
	tok := strings.TrimSpace(out)
	if code != 0 || !strings.HasPrefix(tok, server.ServiceTokenPrefix) || !strings.Contains(errs, "not shown again") {
		t.Fatalf("create: %d %q %s", code, out, errs)
	}
	code, out, errs = halo(t, "service-token", "list", "--server", srv.URL)
	if code != 0 || !strings.Contains(out, "ci-kill") || !strings.Contains(out, "operator") || !strings.Contains(out, "active") || strings.Contains(out, tok[len(server.ServiceTokenPrefix)+16:]) {
		t.Fatalf("list: %d %s %s", code, out, errs)
	}
	code, out, _ = halo(t, "service-token", "list", "--server", srv.URL, "--output", "json")
	var lst server.ServiceTokensResponse
	if code != 0 || json.Unmarshal([]byte(out), &lst) != nil || len(lst.Tokens) != 1 {
		t.Fatalf("list json: %d %s", code, out)
	}
	id := lst.Tokens[0].ID
	if code, _, errs := halo(t, "service-token", "revoke", id, "--server", srv.URL); code == 0 || !strings.Contains(errs, "--reason") {
		t.Fatalf("revoke without reason: %d %s", code, errs)
	}
	if code, out, errs := halo(t, "service-token", "revoke", id, "--server", srv.URL, "--reason", "rotated"); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %d %s %s", code, out, errs)
	}
	for name, args := range map[string][]string{
		"no name":    {"create", "--role", "viewer", "--server", srv.URL},
		"bad role":   {"create", "--name", "x", "--role", "root", "--server", srv.URL},
		"plain http": {"list", "--server", "http://halo.example.com"},
	} {
		if code, _, errs := halo(t, append([]string{"service-token"}, args...)...); code == 0 {
			t.Errorf("%s: accepted (%s)", name, errs)
		}
	}
	t.Setenv("HALO_SESSION", "")
	if code, _, errs := halo(t, "service-token", "list", "--server", srv.URL); code == 0 || !strings.Contains(errs, "HALO_TOKEN") {
		t.Fatalf("no credential: %d %s", code, errs)
	}
}

// TestHaloTokenTransport: HALO_TOKEN goes out as a bearer token and wins over
// HALO_SESSION; HALO_SESSION alone is the cookie, as before.
func TestHaloTokenTransport(t *testing.T) {
	var auth, cookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, cookie = r.Header.Get("Authorization"), ""
		if c, err := r.Cookie("halo_session"); err == nil {
			cookie = c.Value
		}
		_, _ = w.Write([]byte(`{"revocations":[]}`))
	}))
	t.Cleanup(srv.Close)
	tok := server.ServiceTokenPrefix + strings.Repeat("ab", 40)
	for _, c := range []struct {
		name, token, session, auth, cookie string
	}{
		{"token wins", tok, "sess", "Bearer " + tok, ""},
		{"token only", tok, "", "Bearer " + tok, ""},
		{"session only", "", "sess", "", "sess"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("HALO_TOKEN", c.token)
			t.Setenv("HALO_SESSION", c.session)
			if code, _, errs := halo(t, "agents", "revocations", "--server", srv.URL); code != 0 || auth != c.auth || cookie != c.cookie {
				t.Fatalf("%d %s: auth %q cookie %q", code, errs, auth, cookie)
			}
		})
	}
}
