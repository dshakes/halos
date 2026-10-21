package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// TestDirectoryIsAuthoritative: with a SCIM directory configured, the ring
// comes from the directory's groups for the verified subject. The token's
// groups claim and client headers do not count, and a deprovisioned or
// unknown user is an unknown caller (default routing).
func TestDirectoryIsAuthoritative(t *testing.T) {
	var mu sync.Mutex
	dir := map[string]gateway.DirectoryEntry{
		"alice@acme.com": {Active: true, Groups: []string{"ai-platform"}},
		"bob@acme.com":   {Active: true},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gw-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(dir[r.URL.Query().Get("subject")])
	}))
	t.Cleanup(srv.Close)
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	if err := os.WriteFile(tokFile, []byte("gw-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, _ *policy.Org) {
		c.Directory = DirectoryConfig{URL: srv.URL + "/api/v1/gateway/directory", TokenFile: tokFile}
	})
	var tick atomic.Int64 // every lookup sees the clock a TTL later, so each request asks the fake server
	e.p.dir.Now = func() time.Time { return time.Unix(tick.Add(int64(gateway.DefaultDirectoryTTL/time.Second)), 0) }
	spoof := map[string]string{"x-halo-ring": "ring0", "x-halo-groups": "ai-platform"}
	for _, c := range []struct {
		name, user string
		claim      []string
		want       string
	}{
		{"directory group wins over an empty claim", "alice@acme.com", nil, "ring0"},
		{"claimed group not in the directory", "bob@acme.com", []string{"ai-platform"}, "ga"},
	} {
		resp := e.post(t, "/v1/messages", e.token(t, c.user, c.claim...), msgBody, spoof)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", c.name, resp.StatusCode)
		}
		if _, h, _, _ := s.get(); h.Get("x-halo-ring") != c.want {
			t.Errorf("%s: x-halo-ring=%q, want %q", c.name, h.Get("x-halo-ring"), c.want)
		}
	}
	mu.Lock()
	dir["alice@acme.com"] = gateway.DirectoryEntry{} // deprovisioned
	mu.Unlock()
	// A verified caller the directory does not list as active is refused in
	// the protocol's error shape, never demoted to an anonymous caller (which
	// would skip the posture gate and per-user budgets).
	for _, user := range []string{"alice@acme.com", "eve@acme.com"} {
		resp := e.post(t, "/v1/messages", e.token(t, user, "ai-platform"), msgBody, nil)
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), `"permission_error"`) {
			t.Errorf("%s (not active in the directory): %d %s, want 403 permission_error", user, resp.StatusCode, b)
		}
	}
}

// TestDirectoryKeepsWorkloads: with a directory configured, a workload
// credential (not in SCIM) keeps its identity, groups and Kind.
func TestDirectoryKeepsWorkloads(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(gateway.DirectoryEntry{})
	}))
	t.Cleanup(srv.Close)
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	if err := os.WriteFile(tokFile, []byte("gw-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, s, priv := workloadEnv(t, false)
	dc, err := DirectoryConfig{URL: srv.URL, TokenFile: tokFile}.build(e.p.log)
	if err != nil {
		t.Fatal(err)
	}
	e.p.dir = dc
	resp := e.post(t, "/v1/messages", mintWorkload(t, priv, time.Now(), 15*time.Minute), msgBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("workload with a directory configured: %d", resp.StatusCode)
	}
	if _, h, _, _ := s.get(); h.Get("x-halo-ring") != "ring0" {
		t.Errorf("workload: x-halo-ring=%q, want ring0 (from the credential's groups)", h.Get("x-halo-ring"))
	}
	if hits.Load() != 0 {
		t.Errorf("workload looked up in the SCIM directory: %d", hits.Load())
	}
}

// TestDirectoryOutageKeepsIdentity: when the directory cannot be asked (an
// outage, or halo-server rate-limiting this gateway's IP) a verified caller is
// never demoted to anonymous, which would pass the posture gate as "unknown"
// and skip per-user budgets: fail open keeps the subject (so a non-compliant
// device is still refused), fail closed answers 503 in the protocol's shape.
func TestDirectoryOutageKeepsIdentity(t *testing.T) {
	var verdict atomic.Value
	verdict.Store(gateway.PostureVerdict{Reason: "device laptop-1 is not compliant"})
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	if err := os.WriteFile(tokFile, []byte("gw-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	ua := map[string]string{"User-Agent": "claude-cli/2.1.280 (external, cli)"}
	for _, c := range []struct {
		mode, want string
		status     int
	}{
		{"", "halod status", http.StatusForbidden}, // posture gate applied to the kept subject
		{"open", "halod status", http.StatusForbidden},
		{"closed", "directory is unreachable", http.StatusServiceUnavailable},
	} {
		e, _ := gateEnv(t, "enforce", "off", &verdict)
		dc, err := DirectoryConfig{URL: "http://127.0.0.1:1/api/v1/gateway/directory", TokenFile: tokFile, FailMode: c.mode}.build(e.p.log)
		if err != nil {
			t.Fatal(err)
		}
		e.p.dir = dc
		resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com", "ai-platform"), msgBody, ua)
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != c.status || !strings.Contains(string(b), c.want) {
			t.Errorf("failMode %q: %d %s, want %d %q", c.mode, resp.StatusCode, b, c.status, c.want)
		}
	}
	if _, err := (DirectoryConfig{URL: "https://halo.example/d", TokenFile: tokFile, FailMode: "strict"}).build(slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.Contains(err.Error(), "failMode") {
		t.Errorf("failMode strict: %v", err)
	}
}

func TestDirectoryConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tok := filepath.Join(t.TempDir(), "t")
	_ = os.WriteFile(tok, []byte("x"), 0o600)
	for _, c := range []struct {
		name    string
		cfg     DirectoryConfig
		wantNil bool
		wantErr string
	}{
		{"off", DirectoryConfig{}, true, ""},
		{"token without url", DirectoryConfig{TokenFile: tok}, true, "directory.url is required"},
		{"url without token", DirectoryConfig{URL: "https://halo.example/api/v1/gateway/directory"}, true, "needs tokenFile"},
		{"unreadable token", DirectoryConfig{URL: "https://halo.example/d", TokenFile: tok + "-missing"}, true, "directory.tokenFile"},
		{"plain http off-cluster", DirectoryConfig{URL: "http://halo.example/d", TokenFile: tok}, true, "directory url"},
		{"plain http in cluster", DirectoryConfig{URL: "http://halo-server.halos.svc/d", TokenFile: tok, AllowInsecureInCluster: true}, false, ""},
		{"https", DirectoryConfig{URL: "https://halo.example/d", TokenFile: tok}, false, ""},
	} {
		dc, err := c.cfg.build(log)
		if (err != nil) != (c.wantErr != "") || (err != nil && !strings.Contains(err.Error(), c.wantErr)) || (dc == nil) != c.wantNil {
			t.Errorf("%s: client %v err %v", c.name, dc, err)
		}
	}
}
