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
		{"never provisioned", "eve@acme.com", []string{"ai-platform"}, "unknown"},
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
	if resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com", "ai-platform"), msgBody, nil); resp.StatusCode != 200 {
		t.Fatalf("deprovisioned: %d", resp.StatusCode)
	}
	if _, h, _, _ := s.get(); h.Get("x-halo-ring") != "unknown" {
		t.Errorf("deprovisioned user: x-halo-ring=%q, want unknown", h.Get("x-halo-ring"))
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
