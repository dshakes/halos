package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dshakes/halos/internal/gateway"
)

// TestAccessDirectoryIsAuthoritative: with directory_url set, the trusted
// groups header no longer decides the ring; halo-server's SCIM directory does,
// and an unknown or deprovisioned user gets default routing. An invalid
// directory config fails closed to unknown.
func TestAccessDirectoryIsAuthoritative(t *testing.T) {
	dir := map[string]gateway.DirectoryEntry{
		"alice": {Active: true, Groups: []string{"ai-platform"}},
		"bob":   {Active: true},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gw-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(dir[r.URL.Query().Get("subject")])
	}))
	t.Cleanup(srv.Close)
	pol := testPolicy(t)
	for _, c := range []struct {
		name, user, groups, url string
		want                    string
	}{
		{"directory group, no header group", "alice", "", srv.URL, "ring0"},
		{"header group not in the directory", "bob", "ai-platform", srv.URL, "ga"},
		{"never provisioned", "eve", "ai-platform", srv.URL, "unknown"},
		{"invalid directory config fails closed", "alice", "ai-platform", "http://halo.example/d", "unknown"},
	} {
		cfg := trustedCfg(pol)
		cfg.DirectoryURL, cfg.DirectoryToken = c.url, "gw-token"
		k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn),
			hdrs: map[string][]string{"x-acme-user": {c.user}, "x-acme-groups": {c.groups}, "x-halo-ring": {"ring0"}}}
		cfg.access(k)
		if k.exitStatus != 0 || k.set["x-halo-ring"] != c.want {
			t.Errorf("%s: exit %d ring %q, want %q (logs %v)", c.name, k.exitStatus, k.set["x-halo-ring"], c.want, k.logs)
		}
	}
}
