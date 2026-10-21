package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// TestDirectoryClientResolve: directory groups replace the caller's own; an
// inactive or unknown subject resolves to nil; an unreachable server serves
// the cached entry for Grace and then fails closed to unknown.
func TestDirectoryClientResolve(t *testing.T) {
	var entry atomic.Value
	entry.Store(DirectoryEntry{Active: true, Groups: []string{"ai-platform"}})
	var hits, down atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() == 1 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("subject") != "alice@acme.com" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(entry.Load())
	}))
	t.Cleanup(srv.Close)
	c, err := NewDirectoryClient(srv.URL, "tok", time.Minute, 5*time.Minute, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	c.Now = func() time.Time { return now }
	alice := &policy.Subject{ID: "alice@acme.com", Groups: []string{"platform-admins", "spoofed"}}
	ctx := context.Background()

	if got := c.Resolve(ctx, alice); got == nil || got.ID != alice.ID || !slices.Equal(got.Groups, []string{"ai-platform"}) {
		t.Fatalf("active: %+v", got)
	}
	c.Resolve(ctx, alice)
	if hits.Load() != 1 {
		t.Fatalf("cached entry not reused within TTL: %d fetches", hits.Load())
	}
	now = now.Add(time.Minute)
	entry.Store(DirectoryEntry{})
	if got := c.Resolve(ctx, alice); got != nil {
		t.Fatalf("deprovisioned after TTL: %+v, want nil", got)
	}
	entry.Store(DirectoryEntry{Active: true})
	now = now.Add(time.Minute)
	c.Resolve(ctx, alice) // cache: active, no groups
	down.Store(1)
	now = now.Add(4 * time.Minute)
	if got := c.Resolve(ctx, alice); got == nil || len(got.Groups) != 0 {
		t.Fatalf("within grace: %+v, want the cached active entry", got)
	}
	now = now.Add(2 * time.Minute)
	if got := c.Resolve(ctx, alice); got != nil {
		t.Fatalf("past grace with the server down: %+v, want nil (unknown)", got)
	}
	if got := c.Resolve(ctx, nil); got != nil {
		t.Fatalf("anonymous: %+v", got)
	}
	if got := c.Resolve(ctx, &policy.Subject{ID: "bob@acme.com"}); got != nil {
		t.Fatalf("server error, nothing cached: %+v", got)
	}
}

func TestNewDirectoryClient(t *testing.T) {
	for _, c := range []struct {
		name, url, tok string
		insecure, ok   bool
	}{
		{"https", "https://halo.example/api/v1/gateway/directory", "t", false, true},
		{"loopback http", "http://127.0.0.1:8080/d", "t", false, true},
		{"remote http", "http://halo.example/d", "t", false, false},
		{"remote http in cluster", "http://halo.example/d", "t", true, true},
		{"no token", "https://halo.example/d", "", false, false},
		{"no url", "", "t", false, false},
	} {
		dc, err := NewDirectoryClient(c.url, c.tok, 0, 0, nil, c.insecure)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", c.name, err)
		}
		if err == nil && (dc.TTL != DefaultDirectoryTTL || dc.Grace != DefaultDirectoryGrace) {
			t.Errorf("%s: defaults %v %v", c.name, dc.TTL, dc.Grace)
		}
	}
}
