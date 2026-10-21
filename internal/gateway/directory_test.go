package gateway

import (
	"context"
	"encoding/json"
	"errors"
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

	if got, err := c.Resolve(ctx, alice); err != nil || got == nil || got.ID != alice.ID || !slices.Equal(got.Groups, []string{"ai-platform"}) {
		t.Fatalf("active: %+v %v", got, err)
	}
	_, _ = c.Resolve(ctx, alice)
	if hits.Load() != 1 {
		t.Fatalf("cached entry not reused within TTL: %d fetches", hits.Load())
	}
	now = now.Add(time.Minute)
	entry.Store(DirectoryEntry{})
	if got, err := c.Resolve(ctx, alice); got != nil || !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("deprovisioned after TTL: %+v %v, want ErrNotProvisioned (refused, never anonymous)", got, err)
	}
	entry.Store(DirectoryEntry{Active: true})
	now = now.Add(time.Minute)
	_, _ = c.Resolve(ctx, alice) // cache: active, no groups
	down.Store(1)
	now = now.Add(4 * time.Minute)
	if got, err := c.Resolve(ctx, alice); err != nil || got == nil || len(got.Groups) != 0 {
		t.Fatalf("within grace: %+v %v, want the cached active entry", got, err)
	}
	now = now.Add(2 * time.Minute)
	if got, err := c.Resolve(ctx, alice); got != nil || err != nil {
		t.Fatalf("past grace with the server down: %+v %v, want nil (unknown)", got, err)
	}
	if got, err := c.Resolve(ctx, nil); got != nil || err != nil {
		t.Fatalf("anonymous: %+v %v", got, err)
	}
	if got, err := c.Resolve(ctx, &policy.Subject{ID: "bob@acme.com"}); got != nil || err != nil {
		t.Fatalf("server error, nothing cached: %+v %v", got, err)
	}
}

// TestDirectoryClientWorkloads: workload subjects (ADR-0023) are not in SCIM,
// so they skip the lookup and keep their Kind and credential groups. A human
// whose id has the workload prefix still gets no Kind from the directory.
func TestDirectoryClientWorkloads(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(DirectoryEntry{Active: true, Groups: []string{"scim-group"}})
	}))
	t.Cleanup(srv.Close)
	c, err := NewDirectoryClient(srv.URL, "tok", time.Minute, time.Minute, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wl := &policy.Subject{ID: policy.WorkloadSubjectPrefix + "gh:acme/app", Groups: []string{"ci"}, Kind: policy.SubjectWorkload}
	got, err := c.Resolve(context.Background(), wl)
	if err != nil || got == nil || got.Kind != policy.SubjectWorkload || got.ID != wl.ID || !slices.Equal(got.Groups, []string{"ci"}) {
		t.Fatalf("workload: %+v %v, want it unchanged", got, err)
	}
	if hits.Load() != 0 {
		t.Fatalf("workload looked up in the SCIM directory: %d fetches", hits.Load())
	}
	human := &policy.Subject{ID: policy.WorkloadSubjectPrefix + "x"} // Kind "" : only a workload credential sets Kind
	if got, err := c.Resolve(context.Background(), human); err != nil || got == nil || got.Kind != "" || hits.Load() != 1 {
		t.Fatalf("human with a workload-looking id: %+v %v (fetches %d), want a lookup and Kind \"\"", got, err, hits.Load())
	}
}

func TestRejectNotProvisioned(t *testing.T) {
	for path, proto := range map[string]string{"/v1/messages": ProtoAnthropic, "/v1/responses": ProtoResponses} {
		r := RejectNotProvisioned(path)
		if r.Status != http.StatusForbidden || r.Protocol != proto {
			t.Errorf("%s: %+v", path, r)
		}
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
