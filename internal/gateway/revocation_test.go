package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

func agentSub(root, kind string, authTime, iat int64, ids []string, agents ...string) *policy.Subject {
	d := &policy.DelegationChain{AuthTime: authTime, ID: ids[0]}
	for _, a := range agents {
		d.Actors = append(d.Actors, policy.Actor{Agent: a})
	}
	return &policy.Subject{ID: root, Kind: kind, Delegation: d, Credential: &policy.CredentialRef{IDs: ids, IssuedAt: iat}}
}

// TestRevocationListCheck (ADR-0026): which credentials a list kills.
func TestRevocationListCheck(t *testing.T) {
	l := &RevocationList{
		JTIs:     map[string]int64{"dead-jti": 9999},
		Subjects: map[string]int64{"agent:planner": 100, "alice@acme.com": 100, "workload:gh:acme/app": 100},
	}
	wl := func(iat int64, jti string) *policy.Subject {
		return &policy.Subject{ID: "workload:gh:acme/app", Kind: policy.SubjectWorkload, Credential: &policy.CredentialRef{IDs: []string{jti}, IssuedAt: iat}}
	}
	for _, c := range []struct {
		name    string
		sub     *policy.Subject
		revoked bool
	}{
		{"no credential (IdP user)", &policy.Subject{ID: "alice@acme.com"}, false},
		{"nil subject", nil, false},
		{"revoked jti", wl(500, "dead-jti"), true},
		{"workload issued at the epoch", wl(100, "w1"), true},
		{"workload issued after the epoch", wl(101, "w2"), false},
		{"revoked ancestor jti", agentSub("bob@acme.com", "", 500, 500, []string{"a1", "p1", "dead-jti"}, "reviewer"), true},
		{"agent in the chain, issued before its epoch", agentSub("bob@acme.com", "", 500, 99, []string{"a2"}, "planner", "reviewer"), true},
		{"agent in the chain, issued after its epoch", agentSub("bob@acme.com", "", 50, 101, []string{"a3"}, "planner"), false},
		{"human root authenticated before its epoch", agentSub("Alice@ACME.com", "", 90, 500, []string{"a4"}, "reviewer"), true},
		{"human root authenticated after its epoch", agentSub("alice@acme.com", "", 101, 500, []string{"a5"}, "reviewer"), false},
		{"workload-rooted chain, root issued before its epoch", agentSub("workload:gh:acme/app", policy.SubjectWorkload, 100, 500, []string{"a6", "w9"}, "reviewer"), true},
	} {
		err := l.Check(c.sub)
		if got := errors.Is(err, ErrCredentialRevoked); got != c.revoked {
			t.Errorf("%s: revoked=%v (%v), want %v", c.name, got, err, c.revoked)
		}
	}
	var nilList *RevocationList
	if err := nilList.Check(wl(1, "dead-jti")); err != nil {
		t.Fatalf("nil list: %v", err)
	}
	if rej := DirectoryReject("/v1/messages", l.Check(wl(1, "dead-jti"))); rej.Status != http.StatusUnauthorized || rej.Code != "credential_revoked" {
		t.Fatalf("rejection: %+v", rej)
	}
}

// TestDirectoryRevocations: the client fetches the list for credential
// holders only, reuses it for RevocationTTL (the propagation bound), and
// through an outage keeps a list younger than Grace; past Grace fail closed
// refuses and fail open keeps checking the last list it saw, never none.
func TestDirectoryRevocations(t *testing.T) {
	var mu sync.Mutex
	list := RevocationList{JTIs: map[string]int64{}, Subjects: map[string]int64{}}
	var hits, down atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("revocations") != "1" {
			_ = json.NewEncoder(w).Encode(DirectoryEntry{Active: true})
			return
		}
		hits.Add(1)
		if down.Load() == 1 || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
	}))
	t.Cleanup(srv.Close)
	c, err := NewDirectoryClient(srv.URL, "tok", time.Minute, 5*time.Minute, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	c.Now = func() time.Time { return now }
	ctx := context.Background()
	wl := &policy.Subject{ID: "workload:gh:acme/app", Kind: policy.SubjectWorkload, Credential: &policy.CredentialRef{IDs: []string{"w1"}, IssuedAt: now.Unix()}}
	agent := agentSub("workload:gh:acme/app", policy.SubjectWorkload, now.Unix(), now.Unix(), []string{"a1", "w1"}, "reviewer")

	if _, err := c.Resolve(ctx, &policy.Subject{ID: "alice@acme.com"}); err != nil || hits.Load() != 0 {
		t.Fatalf("a human IdP caller fetched the revocation list: %d %v", hits.Load(), err)
	}
	if got, err := c.Resolve(ctx, wl); err != nil || got.Credential == nil {
		t.Fatalf("workload before revocation: %+v %v", got, err)
	}
	mu.Lock()
	list.JTIs["w1"] = now.Add(time.Hour).Unix()
	mu.Unlock()
	now = now.Add(DefaultRevocationTTL - time.Second)
	if _, err := c.Resolve(ctx, agent); err != nil || hits.Load() != 1 {
		t.Fatalf("within RevocationTTL the cached list serves: %d %v", hits.Load(), err)
	}
	now = now.Add(time.Second)
	for _, s := range []*policy.Subject{wl, agent} { // the workload-rooted chain too
		if _, err := c.Resolve(ctx, s); !errors.Is(err, ErrCredentialRevoked) {
			t.Fatalf("%s at RevocationTTL: %v, want ErrCredentialRevoked", s.Delegation.Chain(), err)
		}
	}
	down.Store(1)
	now = now.Add(4 * time.Minute)
	if _, err := c.Resolve(ctx, wl); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("outage within grace: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := c.Resolve(ctx, wl); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("fail open past grace forgot a revocation it had seen: %v", err)
	}
	other := &policy.Subject{ID: "workload:gh:acme/other", Kind: policy.SubjectWorkload, Credential: &policy.CredentialRef{IDs: []string{"w2"}, IssuedAt: now.Unix()}}
	if _, err := c.Resolve(ctx, other); err != nil {
		t.Fatalf("fail open past grace: %v", err)
	}
	c.FailClosed = true
	if _, err := c.Resolve(ctx, other); !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("fail closed past grace: %v", err)
	}
	fresh, _ := NewDirectoryClient(srv.URL, "tok", 0, 0, nil, false)
	fresh.FailClosed = true
	if _, err := fresh.Resolve(ctx, other); !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("fail closed with no list ever fetched: %v", err)
	}
}
