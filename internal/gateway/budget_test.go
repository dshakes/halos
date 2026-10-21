package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/policy"
)

type budgetSrv struct {
	*httptest.Server
	mu      sync.Mutex
	spent   budget.Spend // what /check reports as spent
	batches []BudgetUsage
	checks  atomic.Int64
	fail    atomic.Bool
}

func newBudgetSrv(t *testing.T) *budgetSrv {
	t.Helper()
	s := &budgetSrv{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || s.fail.Load() {
			http.Error(w, "no", http.StatusServiceUnavailable)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/b/check":
			s.checks.Add(1)
			_ = json.NewEncoder(w).Encode(BudgetVerdict{Budgets: []budget.Status{{Budget: "u", Key: "user:a", Action: policy.BudgetEnforce, LimitUSD: 10, SpentUSD: s.spent.USD, SpentTokens: s.spent.Tokens}}})
		case "/b/usage":
			var in BudgetUsage
			_ = json.NewDecoder(r.Body).Decode(&in)
			s.batches = append(s.batches, in)
			for _, rec := range in.Records {
				s.spent.USD += rec.USD
				s.spent.Tokens += rec.Tokens
			}
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestBudgetClientCacheAndGrace(t *testing.T) {
	srv := newBudgetSrv(t)
	now := time.Unix(1_000_000, 0)
	c, err := NewBudgetClient(srv.URL+"/b/", "tok", time.Minute, 10*time.Minute, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	c.Now = func() time.Time { return now }
	alice := budget.Principal{Subject: "a", Groups: []string{"y", "x"}, Ring: "ga"}
	ctx := context.Background()

	if st, ok := c.Check(ctx, alice); !ok || len(st) != 1 || st[0].SpentUSD != 0 {
		t.Fatalf("first check: %v %+v", ok, st)
	}
	// Local usage counts at once; group order does not split the cache.
	c.Record(budget.Principal{Subject: "a", Groups: []string{"x", "y"}, Ring: "ga"}, budget.Spend{USD: 4, Tokens: 40}, now)
	if st, _ := c.Check(ctx, alice); st[0].SpentUSD != 4 || st[0].SpentTokens != 40 || srv.checks.Load() != 1 {
		t.Fatalf("cached check with local usage: %+v (server checks %d)", st, srv.checks.Load())
	}
	// Refetch after TTL: the unreported 4 USD carries over, not lost, not doubled.
	now = now.Add(time.Minute)
	if st, _ := c.Check(ctx, alice); st[0].SpentUSD != 4 || srv.checks.Load() != 2 {
		t.Fatalf("refetch before report: %+v", st)
	}
	if err := c.FlushNow(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if st, _ := c.Check(ctx, alice); st[0].SpentUSD != 4 {
		t.Fatalf("after report the server holds it, once: %+v", st)
	}
	// halo-server down: the cached verdict serves for Grace, then unknown.
	srv.fail.Store(true)
	now = now.Add(5 * time.Minute)
	if st, ok := c.Check(ctx, alice); !ok || st[0].SpentUSD != 4 {
		t.Fatalf("within grace: %v %+v", ok, st)
	}
	now = now.Add(10 * time.Minute)
	if _, ok := c.Check(ctx, alice); ok {
		t.Fatal("past grace must be unknown")
	}
	if _, ok := c.Check(ctx, budget.Principal{Subject: "never-seen"}); ok {
		t.Fatal("no verdict and server down must be unknown")
	}
}

// A failed report is retried with the same batch id (the server dedupes on
// it), and large backlogs go out in bounded batches.
func TestBudgetClientFlush(t *testing.T) {
	srv := newBudgetSrv(t)
	c, err := NewBudgetClient(srv.URL+"/b", "tok", 0, 0, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(999_960, 0) // on a minute boundary
	for i := range maxBudgetBatch + 10 {
		c.Record(budget.Principal{Subject: fmt.Sprint("u", i)}, budget.Spend{USD: 0.5, Tokens: 5}, at)
	}
	c.Record(budget.Principal{Subject: "u0"}, budget.Spend{USD: 0.5, Tokens: 5}, at.Add(30*time.Second)) // same minute: one record
	srv.fail.Store(true)
	if err := c.FlushNow(context.Background()); err == nil {
		t.Fatal("want error from a failing server")
	}
	first := c.inflight.Batch
	srv.fail.Store(false)
	if err := c.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.batches) != 2 || srv.batches[0].Batch != first || len(srv.batches[0].Records) != maxBudgetBatch || len(srv.batches[1].Records) != 10 {
		t.Fatalf("batches: %d (%d, %d records), first id %q vs %q", len(srv.batches), len(srv.batches[0].Records), len(srv.batches[1].Records), srv.batches[0].Batch, first)
	}
	if srv.spent.Tokens != int64(5*(maxBudgetBatch+11)) {
		t.Fatalf("server got %d tokens", srv.spent.Tokens)
	}
	if rep, failed, dropped := c.Counters(); rep != 2 || failed != 1 || dropped != 0 || len(c.unflushed) != 0 || len(c.pending) != 0 {
		t.Fatalf("counters %d/%d/%d, unflushed %d pending %d", rep, failed, dropped, len(c.unflushed), len(c.pending))
	}
}

func TestBudgetClientDropsWhenFull(t *testing.T) {
	c, _ := NewBudgetClient("https://halo.test/b", "tok", 0, 0, 0, nil, false)
	at := time.Unix(1_000_000, 0)
	for i := range maxBudgetPending + 3 {
		c.Record(budget.Principal{Subject: fmt.Sprint(i)}, budget.Spend{Tokens: 1}, at)
	}
	if _, _, dropped := c.Counters(); dropped != 3 {
		t.Fatalf("dropped %d, want 3", dropped)
	}
}

func TestNewBudgetClient(t *testing.T) {
	for name, tc := range map[string]struct{ url, tok string }{
		"no url":     {"", "t"},
		"no token":   {"https://h/b", ""},
		"plain http": {"http://halo.test/b", "t"},
	} {
		if _, err := NewBudgetClient(tc.url, tc.tok, 0, 0, 0, nil, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c, err := NewBudgetClient("http://127.0.0.1:9/b", "t", 0, 0, 0, nil, false)
	if err != nil || c.TTL != DefaultBudgetTTL || c.Grace != DefaultBudgetGrace || c.Flush != DefaultBudgetFlush {
		t.Fatalf("loopback http with defaults: %v %+v", err, c)
	}
}
