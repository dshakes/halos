package pgstore_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// TestServiceTokensSQL (ADR-0036): insert refuses a duplicate id, the point
// lookup and list see the other replica's rows, a revocation is visible on
// every replica at once and never undone, and long-expired rows are pruned.
func TestServiceTokensSQL(t *testing.T) {
	ctx := context.Background()
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	tok := pgstore.ServiceToken{ID: "0123456789abcdef", Hash: []byte("h1"), Expires: exp, Record: []byte(`{"name":"bot"}`)}
	if err := a.PutServiceToken(ctx, tok, 100, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := b.PutServiceToken(ctx, tok, 100, time.Now()); err == nil {
		t.Fatal("duplicate id overwrote a token")
	}
	got, ok, err := b.ServiceToken(ctx, tok.ID)
	if err != nil || !ok || string(got.Hash) != "h1" || !got.Expires.Equal(exp) || got.Revoked {
		t.Fatalf("lookup on the other replica: %+v %v %v", got, ok, err)
	}
	if _, ok, err := b.ServiceToken(ctx, "ffffffffffffffff"); ok || err != nil {
		t.Fatalf("unknown id: %v %v", ok, err)
	}
	r, ok, err := a.RevokeServiceToken(ctx, tok.ID, []byte(`{"reason":"first"}`))
	if err != nil || !ok || !r.Revoked {
		t.Fatalf("revoke: %+v %v %v", r, ok, err)
	}
	r, _, _ = b.RevokeServiceToken(ctx, tok.ID, []byte(`{"reason":"second"}`))
	if string(r.Record) != `{"reason":"first"}` {
		t.Fatalf("second revocation replaced the first record: %s", r.Record)
	}
	if got, _, _ := b.ServiceToken(ctx, tok.ID); !got.Revoked {
		t.Fatal("revocation not visible on the other replica")
	}
	if _, ok, err := a.RevokeServiceToken(ctx, "ffffffffffffffff", nil); ok || err != nil {
		t.Fatalf("revoke unknown: %v %v", ok, err)
	}
	old := pgstore.ServiceToken{ID: "aaaaaaaaaaaaaaaa", Hash: []byte("h2"), Expires: time.Now().Add(-40 * 24 * time.Hour), Record: []byte(`{}`)}
	if err := a.PutServiceToken(ctx, old, 100, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.PutServiceToken(ctx, pgstore.ServiceToken{ID: "bbbbbbbbbbbbbbbb", Hash: []byte("h3"), Expires: exp}, 100, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The cap counts live, unrevoked rows only (bbbb...), atomically across replicas.
	if err := b.PutServiceToken(ctx, pgstore.ServiceToken{ID: "cccccccccccccccc", Hash: []byte("h4"), Expires: exp}, 1, time.Now()); !errors.Is(err, pgstore.ErrServiceTokenLimit) {
		t.Fatalf("over the cap: %v", err)
	}
	var wg sync.WaitGroup
	var okN atomic.Int32
	for i := range 10 {
		db := a
		if i%2 == 1 {
			db = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("d%015x", i)
			if err := db.PutServiceToken(ctx, pgstore.ServiceToken{ID: id, Hash: []byte(id), Expires: exp}, 5, time.Now()); err == nil {
				okN.Add(1)
			} else if !errors.Is(err, pgstore.ErrServiceTokenLimit) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if okN.Load() != 4 { // bbbb... plus four reach the cap of five
		t.Fatalf("concurrent inserts under a cap of 5 with one live: %d succeeded", okN.Load())
	}
	for i := range 10 {
		if _, _, err := a.RevokeServiceToken(ctx, fmt.Sprintf("d%015x", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	all, err := b.ServiceTokens(ctx)
	if err != nil || len(all) != 6 { // live, the revoked first token, four capped-in rows; the 40-day-old one pruned
		t.Fatalf("list after prune: %+v %v", all, err)
	}
	n, err := a.Counts(ctx)
	if err != nil || n["service-tokens"] != 6 {
		t.Fatalf("counts: %v %v", n, err)
	}
}
