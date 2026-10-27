package pgstore_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// TestRevocationsSQL (ADR-0026): a live row's epoch and expiry never move
// backwards, expired rows are invisible and pruned, the point lookup returns
// only the asked keys, and two replicas see each other's rows.
func TestRevocationsSQL(t *testing.T) {
	ctx := context.Background()
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	exp := time.Now().Add(time.Hour)
	put := func(db *pgstore.DB, r pgstore.Revocation) {
		t.Helper()
		if err := db.PutRevocation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	put(a, pgstore.Revocation{Kind: "subject", Key: "agent:planner", Epoch: 200, Expires: exp, Record: []byte(`{"reason":"second"}`)})
	put(b, pgstore.Revocation{Kind: "subject", Key: "agent:planner", Epoch: 100, Expires: exp.Add(-time.Minute), Record: []byte(`{"reason":"first"}`)})
	put(a, pgstore.Revocation{Kind: "jti", Key: "j1", Expires: exp})
	put(a, pgstore.Revocation{Kind: "jti", Key: "gone", Expires: time.Now().Add(-time.Second)})

	all, err := b.Revocations(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("live rows on the other replica: %+v %v", all, err)
	}
	if s := all[1]; s.Kind != "subject" || s.Epoch != 200 || string(s.Record) != `{"reason":"second"}` || !s.Expires.Equal(exp.Truncate(time.Microsecond)) {
		t.Fatalf("epoch/expiry/record moved backwards: %+v", s)
	}
	got, err := a.RevocationsFor(ctx, []string{"j1", "nope"}, []string{"workload:x"})
	if err != nil || len(got) != 1 || got[0].Key != "j1" {
		t.Fatalf("point lookup: %+v %v", got, err)
	}
	if got, err := a.RevocationsFor(ctx, nil, nil); err != nil || got != nil {
		t.Fatalf("empty lookup: %+v %v", got, err)
	}
	n, err := a.Counts(ctx)
	if err != nil || n["revocations"] != 2 {
		t.Fatalf("expired row not pruned: %v %v", n, err)
	}
}

// TestCountAuthFailure: the shared failed-auth count increments atomically
// across replicas within a window and restarts after it (database clock).
func TestCountAuthFailure(t *testing.T) {
	ctx := context.Background()
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	var wg sync.WaitGroup
	for i := range 20 {
		db := a
		if i%2 == 1 {
			db = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.CountAuthFailure(ctx, "scim/192.0.2.1", time.Minute); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, err := a.CountAuthFailure(ctx, "scim/192.0.2.1", time.Minute); err != nil || n != 21 {
		t.Fatalf("count after 20 concurrent failures: %d %v", n, err)
	}
	if n, err := b.CountAuthFailure(ctx, "scim/198.51.100.1", time.Minute); err != nil || n != 1 {
		t.Fatalf("another key: %d %v", n, err)
	}
	if n, err := a.CountAuthFailure(ctx, "agent/192.0.2.9", time.Millisecond); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	time.Sleep(20 * time.Millisecond)
	if n, err := a.CountAuthFailure(ctx, "agent/192.0.2.9", time.Millisecond); err != nil || n != 1 {
		t.Fatalf("window did not restart: %d %v", n, err)
	}
}
