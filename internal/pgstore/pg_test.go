package pgstore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// These tests run against a real Postgres when HALO_TEST_PG_DSN is set
// (see pgtest.OpenTest) and skip otherwise.

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	db, schema := pgtest.OpenTest(t)
	if err := db.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if applied, err := db.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("re-migrate must be a no-op: %v %v", applied, err)
	}
	// Replicas starting together: every migration applies exactly once.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		other, _ := pgtest.OpenTest(t, schema)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := other.Migrate(ctx); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestCheckSchemaMismatch(t *testing.T) {
	ctx := context.Background()
	db, _ := pgtest.OpenTest(t)
	// A database ahead of the binary is refused by both Migrate and CheckSchema.
	if err := exec(db, `INSERT INTO halo_schema_migrations (version, name) VALUES (999, '0999_future.sql')`); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckSchema(ctx); !errors.Is(err, pgstore.ErrSchema) || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("want newer-schema error, got %v", err)
	}
	if _, err := db.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("migrate on a newer schema: %v", err)
	}
	// Behind: no migrations table at all.
	if err := exec(db, `DROP TABLE halo_schema_migrations`); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckSchema(ctx); !errors.Is(err, pgstore.ErrSchema) || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("want behind-schema error, got %v", err)
	}
}

func exec(db *pgstore.DB, q string) error { return pgstore.ExecForTest(db, q) }

// TestJournalReplicas: two replicas append to one stream concurrently; each
// sees every record exactly once, in one global order, its own included.
func TestJournalReplicas(t *testing.T) {
	ctx := context.Background()
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	var seenA, seenB []string
	la, err := a.OpenLog(ctx, "devices", func(r []byte) { seenA = append(seenA, string(r)) })
	if err != nil {
		t.Fatal(err)
	}
	lb, err := b.OpenLog(ctx, "devices", func(r []byte) { seenB = append(seenB, string(r)) })
	if err != nil {
		t.Fatal(err)
	}
	var muA, muB sync.Mutex // a store's mutex serializes its own log use
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			muA.Lock()
			defer muA.Unlock()
			rec := fmt.Sprintf(`{"from":"a","i":%d}`, i)
			if err := la.Append(ctx, "", []byte(rec)); err != nil {
				t.Error(err)
				return
			}
			seenA = append(seenA, rec) // the caller applies its own record after Append
		}()
		go func() {
			defer wg.Done()
			muB.Lock()
			defer muB.Unlock()
			rec := fmt.Sprintf(`{"from":"b","i":%d}`, i)
			if err := lb.Append(ctx, "", []byte(rec)); err != nil {
				t.Error(err)
				return
			}
			seenB = append(seenB, rec)
		}()
	}
	wg.Wait()
	if err := la.Catchup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lb.Catchup(ctx); err != nil {
		t.Fatal(err)
	}
	if len(seenA) != 40 || strings.Join(seenA, ",") != strings.Join(seenB, ",") {
		t.Fatalf("replicas disagree:\na=%v\nb=%v", seenA, seenB)
	}
	// A fresh replica replays the same order.
	var seenC []string
	if _, err := a.OpenLog(ctx, "devices", func(r []byte) { seenC = append(seenC, string(r)) }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seenC, ",") != strings.Join(seenA, ",") {
		t.Fatal("fresh replay differs from the tailed order")
	}
	if _, err := a.OpenLog(ctx, "Bad Name", func([]byte) {}); err == nil {
		t.Fatal("invalid stream name accepted")
	}
}

func TestJournalKeyCompaction(t *testing.T) {
	ctx := context.Background()
	db, _ := pgtest.OpenTest(t)
	l, err := db.OpenLog(ctx, "requests", func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{`{"id":"x","v":1}`, `{"id":"y","v":1}`, `{"id":"x","v":2}`} {
		key := r[7:8]
		if err := l.Append(ctx, key, []byte(r)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Append(ctx, "", []byte(`{"unkeyed":1}`)); err != nil {
		t.Fatal(err)
	}
	var got []string
	if _, err := db.OpenLog(ctx, "requests", func(r []byte) { got = append(got, string(r)) }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != `{"id":"y","v":1},{"id":"x","v":2},{"unkeyed":1}` {
		t.Fatalf("compacted replay %v", got)
	}
	c, err := db.Counts(ctx)
	if err != nil || c["journal/requests"] != 3 {
		t.Fatalf("counts %v %v", c, err)
	}
}

func TestFencedWrites(t *testing.T) {
	ctx := context.Background()
	db, _ := pgtest.OpenTest(t)
	tok, ok, err := db.Acquire(ctx, "controller", "a", time.Minute)
	if err != nil || !ok || tok != 1 {
		t.Fatalf("acquire %d %v %v", tok, ok, err)
	}
	view := db.Fenced(pgstore.Fence{Name: "controller", Token: tok})
	l, err := view.OpenLog(ctx, "controller-state", func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(ctx, "", []byte(`{"experiment":"e"}`)); err != nil {
		t.Fatal("leader write refused:", err)
	}
	if err := view.PutDoc(ctx, "rollout-state", "r", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// The lease moves on (a's lease released, b takes it with token 2).
	if err := db.Release(ctx, "controller", "a"); err != nil {
		t.Fatal(err)
	}
	if tok2, ok, _ := db.Acquire(ctx, "controller", "b", time.Minute); !ok || tok2 != 2 {
		t.Fatalf("b acquire: %d %v", tok2, ok)
	}
	if err := l.Append(ctx, "", []byte(`{"experiment":"late"}`)); !errors.Is(err, pgstore.ErrFenced) {
		t.Fatalf("deposed leader's append: %v, want ErrFenced", err)
	}
	if err := view.PutDoc(ctx, "rollout-state", "r", []byte(`{"late":1}`)); !errors.Is(err, pgstore.ErrFenced) {
		t.Fatalf("deposed leader's doc write: %v, want ErrFenced", err)
	}
	if b, _, _ := view.GetDoc(ctx, "rollout-state", "r"); string(b) != `{}` {
		t.Fatalf("doc overwritten by a deposed leader: %s", b)
	}
}

func TestLeaseSQL(t *testing.T) {
	ctx := context.Background()
	db, _ := pgtest.OpenTest(t)
	ttl := 400 * time.Millisecond
	tok, ok, err := db.Acquire(ctx, "l", "a", ttl)
	if err != nil || !ok || tok != 1 {
		t.Fatalf("%d %v %v", tok, ok, err)
	}
	if tok, ok, _ := db.Acquire(ctx, "l", "a", ttl); !ok || tok != 1 {
		t.Fatalf("renewal changed the token: %d %v", tok, ok)
	}
	if _, ok, _ := db.Acquire(ctx, "l", "b", ttl); ok {
		t.Fatal("b took a live lease")
	}
	time.Sleep(ttl + 100*time.Millisecond)
	if tok, ok, _ := db.Acquire(ctx, "l", "b", ttl); !ok || tok != 2 {
		t.Fatalf("b after expiry: %d %v", tok, ok)
	}
	if err := db.Release(ctx, "l", "a"); err != nil { // not a's: no effect
		t.Fatal(err)
	}
	if _, ok, _ := db.Acquire(ctx, "l", "a", ttl); ok {
		t.Fatal("a's release of b's lease freed it")
	}
	if err := db.Release(ctx, "l", "b"); err != nil {
		t.Fatal(err)
	}
	if tok, ok, _ := db.Acquire(ctx, "l", "a", ttl); !ok || tok != 3 {
		t.Fatalf("a after b released: %d %v", tok, ok)
	}
}

// TestElectorPostgresFailover: two electors on the real lease table; the
// leader's process stops, the follower takes over with a higher token.
func TestElectorPostgresFailover(t *testing.T) {
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	tokens := make(chan int64, 4)
	lead := func(ctx context.Context, tok int64) { tokens <- tok; <-ctx.Done() }
	actx, stopA := context.WithCancel(context.Background())
	bctx, stopB := context.WithCancel(context.Background())
	defer stopB()
	ea := &pgstore.Elector{Store: a, Name: "controller", Holder: "a", TTL: 1500 * time.Millisecond}
	eb := &pgstore.Elector{Store: b, Name: "controller", Holder: "b", TTL: 1500 * time.Millisecond}
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() { defer close(doneA); ea.Run(actx, lead) }()
	first := <-tokens
	go func() { defer close(doneB); eb.Run(bctx, lead) }()
	time.Sleep(400 * time.Millisecond)
	if eb.Leader() {
		t.Fatal("two leaders")
	}
	stopA()
	<-doneA
	select {
	case second := <-tokens:
		if second <= first {
			t.Fatalf("token %d after %d", second, first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no failover")
	}
	stopB()
	<-doneB
}

func TestKV(t *testing.T) {
	ctx := context.Background()
	db, schema := pgtest.OpenTest(t)
	other, _ := pgtest.OpenTest(t, schema)
	exp := time.Now().Add(time.Minute)
	if ok, err := db.Add(ctx, "oidc-state", "s", nil, exp); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, _ := other.Add(ctx, "oidc-state", "s", nil, exp); ok {
		t.Fatal("a consumed login state was consumed again on another replica")
	}
	if err := db.Put(ctx, "enroll", "h", []byte("p"), exp); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := other.Get(ctx, "enroll", "h"); !ok || err != nil || string(v) != "p" {
		t.Fatalf("get %q %v %v", v, ok, err)
	}
	// Concurrent takes of one token across replicas: one winner.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := range 16 {
		d := db
		if i%2 == 1 {
			d = other
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := d.Take(ctx, "enroll", "h"); err != nil {
				t.Error(err)
			} else if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d replicas redeemed one enrollment token", wins)
	}
	// Expired entries: invisible, re-addable, not takeable.
	past := time.Now().Add(-time.Second)
	_ = db.Put(ctx, "x", "old", []byte("v"), past)
	if _, ok, _ := db.Get(ctx, "x", "old"); ok {
		t.Fatal("expired entry visible")
	}
	_, _ = db.Add(ctx, "y", "old", []byte("v"), time.Now().Add(-time.Second)) // reap of x does not touch y
	if _, ok, _ := db.Take(ctx, "y", "old"); ok {
		t.Fatal("expired entry taken")
	}
	_ = db.Put(ctx, "y", "k", []byte("v"), past)
	if ok, _ := db.Add(ctx, "z", "k", []byte("v"), exp); !ok {
		t.Fatal("add in another namespace")
	}
	if err := db.Delete(ctx, "z", "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.Get(ctx, "z", "k"); ok {
		t.Fatal("deleted entry visible")
	}
}

// TestAuditChainConcurrent: writers on two replicas append at once; the
// head-row lock keeps the chain strictly linear (seq 1..n, each prev = the
// previous hash) and every hash verifies.
func TestAuditChainConcurrent(t *testing.T) {
	ctx := context.Background()
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	sum := func(seq uint64, prev, body string) string {
		h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", seq, prev, body)))
		return hex.EncodeToString(h[:])
	}
	var wg sync.WaitGroup
	const n = 50
	for i := range n {
		d := a
		if i%2 == 1 {
			d = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := d.AppendAudit(ctx, func(seq uint64, head string) (pgstore.AuditLink, error) {
				body := fmt.Sprintf("entry-%d", i)
				return pgstore.AuditLink{Seq: seq + 1, Prev: head, Hash: sum(seq+1, head, body), Entry: []byte(body), At: time.Now()}, nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rows, err := pgstore.AuditLinksForTest(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != n {
		t.Fatalf("%d entries, want %d", len(rows), n)
	}
	prev := ""
	for i, l := range rows {
		if l.Seq != uint64(i)+1 || l.Prev != prev || l.Hash != sum(l.Seq, l.Prev, string(l.Entry)) {
			t.Fatalf("chain broken at %d: %+v", i, l)
		}
		prev = l.Hash
	}
	// A link that does not extend the head is refused.
	err = a.AppendAudit(ctx, func(seq uint64, head string) (pgstore.AuditLink, error) {
		return pgstore.AuditLink{Seq: seq + 2, Prev: head, Hash: "x", Entry: []byte("x"), At: time.Now()}, nil
	})
	if err == nil {
		t.Fatal("a forking link was appended")
	}
	if bodies, _ := a.AuditEntries(ctx); len(bodies) != n {
		t.Fatalf("refused link changed the log: %d", len(bodies))
	}
}

func TestReportsAndDocs(t *testing.T) {
	ctx := context.Background()
	db, _ := pgtest.OpenTest(t)
	for i := range 5 {
		if err := db.PutReport(ctx, "device:d1", "h1", []byte(fmt.Sprintf(`{"i":%d}`, i)), 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.PutReport(ctx, "host:h0", "h0", []byte(`{"i":9}`), 3); err != nil {
		t.Fatal(err)
	}
	all, err := db.Reports(ctx)
	if err != nil || len(all) != 2 || string(all[0]) != `{"i":9}` || string(all[1]) != `{"i":4}` {
		t.Fatalf("reports %q %v", all, err)
	}
	hist, err := db.ReportHistory(ctx, "device:d1", 50)
	if err != nil || len(hist) != 3 || string(hist[0]) != `{"i":4}` || string(hist[2]) != `{"i":2}` {
		t.Fatalf("history (newest first, trimmed to 3) %q %v", hist, err)
	}
	if _, ok, err := db.GetDoc(ctx, "k", "missing"); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if err := db.PutDoc(ctx, "k", "n", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := db.PutDoc(ctx, "k", "n", []byte("2")); err != nil {
		t.Fatal(err)
	}
	if b, ok, _ := db.GetDoc(ctx, "k", "n"); !ok || string(b) != "2" {
		t.Fatalf("doc %q", b)
	}
}

func TestPairsAndBudget(t *testing.T) {
	ctx := context.Background()
	db, schema := pgtest.OpenTest(t)
	other, _ := pgtest.OpenTest(t, schema)
	old := time.Now().Add(-48 * time.Hour)
	if err := db.AppendPair(ctx, "p1", old, []byte(`{"id":"p1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := other.AppendPair(ctx, "p2", time.Now(), []byte(`{"id":"p2"}`)); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendPair(ctx, "p2", time.Now(), []byte(`{"id":"dup"}`)); err != nil { // retried: stored once
		t.Fatal(err)
	}
	if n, err := db.PrunePairs(ctx, time.Now().Add(-24*time.Hour)); n != 1 || err != nil {
		t.Fatalf("prune %d %v", n, err)
	}
	var rows []string
	if err := db.Pairs(ctx, func(r []byte) error { rows = append(rows, string(r)); return nil }); err != nil || len(rows) != 1 || rows[0] != `{"id":"p2"}` {
		t.Fatalf("pairs %v %v", rows, err)
	}

	// Many workers on two replicas reserve 1.0 each against a 10.0 cap:
	// exactly 10 succeed, globally.
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := range 30 {
		d := db
		if i%2 == 1 {
			d = other
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := d.Reserve(ctx, "s", fmt.Sprintf("r%d", i), 1, 10, time.Minute)
			if err != nil {
				t.Error(err)
			} else if ok {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 10 {
		t.Fatalf("%d reservations of 1.0 under a 10.0 cap", won)
	}
	if err := db.Settle(ctx, "s", "r0", 1, 0.25); err != nil { // settle below the reservation
		t.Fatal(err)
	}
	if spent, _ := db.Spent(ctx, "s"); spent != 0.25 {
		t.Fatalf("spent %v", spent)
	}
	if ok, _ := db.Reserve(ctx, "s", "extra", 0.75, 10, time.Minute); !ok {
		t.Fatal("freed headroom not reservable")
	}
	if ok, _ := db.Reserve(ctx, "s", "over", 0.01, 10, time.Minute); ok {
		t.Fatal("over-cap reservation succeeded")
	}
	// A reservation whose worker died is reaped at expiry and charged in full.
	if ok, _ := db.Reserve(ctx, "t", "dead", 2, 10, time.Millisecond); !ok {
		t.Fatal("reserve")
	}
	time.Sleep(20 * time.Millisecond)
	if ok, _ := db.Reserve(ctx, "t", "live", 1, 10, time.Minute); !ok { // reaps "dead"
		t.Fatal("reserve after reap")
	}
	if spent, _ := db.Spent(ctx, "t"); spent != 2 {
		t.Fatalf("reaped reservation charged %v, want 2", spent)
	}
	if err := db.Settle(ctx, "t", "dead", 2, 3); err != nil { // the late settle adds only the excess
		t.Fatal(err)
	}
	if spent, _ := db.Spent(ctx, "t"); spent != 3 {
		t.Fatalf("spent %v after late settle, want 3", spent)
	}
	if spent, err := db.Spent(ctx, "none"); spent != 0 || err != nil {
		t.Fatalf("unknown scope %v %v", spent, err)
	}
}

func TestPingAndMetrics(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	if err := db.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	db.WriteMetrics(&sb)
	if !strings.Contains(sb.String(), "halo_db_errors_total 0") {
		t.Fatal(sb.String())
	}
	if _, _, err := db.GetDoc(context.Background(), "k", strings.Repeat("\x00", 1)); err == nil {
		t.Fatal("NUL in a text key must fail")
	}
	if db.Errors() != 1 {
		t.Fatalf("errors %d", db.Errors())
	}
	_ = db.Close()
	if err := db.Ping(context.Background()); err == nil {
		t.Fatal("ping on a closed pool")
	}
}

func TestBudgetLedger(t *testing.T) {
	ctx := context.Background()
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	inc := []pgstore.BudgetCounter{{Budget: "d", Key: "user:x", Bucket: 100, USD: 1.5, Tokens: 10}}
	keep := map[string]int64{"d": 50}
	var wg sync.WaitGroup
	dups := make(chan bool, 6)
	for i := range 6 {
		d := a
		if i%2 == 1 {
			d = b
		}
		wg.Go(func() {
			dup, err := d.ApplyBudget(ctx, "batch-1", inc, keep)
			if err != nil {
				t.Error(err)
			}
			dups <- dup
		})
	}
	wg.Wait()
	close(dups)
	applied := 0
	for d := range dups {
		if !d {
			applied++
		}
	}
	if applied != 1 {
		t.Fatalf("one batch applied %d times across replicas", applied)
	}
	if _, err := a.ApplyBudget(ctx, "batch-2", inc, keep); err != nil {
		t.Fatal(err)
	}
	got, err := b.BudgetCounters(ctx, [][2]string{{"d", "user:x"}})
	if err != nil || len(got) != 1 || got[0].USD != 3 || got[0].Tokens != 20 {
		t.Fatalf("counters %+v %v", got, err)
	}
	// Pruning: buckets before the window and budgets no longer in policy.
	_, _ = a.ApplyBudget(ctx, "batch-3", []pgstore.BudgetCounter{{Budget: "gone", Key: "org", Bucket: 100, USD: 1}}, nil)
	if all, _ := a.BudgetCounters(ctx, nil); len(all) != 2 {
		t.Fatalf("import-style apply (nil keep) must not prune: %+v", all)
	}
	if _, err := a.ApplyBudget(ctx, "batch-4", nil, map[string]int64{"d": 200}); err != nil {
		t.Fatal(err)
	}
	if all, _ := a.BudgetCounters(ctx, nil); len(all) != 0 {
		t.Fatalf("expired bucket and removed budget kept: %+v", all)
	}
	if got, err := a.BudgetCounters(ctx, [][2]string{}); got != nil || err != nil {
		t.Fatalf("empty key list: %v %v", got, err)
	}
}

func TestClaimPending(t *testing.T) {
	ctx := context.Background()
	db, _ := pgtest.OpenTest(t)
	view := map[string][2]bool{} // id -> known, pending
	holder := func(id string) (bool, bool) { v := view[id]; return v[0], v[1] }
	if ok, err := db.ClaimPending(ctx, "k", "r1", holder); !ok || err != nil {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	view["r1"] = [2]bool{true, true}
	if ok, _ := db.ClaimPending(ctx, "k", "r2", holder); ok {
		t.Fatal("claimed over a pending request")
	}
	view["r1"] = [2]bool{true, false} // decided, release lost
	if ok, _ := db.ClaimPending(ctx, "k", "r2", holder); !ok {
		t.Fatal("decided holder not replaced")
	}
	// r2 never reached the log (the replica died): young, it still holds.
	if ok, _ := db.ClaimPending(ctx, "k", "r3", holder); ok {
		t.Fatal("young unknown claim taken over")
	}
	if err := pgstore.ExecForTest(db, `UPDATE halo_request_pending SET claimed_at = now() - interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.ClaimPending(ctx, "k", "r3", holder); !ok {
		t.Fatal("orphan claim not taken over after it aged")
	}
	if err := db.ReleasePending(ctx, "k", "r2"); err != nil { // not the holder: no effect
		t.Fatal(err)
	}
	view["r3"] = [2]bool{true, true}
	if ok, _ := db.ClaimPending(ctx, "k", "r4", holder); ok {
		t.Fatal("stale release removed the live claim")
	}
	if err := db.ReleasePending(ctx, "k", "r3"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.ClaimPending(ctx, "k", "r4", holder); !ok {
		t.Fatal("claim after release")
	}
}
