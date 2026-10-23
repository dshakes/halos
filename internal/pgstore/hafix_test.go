package pgstore_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// TestFenceHoldsOffTakeover (M1): a fenced transaction that passed its check
// keeps the lease row FOR SHARE until it commits, so a takeover waits for it
// instead of committing while the fenced write is still in flight.
func TestFenceHoldsOffTakeover(t *testing.T) {
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	ctx := context.Background()
	tok, ok, err := a.Acquire(ctx, "controller", "a", 300*time.Millisecond)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	release := make(chan struct{})
	checked := make(chan struct{})
	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- pgstore.FenceTxForTest(a, pgstore.Fence{Name: "controller", Token: tok}, func() {}, func() {
			close(checked)
			<-release
		})
	}()
	<-checked
	time.Sleep(400 * time.Millisecond) // the lease has expired on the database clock
	acquired := make(chan int64, 1)
	go func() {
		tok2, ok, err := b.Acquire(ctx, "controller", "b", time.Minute)
		if err != nil || !ok {
			t.Error("takeover:", ok, err)
		}
		acquired <- tok2
	}()
	select {
	case <-acquired:
		close(release)
		<-fenceDone
		t.Fatal("takeover committed while a fenced write that passed its check was still open")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-fenceDone; err != nil {
		t.Fatalf("fenced write: %v", err)
	}
	if tok2 := <-acquired; tok2 <= tok {
		t.Fatalf("takeover token %d after %d", tok2, tok)
	}
}

// TestFenceUsesCheckTime (M1): the expiry is judged when the check runs, not
// when the transaction began: a transaction opened before the lease expired
// and checking after it must be fenced.
func TestFenceUsesCheckTime(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	ctx := context.Background()
	tok, _, err := db.Acquire(ctx, "controller", "a", 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	err = pgstore.FenceTxForTest(db, pgstore.Fence{Name: "controller", Token: tok}, func() { time.Sleep(500 * time.Millisecond) }, func() {})
	if !errors.Is(err, pgstore.ErrFenced) {
		t.Fatalf("check after expiry in a transaction begun before it: %v, want ErrFenced", err)
	}
}

// TestKVLockSQL (H1, L2): owner-checked release and database-clock expiry.
func TestKVLockSQL(t *testing.T) {
	a, schema := pgtest.OpenTest(t)
	b, _ := pgtest.OpenTest(t, schema)
	ctx := context.Background()
	if ok, err := a.TryLock(ctx, "lock", "scim", "owner-a", 300*time.Millisecond); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := b.TryLock(ctx, "lock", "scim", "owner-b", time.Minute); ok {
		t.Fatal("held lock taken")
	}
	if ok, _ := a.TryLock(ctx, "lock", "scim", "owner-a", 300*time.Millisecond); !ok {
		t.Fatal("owner cannot extend")
	}
	time.Sleep(400 * time.Millisecond)
	if ok, _ := b.TryLock(ctx, "lock", "scim", "owner-b", time.Minute); !ok {
		t.Fatal("expired lock not taken over")
	}
	if err := a.Unlock(ctx, "lock", "scim", "owner-a"); err != nil { // a's late release
		t.Fatal(err)
	}
	if ok, _ := a.TryLock(ctx, "lock", "scim", "owner-c", time.Minute); ok {
		t.Fatal("a stale owner's Unlock released the new holder's lock")
	}
	// Concurrent takers: exactly one wins.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := range 12 {
		d := a
		if i%2 == 1 {
			d = b
		}
		wg.Go(func() {
			if ok, err := d.TryLock(ctx, "lock", "race", fmt.Sprint("o", i), time.Minute); err != nil {
				t.Error(err)
			} else if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d owners took one lock", wins)
	}
}

// TestKVRaiseSQL (L3): an epoch never moves backwards, whoever writes last.
func TestKVRaiseSQL(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	if err := db.Raise(ctx, "enroll-drop", "u", 200, exp); err != nil {
		t.Fatal(err)
	}
	if err := db.Raise(ctx, "enroll-drop", "u", 100, exp.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := db.Get(ctx, "enroll-drop", "u"); string(v) != "200" {
		t.Fatalf("epoch moved backwards: %s", v)
	}
	if err := db.Raise(ctx, "enroll-drop", "u", 300, exp); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := db.Get(ctx, "enroll-drop", "u"); string(v) != "300" {
		t.Fatalf("epoch not raised: %s", v)
	}
}

// TestSchemaRollbackCompat (M7): an older binary runs against a newer schema
// whose newer migrations declare it compatible, and refuses one that does not.
func TestSchemaRollbackCompat(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	ctx := context.Background()
	want := pgstore.SchemaVersion()
	// A newer, additive migration (min-binary-schema 1) applied by a newer binary.
	if err := pgstore.ExecForTest(db, fmt.Sprintf(`INSERT INTO halo_schema_migrations (version, name, min_binary) VALUES (%d, 'future_additive.sql', 1)`, want+1)); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckSchema(ctx); err != nil {
		t.Fatalf("older binary refused a compatible newer schema: %v", err)
	}
	if applied, err := db.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("migrate on a compatible newer schema: %v %v", applied, err)
	}
	// A newer migration that needs a binary at its own version.
	if err := pgstore.ExecForTest(db, fmt.Sprintf(`INSERT INTO halo_schema_migrations (version, name, min_binary) VALUES (%d, 'future_breaking.sql', %d)`, want+2, want+2)); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckSchema(ctx); !errors.Is(err, pgstore.ErrSchema) || !strings.Contains(err.Error(), "upgrade halo-server") {
		t.Fatalf("incompatible newer schema: %v", err)
	}
	if _, err := db.Migrate(ctx); err == nil {
		t.Fatal("migrate accepted an incompatible newer schema")
	}
}

// TestMigrationHeaders: every shipped migration declares min-binary-schema,
// and the parser refuses one that does not (the additive-only policy).
func TestMigrationHeaders(t *testing.T) {
	if pgstore.SchemaVersion() < 2 {
		t.Fatal("shipped migrations do not parse")
	}
	bad := fstest.MapFS{"m/0001_x.sql": {Data: []byte("CREATE TABLE x (a int);\n")}}
	if _, err := pgstore.ParseMigrationsForTest(bad, "m"); err == nil || !strings.Contains(err.Error(), "min-binary-schema") {
		t.Fatalf("migration without a header: %v", err)
	}
	ahead := fstest.MapFS{"m/0001_x.sql": {Data: []byte("-- min-binary-schema: 2\nSELECT 1;\n")}}
	if _, err := pgstore.ParseMigrationsForTest(ahead, "m"); err == nil {
		t.Fatal("min-binary-schema above the migration's own version accepted")
	}
	ok := fstest.MapFS{"m/0001_x.sql": {Data: []byte("-- min-binary-schema: 1\nSELECT 1;\n")}}
	if n, err := pgstore.ParseMigrationsForTest(ok, "m"); n != 1 || err != nil {
		t.Fatal(n, err)
	}
}

// TestCheckTLS (L5): a remote host must verify the certificate and host name.
func TestCheckTLS(t *testing.T) {
	for dsn, ok := range map[string]bool{
		"postgres://u:p@db.internal:5432/halos?sslmode=verify-full":   true,
		"postgres://u:p@db.internal:5432/halos?sslmode=verify-ca":     false,
		"postgres://u:p@db.internal:5432/halos?sslmode=require":       false,
		"postgres://u:p@db.internal:5432/halos?sslmode=prefer":        false,
		"postgres://u:p@db.internal:5432/halos":                       false, // default prefer
		"postgres://u:p@db.internal:5432/halos?sslmode=disable":       false,
		"postgres://u:p@127.0.0.1:5432/halos?sslmode=disable":         true, // loopback never leaves the host
		"postgres://u:p@localhost:5432/halos?sslmode=disable":         true,
		"postgres://u:p@[::1]:5432/halos?sslmode=disable":             true,
		"host=/var/run/postgresql dbname=halos sslmode=disable":       true, // Unix socket
		"postgres://u:p@a,db.internal:5432/halos?sslmode=verify-full": true,
	} {
		err := pgstore.CheckTLS(dsn)
		if (err == nil) != ok {
			t.Errorf("%s: %v, want ok=%v", dsn, err, ok)
		}
		if err != nil && strings.Contains(err.Error(), ":p@") {
			t.Errorf("error leaks the password: %v", err)
		}
	}
	if _, err := pgstore.OpenWith(context.Background(), "postgres://u:p@db.internal:5432/halos?sslmode=require", pgstore.Options{}); !errors.Is(err, pgstore.ErrInsecureTLS) {
		t.Fatalf("OpenWith without --database-insecure-tls: %v", err)
	}
}

// TestAuditTailPaged (M6): newest-first reads stop at what they need.
func TestAuditTailPaged(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	ctx := context.Background()
	for i := range 1200 {
		err := db.AppendAudit(ctx, func(seq uint64, head string) (pgstore.AuditLink, error) {
			return pgstore.AuditLink{Seq: seq + 1, Prev: head, Hash: fmt.Sprintf("h%d", i), Entry: []byte(`{}`), At: time.Now()}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var seqs []uint64
	if err := db.EachAuditDesc(ctx, func(seq uint64, _ []byte) bool { seqs = append(seqs, seq); return len(seqs) < 3 }); err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 3 || seqs[0] != 1200 || seqs[2] != 1198 {
		t.Fatalf("tail %v", seqs)
	}
	n := 0
	if err := db.EachAuditDesc(ctx, func(uint64, []byte) bool { n++; return true }); err != nil || n != 1200 {
		t.Fatalf("full descending read across pages: %d %v", n, err)
	}
}

// TestImportIsTransactional (L6): an import that fails verification leaves
// the database empty, so it can be run again.
func TestImportIsTransactional(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	ctx := context.Background()
	err := db.Import(ctx, func(im *pgstore.Importer) error {
		if err := im.AppendJournal("devices", []byte(`{"id":"d1"}`)); err != nil {
			return err
		}
		if err := im.PutDoc("rollout-state", "r", []byte(`{}`)); err != nil {
			return err
		}
		return errors.New("verify failed")
	})
	if err == nil {
		t.Fatal("failed import reported success")
	}
	c, err := db.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, n := range c {
		if n != 0 {
			t.Fatalf("a failed import left %d rows in %s", n, k)
		}
	}
	for _, k := range []string{"kv", "leases", "request-pending", "budget-batches", "budget-buckets", "shadow-pairs", "audit", "reports"} {
		if _, ok := c[k]; !ok {
			t.Errorf("Counts does not cover %s", k)
		}
	}
	// A database holding anything (here a lease) is refused.
	if _, _, err := db.Acquire(ctx, "controller", "x", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.Import(ctx, func(*pgstore.Importer) error { return nil }); !errors.Is(err, pgstore.ErrNotEmpty) {
		t.Fatalf("import into a database holding a lease: %v", err)
	}
}
