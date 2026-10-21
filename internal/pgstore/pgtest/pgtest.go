// Package pgtest opens throwaway Postgres schemas for integration tests.
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/pgstore"
)

// TestDSNEnv names the variable holding a Postgres URL for integration
// tests; they skip when it is unset.
const TestDSNEnv = "HALO_TEST_PG_DSN"

// Schema creates an empty schema in the HALO_TEST_PG_DSN database (dropped
// when t ends) and returns its name, or skips t when the variable is unset.
func Schema(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv(TestDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set: skipping Postgres integration test", TestDSNEnv)
	}
	var b [6]byte
	_, _ = rand.Read(b[:]) // test-only: crypto/rand does not fail
	name := "halo_test_" + hex.EncodeToString(b[:])
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(context.Background(), "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+name+" CASCADE") // best effort
		_ = admin.Close()
	})
	return name
}

// OpenTest returns a migrated DB in a fresh schema (see Schema). Each call
// opens its own pool, so two calls on one schema model two replicas: pass
// the first call's schema to share it.
func OpenTest(t testing.TB, schema ...string) (*pgstore.DB, string) {
	t.Helper()
	var name string
	if len(schema) > 0 {
		name = schema[0]
	} else {
		name = Schema(t)
	}
	ctx := context.Background()
	db, err := pgstore.Open(ctx, URL(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return db, name
}

// URL is the HALO_TEST_PG_DSN database URL with schema first on the search path.
func URL(schema string) string {
	dsn := os.Getenv(TestDSNEnv)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}
