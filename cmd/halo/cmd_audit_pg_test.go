package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/server"
)

// TestAuditVerifyDatabase: `halo audit verify --database-url-file` checks the
// HA backend's chain (HALO_TEST_PG_DSN; skipped otherwise).
func TestAuditVerifyDatabase(t *testing.T) {
	db, schema := pgtest.OpenTest(t)
	b := server.NewPGBackend(db)
	ctx := context.Background()
	for range 3 {
		if err := b.AppendAudit(ctx, server.AuditEntry{Time: time.Now().UTC(), Actor: "ops", Action: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	url := filepath.Join(t.TempDir(), "url")
	if err := os.WriteFile(url, []byte(pgtest.URL(schema)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := verifyAudit(ctx, "", url, false)
	if err != nil || r.Error != "" || r.Entries != 3 {
		t.Fatalf("verify: %+v %v", r, err)
	}
	raw, err := sql.Open("pgx", pgtest.URL(schema))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.ExecContext(ctx, `UPDATE halo_audit SET entry = convert_to(replace(convert_from(entry, 'UTF8'), '"ops"', '"mallory"'), 'UTF8') WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	if r, err := verifyAudit(ctx, "", url, false); err != nil || r.Error == "" {
		t.Fatalf("tampered chain verified: %+v %v", r, err)
	}
}
