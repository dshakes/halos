package pgstore

import (
	"context"
	"database/sql"
	"io/fs"
)

// ExecForTest runs raw SQL (tests own their schema).
func ExecForTest(d *DB, q string) error {
	_, err := d.db.ExecContext(context.Background(), q)
	return err
}

// FenceTxForTest runs one fenced transaction the way every fenced write does:
// begin, beforeCheck, checkFence, hold, then insert a document and commit.
func FenceTxForTest(d *DB, f Fence, beforeCheck, hold func()) error {
	ctx := context.Background()
	return d.tx(ctx, func(t *sql.Tx) error {
		beforeCheck()
		if err := checkFence(ctx, t, f); err != nil {
			return err
		}
		hold()
		_, err := t.ExecContext(ctx, putDoc, "fence-test", "x", []byte("v"))
		return err
	})
}

// ParseMigrationsForTest exposes the migration parser for header checks.
func ParseMigrationsForTest(fsys fs.FS, dir string) (int, error) {
	ms, err := parseMigrations(fsys, dir)
	return len(ms), err
}

// AuditLinksForTest returns the stored chain positions, oldest first.
func AuditLinksForTest(d *DB) ([]AuditLink, error) {
	rows, err := d.db.QueryContext(context.Background(), `SELECT seq, hash, prev, entry FROM halo_audit ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditLink
	for rows.Next() {
		var l AuditLink
		var seq int64
		if err := rows.Scan(&seq, &l.Hash, &l.Prev, &l.Entry); err != nil {
			return nil, err
		}
		l.Seq = uint64(seq) //nolint:gosec // test: seq is positive
		out = append(out, l)
	}
	return out, rows.Err()
}
