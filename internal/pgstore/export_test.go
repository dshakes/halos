package pgstore

import "context"

// ExecForTest runs raw SQL (tests own their schema).
func ExecForTest(d *DB, q string) error {
	_, err := d.db.ExecContext(context.Background(), q)
	return err
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
