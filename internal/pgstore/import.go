package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// importLock serializes imports (and keeps two from interleaving).
const importLock = 0x696d7074 // "impt"

// ErrNotEmpty means an import's target already holds state.
var ErrNotEmpty = errors.New("pgstore: target database is not empty")

// Importer writes a whole data-dir import inside one transaction: either all
// of it commits, after the caller verified it through the same transaction,
// or none of it does and the import can simply be run again.
type Importer struct {
	ctx context.Context
	t   *sql.Tx
	db  *DB
}

// Import runs fn in one transaction that it first checks is starting from
// an empty database (every table Counts covers). fn returning an error, or a
// failed commit, leaves the database as it was.
func (d *DB) Import(ctx context.Context, fn func(*Importer) error) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, importLock); err != nil {
			return fmt.Errorf("pgstore: import lock: %w", err)
		}
		im := &Importer{ctx: ctx, t: t, db: d}
		c, err := im.Counts()
		if err != nil {
			return err
		}
		for k, n := range c {
			if n > 0 {
				return fmt.Errorf("%w (%s has %d rows): import into a freshly migrated database", ErrNotEmpty, k, n)
			}
		}
		return fn(im)
	})
}

// Counts is DB.Counts inside the import transaction.
func (im *Importer) Counts() (map[string]int64, error) { return counts(im.ctx, im.t) }

// AppendJournal appends one record to stream.
func (im *Importer) AppendJournal(stream string, body []byte) error {
	if _, err := im.t.ExecContext(im.ctx, `INSERT INTO halo_journal (stream, body) VALUES ($1, $2)`, stream, body); err != nil {
		return fmt.Errorf("pgstore: import %s: %w", stream, err)
	}
	return nil
}

// AppendAudit appends an already-chained entry; it must extend the head.
func (im *Importer) AppendAudit(l AuditLink) error {
	var seq int64
	var hash string
	if err := im.t.QueryRowContext(im.ctx, `SELECT seq, hash FROM halo_audit_head WHERE id FOR UPDATE`).Scan(&seq, &hash); err != nil {
		return fmt.Errorf("pgstore: lock audit head: %w", err)
	}
	if l.Seq != uint64(seq)+1 || l.Prev != hash { //nolint:gosec // seq is non-negative
		return fmt.Errorf("pgstore: audit link seq %d does not extend head %d", l.Seq, seq)
	}
	return insertAudit(im.ctx, im.t, l)
}

// EachAudit streams the imported chain (seq order) for verification.
func (im *Importer) EachAudit(fn func(seq uint64, entry []byte) bool) error {
	rows, err := im.t.QueryContext(im.ctx, `SELECT seq, entry FROM halo_audit ORDER BY seq`)
	if err != nil {
		return fmt.Errorf("pgstore: read audit: %w", err)
	}
	defer func() { _ = rows.Close() }() // read-only
	for rows.Next() {
		var seq int64
		var b []byte
		if err := rows.Scan(&seq, &b); err != nil {
			return fmt.Errorf("pgstore: read audit: %w", err)
		}
		if !fn(uint64(seq), b) { //nolint:gosec // seq is positive
			return nil
		}
	}
	return rows.Err()
}

// PutReport stores a reporter's latest report (history starts with it).
func (im *Importer) PutReport(key, hostname string, report []byte) error {
	if _, err := im.t.ExecContext(im.ctx, `INSERT INTO halo_reports (rkey, hostname, report, updated_at) VALUES ($1, $2, $3, now())`, key, hostname, report); err != nil {
		return fmt.Errorf("pgstore: import report: %w", err)
	}
	if _, err := im.t.ExecContext(im.ctx, `INSERT INTO halo_report_history (rkey, report) VALUES ($1, $2)`, key, report); err != nil {
		return fmt.Errorf("pgstore: import report history: %w", err)
	}
	return nil
}

// PutDoc stores document kind/name.
func (im *Importer) PutDoc(kind, name string, body []byte) error {
	if _, err := im.t.ExecContext(im.ctx, putDoc, kind, name, body); err != nil {
		return fmt.Errorf("pgstore: import %s/%s: %w", kind, name, err)
	}
	return nil
}

// AddBudget adds counter buckets.
func (im *Importer) AddBudget(incs []BudgetCounter) error {
	for _, c := range incs {
		if _, err := im.t.ExecContext(im.ctx, `INSERT INTO halo_budget_buckets (budget, rkey, bucket, usd, tokens) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (budget, rkey, bucket) DO UPDATE SET usd = halo_budget_buckets.usd + EXCLUDED.usd, tokens = halo_budget_buckets.tokens + EXCLUDED.tokens`,
			c.Budget, c.Key, c.Bucket, c.USD, c.Tokens); err != nil {
			return fmt.Errorf("pgstore: import budget %s/%s: %w", c.Budget, c.Key, err)
		}
	}
	return nil
}
