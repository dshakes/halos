package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dshakes/halos/internal/storage"
)

// ---- audit chain ----

// AuditLink is one stored audit entry: its chain position and encoded body.
type AuditLink struct {
	Seq        uint64
	Hash, Prev string
	Entry      []byte
	At         time.Time
}

// AppendAudit appends one entry to the hash chain. The chain head row is
// locked (SELECT ... FOR UPDATE) for the whole transaction, so concurrent
// writers on any replica append strictly one after another; chain receives
// the head and returns the new link, which must extend it.
func (d *DB) AppendAudit(ctx context.Context, chain func(headSeq uint64, headHash string) (AuditLink, error)) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		var seq int64
		var hash string
		if err := t.QueryRowContext(ctx, `SELECT seq, hash FROM halo_audit_head WHERE id FOR UPDATE`).Scan(&seq, &hash); err != nil {
			return fmt.Errorf("pgstore: lock audit head: %w", err)
		}
		l, err := chain(uint64(seq), hash) //nolint:gosec // seq is a non-negative sequence
		if err != nil {
			return err
		}
		if l.Seq != uint64(seq)+1 || l.Prev != hash { //nolint:gosec // as above
			return fmt.Errorf("pgstore: audit link seq %d does not extend head %d", l.Seq, seq)
		}
		return insertAudit(ctx, t, l)
	})
}

func insertAudit(ctx context.Context, t *sql.Tx, l AuditLink) error {
	if _, err := t.ExecContext(ctx, `INSERT INTO halo_audit (seq, hash, prev, entry, at) VALUES ($1, $2, $3, $4, $5)`,
		int64(l.Seq), l.Hash, l.Prev, l.Entry, l.At); err != nil { //nolint:gosec // audit seq never exceeds int64
		return fmt.Errorf("pgstore: insert audit seq %d: %w", l.Seq, err)
	}
	if _, err := t.ExecContext(ctx, `UPDATE halo_audit_head SET seq = $1, hash = $2 WHERE id`, int64(l.Seq), l.Hash); err != nil { //nolint:gosec // as above
		return fmt.Errorf("pgstore: advance audit head: %w", err)
	}
	return nil
}

// AuditEntries returns every stored entry body, oldest first.
// ponytail: reads the whole chain like the file backend; page by seq if it gets big.
func (d *DB) AuditEntries(ctx context.Context) ([][]byte, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT entry FROM halo_audit ORDER BY seq`)
	if err != nil {
		return nil, d.fail(fmt.Errorf("pgstore: read audit: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, d.fail(fmt.Errorf("pgstore: read audit: %w", err))
		}
		out = append(out, b)
	}
	return out, d.fail(rows.Err())
}

// ---- fleet reports ----

// PutReport upserts the latest report for key and appends it to key's
// history, keeping the newest keep entries.
func (d *DB) PutReport(ctx context.Context, key, hostname string, report []byte, keep int) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `INSERT INTO halo_reports (rkey, hostname, report, updated_at) VALUES ($1, $2, $3, now())
			ON CONFLICT (rkey) DO UPDATE SET hostname = EXCLUDED.hostname, report = EXCLUDED.report, updated_at = now()`, key, hostname, report); err != nil {
			return fmt.Errorf("pgstore: put report: %w", err)
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO halo_report_history (rkey, report) VALUES ($1, $2)`, key, report); err != nil {
			return fmt.Errorf("pgstore: report history: %w", err)
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM halo_report_history WHERE rkey = $1 AND id <= (
			SELECT id FROM halo_report_history WHERE rkey = $1 ORDER BY id DESC OFFSET $2 LIMIT 1)`, key, keep); err != nil {
			return fmt.Errorf("pgstore: trim report history: %w", err)
		}
		return nil
	})
}

// Reports returns the latest report of every reporter.
func (d *DB) Reports(ctx context.Context) ([][]byte, error) {
	return d.blobs(ctx, `SELECT report FROM halo_reports ORDER BY hostname, rkey`)
}

// ReportHistory returns up to limit reports for key, newest first.
func (d *DB) ReportHistory(ctx context.Context, key string, limit int) ([][]byte, error) {
	return d.blobs(ctx, `SELECT report FROM halo_report_history WHERE rkey = $1 ORDER BY id DESC LIMIT $2`, key, limit)
}

func (d *DB) blobs(ctx context.Context, q string, args ...any) ([][]byte, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, d.fail(fmt.Errorf("pgstore: query: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, d.fail(fmt.Errorf("pgstore: scan: %w", err))
		}
		out = append(out, b)
	}
	return out, d.fail(rows.Err())
}

// ---- documents ----

// GetDoc returns document kind/name; ok is false when there is none.
func (d *DB) GetDoc(ctx context.Context, kind, name string) ([]byte, bool, error) {
	var b []byte
	err := d.db.QueryRowContext(ctx, `SELECT body FROM halo_docs WHERE kind = $1 AND name = $2`, kind, name).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, d.fail(fmt.Errorf("pgstore: get %s/%s: %w", kind, name, err))
	}
	return b, true, nil
}

const putDoc = `INSERT INTO halo_docs (kind, name, body, updated_at) VALUES ($1, $2, $3, now())
	ON CONFLICT (kind, name) DO UPDATE SET body = EXCLUDED.body, updated_at = now()`

// PutDoc stores document kind/name.
func (d *DB) PutDoc(ctx context.Context, kind, name string, body []byte) error {
	if _, err := d.db.ExecContext(ctx, putDoc, kind, name, body); err != nil {
		return d.fail(fmt.Errorf("pgstore: put %s/%s: %w", kind, name, err))
	}
	return nil
}

// ---- halo-shadow ----

// AppendPair stores one encoded pair row (idempotent on id).
func (d *DB) AppendPair(ctx context.Context, id string, at time.Time, row []byte) error {
	if _, err := d.db.ExecContext(ctx, `INSERT INTO halo_shadow_pairs (id, at, body) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, id, at, row); err != nil {
		return d.fail(fmt.Errorf("pgstore: append pair %s: %w", id, err))
	}
	return nil
}

// PrunePairs deletes pairs older than cutoff.
func (d *DB) PrunePairs(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := d.db.ExecContext(ctx, `DELETE FROM halo_shadow_pairs WHERE at < $1`, cutoff)
	if err != nil {
		return 0, d.fail(fmt.Errorf("pgstore: prune pairs: %w", err))
	}
	n, err := res.RowsAffected()
	return int(n), d.fail(err)
}

// Pairs calls fn with every stored pair row, oldest first.
func (d *DB) Pairs(ctx context.Context, fn func(row []byte) error) error {
	rows, err := d.db.QueryContext(ctx, `SELECT body FROM halo_shadow_pairs ORDER BY at, id`)
	if err != nil {
		return d.fail(fmt.Errorf("pgstore: read pairs: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return d.fail(fmt.Errorf("pgstore: read pairs: %w", err))
		}
		if err := fn(b); err != nil {
			return err
		}
	}
	return d.fail(rows.Err())
}

// Reserve books amount against scope's budget of limit USD, globally across
// replicas: one conditional UPDATE (spent+reserved+amount <= limit) decides.
// Reservations older than ttl (a worker that died before settling) are first
// reaped and charged in full, since their upstream calls may have been paid.
func (d *DB) Reserve(ctx context.Context, scope, id string, amount, limit float64, ttl time.Duration) (bool, error) {
	ok := false
	err := d.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `INSERT INTO halo_shadow_budget (scope) VALUES ($1) ON CONFLICT (scope) DO NOTHING`, scope); err != nil {
			return fmt.Errorf("pgstore: budget row: %w", err)
		}
		if _, err := t.ExecContext(ctx, `WITH gone AS (
				DELETE FROM halo_shadow_reservations WHERE scope = $1 AND expires_at <= now() RETURNING amount)
			UPDATE halo_shadow_budget SET reserved = reserved - s.total, spent = spent + s.total
			FROM (SELECT COALESCE(sum(amount), 0) AS total FROM gone) s WHERE scope = $1 AND s.total > 0`, scope); err != nil {
			return fmt.Errorf("pgstore: reap reservations: %w", err)
		}
		res, err := t.ExecContext(ctx, `UPDATE halo_shadow_budget SET reserved = reserved + $2
			WHERE scope = $1 AND spent + reserved + $2 <= $3`, scope, amount, limit)
		if err != nil {
			return fmt.Errorf("pgstore: reserve: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO halo_shadow_reservations (id, scope, amount, expires_at)
			VALUES ($1, $2, $3, now() + $4 * interval '1 millisecond')`, id, scope, amount, ttl.Milliseconds()); err != nil {
			return fmt.Errorf("pgstore: record reservation: %w", err)
		}
		ok = true
		return nil
	})
	return ok, err
}

// Settle swaps reservation id for the charged amount. If the reservation was
// already reaped (and charged in full) only the excess is added.
func (d *DB) Settle(ctx context.Context, scope, id string, amount, charged float64) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		var reserved float64
		err := t.QueryRowContext(ctx, `DELETE FROM halo_shadow_reservations WHERE id = $1 RETURNING amount`, id).Scan(&reserved)
		switch {
		case errors.Is(err, sql.ErrNoRows): // reaped: amount already in spent
			_, err = t.ExecContext(ctx, `UPDATE halo_shadow_budget SET spent = spent + $2 WHERE scope = $1`, scope, max(0, charged-amount))
		case err == nil:
			_, err = t.ExecContext(ctx, `UPDATE halo_shadow_budget SET reserved = reserved - $2, spent = spent + $3 WHERE scope = $1`, scope, reserved, charged)
		}
		if err != nil {
			return fmt.Errorf("pgstore: settle %s: %w", id, err)
		}
		return nil
	})
}

// ---- fenced view ----

// Fenced is the view of d a leader writes through: its logs (OpenLog) and
// document writes (PutDoc) commit only while f's lease is still held at f's
// token, so a deposed leader finishing a tick cannot overwrite its successor.
type Fenced struct {
	db *DB
	f  Fence
}

// Fenced returns d's view fenced by f.
func (d *DB) Fenced(f Fence) *Fenced { return &Fenced{d, f} }

// OpenLog implements storage.Opener with fenced appends.
func (v *Fenced) OpenLog(ctx context.Context, name string, replay func([]byte)) (storage.Log, error) {
	return v.db.OpenFencedLog(ctx, name, replay, v.f)
}

// GetDoc reads like DB.GetDoc.
func (v *Fenced) GetDoc(ctx context.Context, kind, name string) ([]byte, bool, error) {
	return v.db.GetDoc(ctx, kind, name)
}

// PutDoc is DB.PutDoc, refused with ErrFenced once the lease has moved on.
func (v *Fenced) PutDoc(ctx context.Context, kind, name string, body []byte) error {
	return v.db.tx(ctx, func(t *sql.Tx) error {
		if err := checkFence(ctx, t, v.f); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, putDoc, kind, name, body); err != nil {
			return fmt.Errorf("pgstore: put %s/%s: %w", kind, name, err)
		}
		return nil
	})
}

// ---- counts (import verification) ----

// Counts returns row counts: "journal/<stream>" per log stream, "audit",
// "reports" and "docs/<kind>".
func (d *DB) Counts(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for _, q := range []struct{ prefix, sql string }{
		{"journal/", `SELECT stream, count(*) FROM halo_journal GROUP BY stream`},
		{"", `SELECT 'audit', count(*) FROM halo_audit`},
		{"", `SELECT 'reports', count(*) FROM halo_reports`},
		{"docs/", `SELECT kind, count(*) FROM halo_docs GROUP BY kind`},
	} {
		if err := d.count(ctx, q.prefix, q.sql, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (d *DB) count(ctx context.Context, prefix, q string, out map[string]int64) error {
	rows, err := d.db.QueryContext(ctx, q)
	if err != nil {
		return d.fail(fmt.Errorf("pgstore: count: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return d.fail(fmt.Errorf("pgstore: count: %w", err))
		}
		out[prefix+k] = n
	}
	return d.fail(rows.Err())
}

// Spent returns scope's settled spend.
func (d *DB) Spent(ctx context.Context, scope string) (float64, error) {
	var v float64
	err := d.db.QueryRowContext(ctx, `SELECT spent FROM halo_shadow_budget WHERE scope = $1`, scope).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, d.fail(fmt.Errorf("pgstore: read spend: %w", err))
	}
	return v, nil
}
