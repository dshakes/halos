package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Revocation is one credential revocation row (ADR-0026). Kind is "jti" or
// "subject"; Epoch is a subject's revoked-before time (unix seconds, 0 for a
// jti); Record is opaque to this package.
type Revocation struct {
	Kind, Key string
	Epoch     int64
	Expires   time.Time
	Record    []byte
}

// PutRevocation records r in one upsert that never weakens a live row: the
// epoch and the expiry only move forward (GREATEST), and the record follows
// the larger epoch. Expired rows are pruned.
func (d *DB) PutRevocation(ctx context.Context, r Revocation) error {
	if err := putRevocation(ctx, d.db, r); err != nil {
		return d.fail(err)
	}
	if _, err := d.db.ExecContext(ctx, `DELETE FROM halo_revocations WHERE expires_at <= now()`); err != nil {
		return d.fail(fmt.Errorf("pgstore: prune revocations: %w", err))
	}
	return nil
}

// execer is *sql.DB or *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func putRevocation(ctx context.Context, x execer, r Revocation) error {
	if r.Record == nil {
		r.Record = []byte{} // nil would be SQL NULL
	}
	if _, err := x.ExecContext(ctx, `INSERT INTO halo_revocations (kind, rkey, epoch, expires_at, record) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (kind, rkey) DO UPDATE SET
			record = CASE WHEN EXCLUDED.epoch >= halo_revocations.epoch OR halo_revocations.expires_at <= now() THEN EXCLUDED.record ELSE halo_revocations.record END,
			epoch = CASE WHEN halo_revocations.expires_at <= now() THEN EXCLUDED.epoch ELSE GREATEST(halo_revocations.epoch, EXCLUDED.epoch) END,
			expires_at = GREATEST(halo_revocations.expires_at, EXCLUDED.expires_at)`,
		r.Kind, r.Key, r.Epoch, r.Expires, r.Record); err != nil {
		return fmt.Errorf("pgstore: put revocation: %w", err)
	}
	return nil
}

// PutRevocation stores a revocation as DB.PutRevocation does (no pruning).
func (im *Importer) PutRevocation(r Revocation) error { return putRevocation(im.ctx, im.t, r) }

// Revocations returns every live revocation, ordered by kind and key.
func (d *DB) Revocations(ctx context.Context) ([]Revocation, error) {
	return d.revocations(ctx, `SELECT kind, rkey, epoch, expires_at, record FROM halo_revocations WHERE expires_at > now() ORDER BY kind, rkey`)
}

// RevocationsFor returns the live revocations of the given jtis and
// subjects: one indexed query, for the per-request check.
func (d *DB) RevocationsFor(ctx context.Context, jtis, subjects []string) ([]Revocation, error) {
	if len(jtis) == 0 && len(subjects) == 0 {
		return nil, nil
	}
	return d.revocations(ctx, `SELECT kind, rkey, epoch, expires_at, record FROM halo_revocations
		WHERE expires_at > now() AND ((kind = 'jti' AND rkey = ANY($1::text[])) OR (kind = 'subject' AND rkey = ANY($2::text[])))`,
		nonNil(jtis), nonNil(subjects))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (d *DB) revocations(ctx context.Context, q string, args ...any) ([]Revocation, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, d.fail(fmt.Errorf("pgstore: read revocations: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	var out []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.Kind, &r.Key, &r.Epoch, &r.Expires, &r.Record); err != nil {
			return nil, d.fail(fmt.Errorf("pgstore: read revocations: %w", err))
		}
		out = append(out, r)
	}
	return out, d.fail(rows.Err())
}
