package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ServiceToken is one service-account API token row (ADR-0036). Hash is the
// SHA-256 of the token; the token itself is never stored. Record is opaque to
// this package.
type ServiceToken struct {
	ID      string
	Hash    []byte
	Expires time.Time
	Revoked bool
	Record  []byte
}

// serviceTokenRetention is how long a row is kept past its expiry, so the
// list still shows recently expired tokens.
const serviceTokenRetention = 30 * 24 * time.Hour

// ErrServiceTokenLimit is PutServiceToken's refusal at the active-token cap.
var ErrServiceTokenLimit = errors.New("service token limit reached")

// serviceTokenLock serializes the cap check and insert across replicas.
const serviceTokenLock = 0x73617463 // "satc"

// PutServiceToken inserts a new token unless maxActive tokens (not revoked,
// expiring after now) already exist (ErrServiceTokenLimit): the count and the
// insert are one transaction under an advisory lock, so concurrent creations
// on any replicas never exceed it. An existing id is an error (ids are
// random: a collision is a bug, never an overwrite). Long-expired rows are pruned.
func (d *DB) PutServiceToken(ctx context.Context, t ServiceToken, maxActive int, now time.Time) error {
	x, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return d.fail(fmt.Errorf("pgstore: put service token: %w", err))
	}
	defer func() { _ = x.Rollback() }() // no-op after Commit
	if _, err := x.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, serviceTokenLock); err != nil {
		return d.fail(fmt.Errorf("pgstore: lock service tokens: %w", err))
	}
	var n int
	if err := x.QueryRowContext(ctx, `SELECT count(*) FROM halo_service_tokens WHERE NOT revoked AND expires_at > $1`, now).Scan(&n); err != nil {
		return d.fail(fmt.Errorf("pgstore: count service tokens: %w", err))
	}
	if n >= maxActive {
		return ErrServiceTokenLimit // a refusal, not a database error
	}
	if err := putServiceToken(ctx, x, t); err != nil {
		return d.fail(err)
	}
	if err := x.Commit(); err != nil {
		return d.fail(fmt.Errorf("pgstore: put service token: %w", err))
	}
	if _, err := d.db.ExecContext(ctx, `DELETE FROM halo_service_tokens WHERE expires_at <= now() - $1 * interval '1 second'`, int64(serviceTokenRetention/time.Second)); err != nil {
		return d.fail(fmt.Errorf("pgstore: prune service tokens: %w", err))
	}
	return nil
}

func putServiceToken(ctx context.Context, x execer, t ServiceToken) error {
	if t.Record == nil {
		t.Record = []byte{} // nil would be SQL NULL
	}
	if _, err := x.ExecContext(ctx, `INSERT INTO halo_service_tokens (id, hash, expires_at, revoked, record) VALUES ($1, $2, $3, $4, $5)`,
		t.ID, t.Hash, t.Expires, t.Revoked, t.Record); err != nil {
		return fmt.Errorf("pgstore: put service token: %w", err)
	}
	return nil
}

// PutServiceToken stores a token as DB.PutServiceToken does (no pruning).
func (im *Importer) PutServiceToken(t ServiceToken) error { return putServiceToken(im.ctx, im.t, t) }

// RevokeServiceToken marks id revoked and replaces its record, unless it is
// already revoked (the first revocation's record stands). It returns the row
// as stored and whether it exists.
func (d *DB) RevokeServiceToken(ctx context.Context, id string, record []byte) (ServiceToken, bool, error) {
	if record == nil {
		record = []byte{}
	}
	if _, err := d.db.ExecContext(ctx, `UPDATE halo_service_tokens SET revoked = TRUE, record = $2 WHERE id = $1 AND NOT revoked`, id, record); err != nil {
		return ServiceToken{}, false, d.fail(fmt.Errorf("pgstore: revoke service token: %w", err))
	}
	return d.ServiceToken(ctx, id)
}

// ServiceToken returns the row with id: one primary-key lookup, for the
// per-request check.
func (d *DB) ServiceToken(ctx context.Context, id string) (ServiceToken, bool, error) {
	var t ServiceToken
	err := d.db.QueryRowContext(ctx, `SELECT id, hash, expires_at, revoked, record FROM halo_service_tokens WHERE id = $1`, id).
		Scan(&t.ID, &t.Hash, &t.Expires, &t.Revoked, &t.Record)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceToken{}, false, nil
	}
	if err != nil {
		return ServiceToken{}, false, d.fail(fmt.Errorf("pgstore: read service token: %w", err))
	}
	return t, true, nil
}

// ServiceTokens lists every row, oldest expiry first.
func (d *DB) ServiceTokens(ctx context.Context) ([]ServiceToken, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, hash, expires_at, revoked, record FROM halo_service_tokens ORDER BY expires_at, id`)
	if err != nil {
		return nil, d.fail(fmt.Errorf("pgstore: list service tokens: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	var out []ServiceToken
	for rows.Next() {
		var t ServiceToken
		if err := rows.Scan(&t.ID, &t.Hash, &t.Expires, &t.Revoked, &t.Record); err != nil {
			return nil, d.fail(fmt.Errorf("pgstore: list service tokens: %w", err))
		}
		out = append(out, t)
	}
	return out, d.fail(rows.Err())
}
