package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// BudgetCounter is one bucket of one budget counter.
type BudgetCounter struct {
	Budget, Key string
	Bucket      int64 // bucket start, unix seconds
	USD         float64
	Tokens      int64
}

// budgetBatchMemory is how long an applied usage batch id is remembered
// (budget.batchMemory): a gateway replica retries a batch whose answer it lost.
const budgetBatchMemory = time.Hour

// ApplyBudget adds incs to the counters unless batch was already applied, in
// one transaction: the batch id's primary key decides, so of two replicas
// receiving the same retry exactly one counts it. keep maps each budget still
// in policy to the oldest bucket start still inside its window; other buckets
// and budgets are pruned in the same transaction.
func (d *DB) ApplyBudget(ctx context.Context, batch string, incs []BudgetCounter, keep map[string]int64) (duplicate bool, err error) {
	err = d.tx(ctx, func(t *sql.Tx) error {
		if batch != "" {
			res, err := t.ExecContext(ctx, `INSERT INTO halo_budget_batches (batch) VALUES ($1) ON CONFLICT (batch) DO NOTHING`, batch)
			if err != nil {
				return fmt.Errorf("pgstore: budget batch: %w", err)
			}
			if n, err := res.RowsAffected(); err != nil || n == 0 {
				duplicate = err == nil
				return err
			}
		}
		for _, c := range incs {
			if _, err := t.ExecContext(ctx, `INSERT INTO halo_budget_buckets (budget, rkey, bucket, usd, tokens) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (budget, rkey, bucket) DO UPDATE SET usd = halo_budget_buckets.usd + EXCLUDED.usd, tokens = halo_budget_buckets.tokens + EXCLUDED.tokens`,
				c.Budget, c.Key, c.Bucket, c.USD, c.Tokens); err != nil {
				return fmt.Errorf("pgstore: budget %s/%s: %w", c.Budget, c.Key, err)
			}
		}
		return pruneBudgets(ctx, t, keep)
	})
	return duplicate, err
}

func pruneBudgets(ctx context.Context, t *sql.Tx, keep map[string]int64) error {
	if _, err := t.ExecContext(ctx, `DELETE FROM halo_budget_batches WHERE applied_at < now() - $1 * interval '1 second'`, int64(budgetBatchMemory.Seconds())); err != nil {
		return fmt.Errorf("pgstore: prune budget batches: %w", err)
	}
	if keep == nil { // no policy view (import): prune nothing else
		return nil
	}
	names := make([]string, 0, len(keep))
	for name, oldest := range keep {
		names = append(names, name)
		if _, err := t.ExecContext(ctx, `DELETE FROM halo_budget_buckets WHERE budget = $1 AND bucket < $2`, name, oldest); err != nil {
			return fmt.Errorf("pgstore: prune budget %s: %w", name, err)
		}
	}
	sort.Strings(names)
	if _, err := t.ExecContext(ctx, `DELETE FROM halo_budget_buckets WHERE NOT (budget = ANY($1))`, names); err != nil {
		return fmt.Errorf("pgstore: prune removed budgets: %w", err)
	}
	return nil
}

// BudgetCounters returns the buckets of the given (budget, key) counters, or
// of every counter when keys is nil.
func (d *DB) BudgetCounters(ctx context.Context, keys [][2]string) ([]BudgetCounter, error) {
	if keys != nil && len(keys) == 0 {
		return nil, nil
	}
	q, args := `SELECT budget, rkey, bucket, usd, tokens FROM halo_budget_buckets`, []any{}
	if keys != nil {
		bs, ks := make([]string, len(keys)), make([]string, len(keys))
		for i, k := range keys {
			bs[i], ks[i] = k[0], k[1]
		}
		q += ` WHERE (budget, rkey) IN (SELECT * FROM unnest($1::text[], $2::text[]))`
		args = append(args, bs, ks)
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, d.fail(fmt.Errorf("pgstore: read budgets: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	var out []BudgetCounter
	for rows.Next() {
		var c BudgetCounter
		if err := rows.Scan(&c.Budget, &c.Key, &c.Bucket, &c.USD, &c.Tokens); err != nil {
			return nil, d.fail(fmt.Errorf("pgstore: read budgets: %w", err))
		}
		out = append(out, c)
	}
	return out, d.fail(rows.Err())
}

// ---- pending access requests ----

// orphanClaimAge: a claim whose request never reached the log (the replica
// died between claim and append) is taken over after this long. A younger
// unknown holder may just be about to append.
const orphanClaimAge = time.Minute

// ClaimPending makes requestID the one pending request for dedupe; ok=false
// when another pending request holds it. The primary key decides between
// concurrent claims. holder reports what the caller's request log says about
// the current holder: a known request that is no longer pending (decided)
// is replaced at once; an unknown one only once its claim is orphanClaimAge
// old. Replacement is a compare-and-swap on the holder's id.
func (d *DB) ClaimPending(ctx context.Context, dedupe, requestID string, holder func(id string) (known, pending bool)) (bool, error) {
	for range 3 { // a lost compare-and-swap means someone else moved: look again
		res, err := d.db.ExecContext(ctx, `INSERT INTO halo_request_pending (dedupe, request_id) VALUES ($1, $2) ON CONFLICT (dedupe) DO NOTHING`, dedupe, requestID)
		if err != nil {
			return false, d.fail(fmt.Errorf("pgstore: claim request: %w", err))
		}
		if n, err := res.RowsAffected(); err != nil || n == 1 {
			return err == nil, d.fail(err)
		}
		var cur string
		err = d.db.QueryRowContext(ctx, `SELECT request_id FROM halo_request_pending WHERE dedupe = $1`, dedupe).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, d.fail(fmt.Errorf("pgstore: claim request: %w", err))
		}
		known, pending := holder(cur)
		if pending {
			return false, nil
		}
		minAge := int64(0)
		if !known {
			minAge = int64(orphanClaimAge.Seconds())
		}
		res, err = d.db.ExecContext(ctx, `UPDATE halo_request_pending SET request_id = $3, claimed_at = now()
			WHERE dedupe = $1 AND request_id = $2 AND claimed_at <= now() - $4 * interval '1 second'`, dedupe, cur, requestID, minAge)
		if err != nil {
			return false, d.fail(fmt.Errorf("pgstore: claim request: %w", err))
		}
		n, err := res.RowsAffected()
		switch {
		case err != nil || n == 1:
			return err == nil, d.fail(err)
		case !known: // a young claim whose request may be about to land: it holds
			return false, nil
		}
	}
	return false, errors.New("pgstore: claim request: contended")
}

// ReleasePending drops dedupe's claim if requestID still holds it.
func (d *DB) ReleasePending(ctx context.Context, dedupe, requestID string) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM halo_request_pending WHERE dedupe = $1 AND request_id = $2`, dedupe, requestID); err != nil {
		return d.fail(fmt.Errorf("pgstore: release request claim: %w", err))
	}
	return nil
}

// ---- documents by kind ----

// Docs returns every document of kind, by name.
func (d *DB) Docs(ctx context.Context, kind string) ([][]byte, error) {
	return d.blobs(ctx, `SELECT body FROM halo_docs WHERE kind = $1 ORDER BY name`, kind)
}

// ---- audit reads ----

// EachAudit streams stored audit entries with seq >= from, in seq order,
// until fn returns false.
func (d *DB) EachAudit(ctx context.Context, from uint64, fn func(seq uint64, entry []byte) bool) error {
	rows, err := d.db.QueryContext(ctx, `SELECT seq, entry FROM halo_audit WHERE seq >= $1 ORDER BY seq`, int64(from)) //nolint:gosec // seq fits int64
	if err != nil {
		return d.fail(fmt.Errorf("pgstore: read audit: %w", err))
	}
	defer func() { _ = rows.Close() }() // read-only
	for rows.Next() {
		var seq int64
		var b []byte
		if err := rows.Scan(&seq, &b); err != nil {
			return d.fail(fmt.Errorf("pgstore: read audit: %w", err))
		}
		if !fn(uint64(seq), b) { //nolint:gosec // seq is positive
			return nil
		}
	}
	return d.fail(rows.Err())
}

// AuditHead returns the chain head (seq 0 and "" when empty).
func (d *DB) AuditHead(ctx context.Context) (uint64, string, error) {
	var seq int64
	var hash string
	if err := d.db.QueryRowContext(ctx, `SELECT seq, hash FROM halo_audit_head WHERE id`).Scan(&seq, &hash); err != nil {
		return 0, "", d.fail(fmt.Errorf("pgstore: read audit head: %w", err))
	}
	return uint64(seq), hash, nil //nolint:gosec // seq is non-negative
}
