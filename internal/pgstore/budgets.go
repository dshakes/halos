package pgstore

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
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
// receiving the same retry exactly one counts it. The upserts run in
// (budget, key, bucket) order, so two transactions touching the same rows
// lock them in the same order and cannot deadlock. Nothing is pruned here:
// see PruneBudgets.
func (d *DB) ApplyBudget(ctx context.Context, batch string, incs []BudgetCounter) (duplicate bool, err error) {
	incs = slices.Clone(incs)
	slices.SortFunc(incs, func(a, b BudgetCounter) int {
		return cmp.Or(cmp.Compare(a.Budget, b.Budget), cmp.Compare(a.Key, b.Key), cmp.Compare(a.Bucket, b.Bucket))
	})
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
		return nil
	})
	return duplicate, err
}

// PruneBudgets drops what no budget can still count, judged on the database
// clock and nothing else: buckets that started more than retention ago (the
// caller passes the longest window policy allows), and batch ids older than
// budgetBatchMemory. It never consults a replica's policy, so a replica on a
// stale policy cannot delete the counters of a budget it does not know yet; a
// removed budget's rows simply age out. Safe on any replica, any number of times.
func (d *DB) PruneBudgets(ctx context.Context, retention time.Duration) (int64, error) {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM halo_budget_batches WHERE applied_at < now() - $1 * interval '1 second'`, int64(budgetBatchMemory.Seconds())); err != nil {
		return 0, d.fail(fmt.Errorf("pgstore: prune budget batches: %w", err))
	}
	res, err := d.db.ExecContext(ctx, `DELETE FROM halo_budget_buckets WHERE bucket < extract(epoch FROM now())::bigint - $1`, int64(retention.Seconds()))
	if err != nil {
		return 0, d.fail(fmt.Errorf("pgstore: prune budget buckets: %w", err))
	}
	n, err := res.RowsAffected()
	return n, d.fail(err)
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

// auditDescPage is how many rows one backwards page of EachAuditDesc reads.
const auditDescPage = 500

// EachAuditDesc streams stored audit entries newest first, in pages of
// auditDescPage keyed on seq (ORDER BY seq DESC LIMIT), until fn returns
// false: a tail read touches only the rows it returns, not the whole table.
func (d *DB) EachAuditDesc(ctx context.Context, fn func(seq uint64, entry []byte) bool) error {
	before := int64(math.MaxInt64)
	for {
		rows, err := d.db.QueryContext(ctx, `SELECT seq, entry FROM halo_audit WHERE seq < $1 ORDER BY seq DESC LIMIT $2`, before, auditDescPage)
		if err != nil {
			return d.fail(fmt.Errorf("pgstore: read audit: %w", err))
		}
		n, stop := 0, false
		for rows.Next() {
			var seq int64
			var b []byte
			if err := rows.Scan(&seq, &b); err != nil {
				_ = rows.Close() // already failing
				return d.fail(fmt.Errorf("pgstore: read audit: %w", err))
			}
			n, before = n+1, seq
			if !fn(uint64(seq), b) { //nolint:gosec // seq is positive
				stop = true
				break
			}
		}
		err = rows.Err()
		_ = rows.Close() // read-only
		if err != nil {
			return d.fail(fmt.Errorf("pgstore: read audit: %w", err))
		}
		if stop || n < auditDescPage {
			return nil
		}
	}
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
