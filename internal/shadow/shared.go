package shadow

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PairDB is a pair table shared by every halo-shadow replica (pgstore.DB).
type PairDB interface {
	AppendPair(ctx context.Context, id string, at time.Time, row []byte) error
	PrunePairs(ctx context.Context, cutoff time.Time) (int, error)
}

// DBStore stores pairs in a shared table, one row per pair in exactly the
// FileStore row format (sealed with the pair key when one is set), so
// workers keep no state and `halo-shadow decrypt-pairs` reads an export.
type DBStore struct {
	db   PairDB
	seal sealer
	ttl  time.Duration
}

// NewDBStore returns a Store on db with FileStore's options.
func NewDBStore(db PairDB, o StoreOptions) (*DBStore, error) {
	seal, err := newSealer(o.Key)
	if err != nil {
		return nil, err
	}
	return &DBStore{db: db, seal: seal, ttl: o.Retention}, nil
}

// Append implements Store; a retried pair (same id) is stored once.
func (s *DBStore) Append(ctx context.Context, p Pair) error {
	b, err := s.seal.row(p)
	if err != nil {
		return err
	}
	if err := s.db.AppendPair(ctx, p.ID, p.Time, b); err != nil {
		return fmt.Errorf("shadow: store pair %s: %w", p.ID, err)
	}
	return nil
}

// pruneTimeout bounds one retention sweep.
const pruneTimeout = time.Minute

// Prune deletes pairs older than Retention (no-op if 0). Every replica may
// run it; the DELETE is idempotent.
func (s *DBStore) Prune(now time.Time) (int, error) {
	if s.ttl <= 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), pruneTimeout)
	defer cancel()
	n, err := s.db.PrunePairs(ctx, now.Add(-s.ttl))
	if err != nil {
		return 0, fmt.Errorf("shadow: prune pairs: %w", err)
	}
	return n, nil
}

// Close implements io.Closer; the database is the caller's to close.
func (s *DBStore) Close() error { return nil }

// Budget books a job's worst-case cost before anything is sent and settles
// it to the charged cost afterwards. The default is per process; SharedBudget
// makes the cap global across replicas.
type Budget interface {
	// Reserve books est under reservation id; false = over budget.
	Reserve(ctx context.Context, id string, est float64) (bool, error)
	// Settle swaps reservation id (of est) for charged.
	Settle(ctx context.Context, id string, est, charged float64) error
	// Spent is the settled spend.
	Spent(ctx context.Context) (float64, error)
}

// localBudget is the in-process Budget (one replica).
type localBudget struct {
	mu              sync.Mutex
	limit           float64
	spent, reserved float64
}

func (b *localBudget) Reserve(_ context.Context, _ string, est float64) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.spent+b.reserved+est > b.limit {
		return false, nil
	}
	b.reserved += est
	return true, nil
}

func (b *localBudget) Settle(_ context.Context, _ string, est, charged float64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reserved -= est
	b.spent += charged
	return nil
}

func (b *localBudget) Spent(context.Context) (float64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spent, nil
}

// BudgetDB is the shared budget table (pgstore.DB).
type BudgetDB interface {
	Reserve(ctx context.Context, scope, id string, amount, limit float64, ttl time.Duration) (bool, error)
	Settle(ctx context.Context, scope, id string, amount, charged float64) error
	Spent(ctx context.Context, scope string) (float64, error)
}

// ReservationTTL is how long an unsettled reservation lives before it is
// reaped and charged in full: longer than queueing plus both upstream calls.
const ReservationTTL = 15 * time.Minute

// SharedBudget is one budget for every replica: a reservation is a
// conditional UPDATE (spent+reserved+est <= Limit) on the scope's row.
type SharedBudget struct {
	DB    BudgetDB
	Scope string  // budget name; change it to start a fresh budget
	Limit float64 // USD
}

// Reserve implements Budget.
func (b SharedBudget) Reserve(ctx context.Context, id string, est float64) (bool, error) {
	return b.DB.Reserve(ctx, b.Scope, id, est, b.Limit, ReservationTTL)
}

// Settle implements Budget.
func (b SharedBudget) Settle(ctx context.Context, id string, est, charged float64) error {
	return b.DB.Settle(ctx, b.Scope, id, est, charged)
}

// Spent implements Budget.
func (b SharedBudget) Spent(ctx context.Context) (float64, error) { return b.DB.Spent(ctx, b.Scope) }
