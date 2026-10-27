package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/storage"
)

// Backend is the shared state that lets several halo-server replicas serve
// one fleet (ADR-0021). Config.Backend nil means the single-replica default:
// JSONL files under DataDir and in-process ephemeral state.
type Backend interface {
	storage.Opener // device, request, session-revocation, SCIM logs
	storage.KV     // enrollment tokens, login states, server-side sessions, claims, workload jti
	// AppendAudit chains e after the current head under a lock held across
	// replicas, filling Seq, Prev and Hash.
	AppendAudit(ctx context.Context, e AuditEntry) error
	// EachAudit streams entries with seq >= from, oldest first, with their
	// stored bytes, until fn returns false. A row that does not decode is
	// passed zero-valued, so verification breaks there.
	EachAudit(ctx context.Context, from uint64, fn func(raw []byte, e AuditEntry) bool) error
	// EachAuditDesc streams entries newest first until fn returns false,
	// reading only as many rows as it is given (paged ORDER BY seq DESC).
	EachAuditDesc(ctx context.Context, fn func(raw []byte, e AuditEntry) bool) error
	// AuditHead is the newest entry's seq and hash.
	AuditHead(ctx context.Context) (uint64, string, error)
	// RolloutStates is where the controller's rollout state lives.
	RolloutStates() rollout.StateStore
	// Docs lists every document of kind (verdicts: one per experiment).
	Docs(ctx context.Context, kind string) ([][]byte, error)
	// Leased runs fn on exactly one replica at a time (lease name) until ctx
	// ends; docs writes through the view fn gets are fenced by that lease.
	Leased(ctx context.Context, name string, fn func(ctx context.Context, docs rollout.Docs))
	// ApplyBudget adds usage unless batch was applied before (atomic, any replica).
	ApplyBudget(ctx context.Context, batch string, incs []pgstore.BudgetCounter) (duplicate bool, err error)
	// PruneBudgets drops buckets older than retention and stale batch ids,
	// on the store's clock and independent of any replica's policy.
	PruneBudgets(ctx context.Context, retention time.Duration) (int64, error)
	// BudgetCounters reads the given (budget, key) counters; nil = all.
	BudgetCounters(ctx context.Context, keys [][2]string) ([]pgstore.BudgetCounter, error)
	// ClaimPending makes requestID the one pending access request for dedupe
	// (atomic across replicas; see pgstore.DB.ClaimPending). ReleasePending drops it.
	ClaimPending(ctx context.Context, dedupe, requestID string, holder func(id string) (known, pending bool)) (bool, error)
	ReleasePending(ctx context.Context, dedupe, requestID string) error
	// failureCounter shares the failed-auth limiters' counts across replicas.
	failureCounter
	// revocationStore holds credential revocations (ADR-0026).
	revocationStore
	// Ping fails when the backend is unreachable (/readyz).
	Ping(ctx context.Context) error
}

// PGBackend is the Postgres Backend.
type PGBackend struct {
	*pgstore.DB
	LeaseTTL time.Duration // Leased lease length; 0 = 15s
}

// NewPGBackend wraps an open, migrated database.
func NewPGBackend(db *pgstore.DB) *PGBackend { return &PGBackend{DB: db} }

// AppendAudit implements Backend.
func (b *PGBackend) AppendAudit(ctx context.Context, e AuditEntry) error {
	return b.DB.AppendAudit(ctx, func(seq uint64, head string) (pgstore.AuditLink, error) {
		c := ChainAuditEntry(e, seq, head)
		body, err := json.Marshal(c)
		if err != nil {
			return pgstore.AuditLink{}, fmt.Errorf("audit: encode: %w", err)
		}
		return pgstore.AuditLink{Seq: c.Seq, Hash: c.Hash, Prev: c.Prev, Entry: body, At: c.Time}, nil
	})
}

// ImportAuditEntry appends an entry that is already chained (Seq, Prev and
// Hash set), as `halo-server import` copies a file chain; it must extend the head.
func (b *PGBackend) ImportAuditEntry(ctx context.Context, e AuditEntry) error {
	return b.DB.AppendAudit(ctx, func(uint64, string) (pgstore.AuditLink, error) {
		body, err := json.Marshal(e)
		if err != nil {
			return pgstore.AuditLink{}, fmt.Errorf("audit: encode: %w", err)
		}
		return pgstore.AuditLink{Seq: e.Seq, Hash: e.Hash, Prev: e.Prev, Entry: body, At: e.Time}, nil
	})
}

// EachAudit implements Backend.
func (b *PGBackend) EachAudit(ctx context.Context, from uint64, fn func(raw []byte, e AuditEntry) bool) error {
	return b.DB.EachAudit(ctx, from, func(_ uint64, raw []byte) bool {
		var e AuditEntry
		_ = json.Unmarshal(raw, &e) // garbage: zero entry, the chain breaks there
		return fn(raw, e)
	})
}

// EachAuditDesc implements Backend.
func (b *PGBackend) EachAuditDesc(ctx context.Context, fn func(raw []byte, e AuditEntry) bool) error {
	return b.DB.EachAuditDesc(ctx, func(_ uint64, raw []byte) bool {
		var e AuditEntry
		_ = json.Unmarshal(raw, &e) // garbage: zero entry, the chain breaks there
		return fn(raw, e)
	})
}

// RolloutStates implements Backend.
func (b *PGBackend) RolloutStates() rollout.StateStore { return rollout.DocStore{DB: b.DB} }

// Leased implements Backend with a leader lease per name.
func (b *PGBackend) Leased(ctx context.Context, name string, fn func(ctx context.Context, docs rollout.Docs)) {
	b.DB.Leased(ctx, name, b.LeaseTTL, func(lctx context.Context, view *pgstore.Fenced) { fn(lctx, view) })
}

// pgReports is the fleet report Store on Postgres.
type pgReports struct{ db *pgstore.DB }

// NewPGStore returns the fleet report Store on db: the latest report per
// reporter, and a MaxHistory-bounded history that, unlike the file store's,
// survives a restart.
func NewPGStore(db *pgstore.DB) Store { return &pgReports{db} }

func (s *pgReports) Put(h Host) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	return s.db.PutReport(ctx, h.key(), h.Hostname, b, MaxHistory)
}

func (s *pgReports) All() []Host {
	ctx, cancel := storage.Ctx()
	defer cancel()
	rows, err := s.db.Reports(ctx)
	if err != nil {
		return nil // ponytail: Store.All has no error; the DB error is counted in halo_db_errors_total and fails /readyz
	}
	out := decodeHosts(rows)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].key() < out[j].key()
	})
	return out
}

func (s *pgReports) History(key string) []Host {
	ctx, cancel := storage.Ctx()
	defer cancel()
	rows, err := s.db.ReportHistory(ctx, key, MaxHistory)
	if err != nil {
		return nil // see All
	}
	return decodeHosts(rows)
}

func decodeHosts(rows [][]byte) []Host {
	out := make([]Host, 0, len(rows))
	for _, r := range rows {
		var h Host
		if json.Unmarshal(r, &h) == nil {
			out = append(out, h)
		}
	}
	return out
}

// kvOf is b's KV, or nil (a nil Backend must not become a non-nil interface).
func kvOf(b Backend) storage.KV {
	if b == nil {
		return nil
	}
	return b
}

// clusterMutex is a mutex that, with a shared KV, also holds a cluster-wide
// lock, so a read-modify-write runs on one replica at a time. The lock is a
// KV row whose value is a random owner token and whose expiry the database
// sets (now() + clusterLockTTL): replica clocks play no part, and Unlock
// deletes only the row this holder owns, so a holder whose lock expired can
// never release its successor's. If the lock cannot be taken within
// clusterLockWait, Lock fails (callers answer 503 and the IdP retries); it
// never proceeds unlocked. Zero value: a plain mutex.
type clusterMutex struct {
	local sync.Mutex
	kv    storage.KV
	name  string
	log   *slog.Logger
	owner string // the token of the held cluster lock ("" = not held)
	wait  time.Duration
}

const (
	clusterLockTTL  = 30 * time.Second
	clusterLockWait = 10 * time.Second
)

// errClusterLock is Lock's failure: the lock is held elsewhere or the store
// is unreachable.
var errClusterLock = errors.New("cluster lock not acquired")

// Lock takes the local mutex and, with a shared KV, the cluster lock; the
// returned func releases both. On error nothing is held.
func (m *clusterMutex) Lock() (func(), error) {
	m.local.Lock()
	if m.kv == nil {
		return m.local.Unlock, nil
	}
	wait := m.wait
	if wait <= 0 {
		wait = clusterLockWait
	}
	owner := randB64(16)
	deadline := time.Now().Add(wait)
	var lastErr error
	for {
		ctx, cancel := storage.Ctx()
		ok, err := m.kv.TryLock(ctx, "lock", m.name, owner, clusterLockTTL)
		cancel()
		if ok && err == nil {
			m.owner = owner
			return m.unlock, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			m.local.Unlock()
			orDefault(m.log).Error("cluster lock not acquired; refusing the mutation", "lock", m.name, "waited", wait, "err", lastErr)
			if lastErr != nil {
				return nil, fmt.Errorf("%w: %s: %w", errClusterLock, m.name, lastErr)
			}
			return nil, fmt.Errorf("%w: %s held by another replica for over %s", errClusterLock, m.name, wait)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (m *clusterMutex) unlock() {
	if m.owner != "" {
		ctx, cancel := storage.Ctx()
		if err := m.kv.Unlock(ctx, "lock", m.name, m.owner); err != nil {
			orDefault(m.log).Warn("cluster lock release failed; it expires on its own", "lock", m.name, "err", err)
		}
		cancel()
		m.owner = ""
	}
	m.local.Unlock()
}
