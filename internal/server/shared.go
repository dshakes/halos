package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/storage"
)

// Backend is the shared state that lets several halo-server replicas serve
// one fleet (ADR-0021). Config.Backend nil means the single-replica default:
// JSONL files under DataDir and in-process ephemeral state.
type Backend interface {
	storage.Opener // device, request, session-revocation logs
	storage.KV     // enrollment tokens, login states, server-side sessions, approval claims
	// AppendAudit chains e after the current head under a lock held across
	// replicas, filling Seq, Prev and Hash.
	AppendAudit(ctx context.Context, e AuditEntry) error
	// AuditEntries returns the whole chain, oldest first.
	AuditEntries(ctx context.Context) ([]AuditEntry, error)
	// RolloutStates is where the controller's rollout state lives.
	RolloutStates() rollout.StateStore
	// Ping fails when the backend is unreachable (/readyz).
	Ping(ctx context.Context) error
}

// PGBackend is the Postgres Backend.
type PGBackend struct{ *pgstore.DB }

// NewPGBackend wraps an open, migrated database.
func NewPGBackend(db *pgstore.DB) *PGBackend { return &PGBackend{db} }

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

// AuditEntries implements Backend. A row that does not decode is returned
// zero-valued, so VerifyAuditChain reports the break there.
func (b *PGBackend) AuditEntries(ctx context.Context) ([]AuditEntry, error) {
	rows, err := b.DB.AuditEntries(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AuditEntry, len(rows))
	for i, r := range rows {
		_ = json.Unmarshal(r, &out[i]) // garbage: zero entry, the chain breaks there
	}
	return out, nil
}

// RolloutStates implements Backend.
func (b *PGBackend) RolloutStates() rollout.StateStore { return rollout.DocStore{DB: b.DB} }

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
