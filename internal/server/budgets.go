package server

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Budget API limits.
const (
	maxBudgetCheckBytes = 64 << 10
	maxBudgetUsageBytes = 8 << 20
	maxBudgetRecords    = 5_000
	maxBudgetGroups     = 512
	// budgetSaveEvery bounds how much usage a crash can lose: the ledger is
	// written at most this often while usage arrives, and on Close.
	budgetSaveEvery = 10 * time.Second
)

// budgetStore is halo-server's authoritative budget ledger (ADR-0017),
// persisted as <data-dir>/budgets.json with one writer, or, with a shared
// Backend (ADR-0021), kept in the database: every replica then adds usage to
// and reads verdicts from the same counters, so N replicas grant one budget,
// not N.
type budgetStore struct {
	l    *budget.Ledger
	path string  // "" = in-memory only
	db   Backend // set: counters live in the database; l is unused

	mu    sync.Mutex // serialises saves
	saved time.Time
}

func openBudgetStore(dir string, db Backend) (*budgetStore, error) {
	s := &budgetStore{l: budget.NewLedger(), db: db}
	if dir == "" || db != nil {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("server: budgets: %w", err)
	}
	s.path = filepath.Join(dir, "budgets.json")
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("server: budgets: %w", err)
	}
	if s.l, err = budget.LoadLedger(b); err != nil {
		return nil, fmt.Errorf("server: budgets %s: %w", s.path, err)
	}
	return s, nil
}

// save writes the ledger if it changed, at most every budgetSaveEvery unless force.
func (s *budgetStore) save(now time.Time, force bool) error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !force && now.Sub(s.saved) < budgetSaveEvery {
		return nil
	}
	b, changed, err := s.l.Snapshot()
	if err != nil || !changed {
		return err
	}
	s.saved = now
	if err := fsutil.WriteAtomic(s.path, b, 0o600); err != nil {
		return fmt.Errorf("server: save budgets: %w", err)
	}
	return nil
}

// status is the state of every counter p is charged to.
func (s *budgetStore) status(budgets []policy.Budget, p budget.Principal, now time.Time) ([]budget.Status, error) {
	if s.db == nil {
		return s.l.Status(budgets, p, now), nil
	}
	cs := budget.Charges(budgets, p)
	keys := make([][2]string, 0, len(cs))
	for _, c := range cs {
		keys = append(keys, [2]string{c.Budget.Name, c.Key})
	}
	l, err := s.load(keys)
	if err != nil {
		return nil, err
	}
	return l.Status(budgets, p, now), nil
}

// all is every counter with spend in its window (see budget.Ledger.All).
func (s *budgetStore) all(budgets []policy.Budget, now time.Time) ([]budget.Status, error) {
	if s.db == nil {
		return s.l.All(budgets, now), nil
	}
	l, err := s.load(nil)
	if err != nil {
		return nil, err
	}
	return l.All(budgets, now), nil
}

// apply charges recs once per batch id.
func (s *budgetStore) apply(budgets []policy.Budget, batch string, recs []budget.Record, now time.Time) (bool, error) {
	if s.db == nil {
		return s.l.Apply(budgets, batch, recs, now), nil
	}
	var incs []pgstore.BudgetCounter
	for name, byKey := range budget.Increments(budgets, recs, now) {
		for key, bk := range byKey {
			for start, sp := range bk {
				incs = append(incs, pgstore.BudgetCounter{Budget: name, Key: key, Bucket: start, USD: sp.USD, Tokens: sp.Tokens})
			}
		}
	}
	keep := make(map[string]int64, len(budgets))
	for i := range budgets {
		keep[budgets[i].Name] = budget.Cutoff(&budgets[i], now).Unix()
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	return s.db.ApplyBudget(ctx, batch, incs, keep)
}

// load reads counters from the database into a read-only ledger view.
func (s *budgetStore) load(keys [][2]string) (*budget.Ledger, error) {
	ctx, cancel := storage.Ctx()
	defer cancel()
	rows, err := s.db.BudgetCounters(ctx, keys)
	if err != nil {
		return nil, err
	}
	c := budget.Counters{}
	for _, r := range rows {
		if c[r.Budget] == nil {
			c[r.Budget] = map[string]map[int64]budget.Spend{}
		}
		if c[r.Budget][r.Key] == nil {
			c[r.Budget][r.Key] = map[int64]budget.Spend{}
		}
		c[r.Budget][r.Key][r.Bucket] = budget.Spend{USD: r.USD, Tokens: r.Tokens}
	}
	return budget.FromCounters(c), nil
}

func budgetsOf(org *policy.Org) []policy.Budget {
	if org == nil || org.Gateway == nil {
		return nil
	}
	return org.Gateway.Budgets
}

func validPrincipal(p budget.Principal) error {
	switch {
	case len(p.Subject) > 256 || len(p.Ring) > 128:
		return errors.New("subject (<=256) or ring (<=128) too long")
	case len(p.Groups) > maxBudgetGroups:
		return fmt.Errorf("more than %d groups", maxBudgetGroups)
	}
	for _, g := range p.Groups {
		if g == "" || len(g) > 256 {
			return errors.New("group empty or longer than 256")
		}
	}
	return nil
}

// gatewayBudgetOK answers the shared preamble of the gateway budget endpoints.
func (s *Server) gatewayBudgetOK(w http.ResponseWriter, r *http.Request) ([]policy.Budget, bool) {
	if s.cfg.GatewayToken == "" {
		apiErr(w, http.StatusNotFound, "budgets not configured")
		return nil, false
	}
	if !s.gatewayAuth(w, r) {
		return nil, false
	}
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return nil, false
	}
	return budgetsOf(org), true
}

// postGatewayBudgetCheck: POST /api/v1/gateway/budget/check (gateway token).
// The verdict is every counter the principal is charged to, in its current window.
func (s *Server) postGatewayBudgetCheck(w http.ResponseWriter, r *http.Request) {
	budgets, ok := s.gatewayBudgetOK(w, r)
	if !ok {
		return
	}
	var in gateway.BudgetCheck
	if err := decodeBody(w, r, maxBudgetCheckBytes, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := validPrincipal(in.Principal); err != nil {
		apiErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	sts, err := s.budgets.status(budgets, in.Principal, s.cfg.Now())
	if err != nil {
		s.cfg.Log.Error("read budgets", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "budget store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, gateway.BudgetVerdict{Budgets: sts})
}

// postGatewayBudgetUsage: POST /api/v1/gateway/budget/usage (gateway token).
// A replica's usage since its last report; a repeated batch id is a retry and
// is acknowledged without counting again.
func (s *Server) postGatewayBudgetUsage(w http.ResponseWriter, r *http.Request) {
	budgets, ok := s.gatewayBudgetOK(w, r)
	if !ok {
		return
	}
	var in gateway.BudgetUsage
	if err := decodeBody(w, r, maxBudgetUsageBytes, &in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			apiErr(w, http.StatusRequestEntityTooLarge, "usage batch too large")
			return
		}
		apiErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	switch {
	case in.Batch == "" || len(in.Batch) > 64:
		apiErr(w, http.StatusUnprocessableEntity, "batch id required (<=64 chars)")
		return
	case len(in.Records) > maxBudgetRecords:
		apiErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("more than %d records", maxBudgetRecords))
		return
	}
	for i, rec := range in.Records {
		err := validPrincipal(rec.Principal)
		if err == nil && (rec.USD < 0 || math.IsNaN(rec.USD) || math.IsInf(rec.USD, 0) || rec.Tokens < 0) {
			err = errors.New("usd and tokens must be finite and >= 0")
		}
		if err != nil {
			apiErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("records[%d]: %v", i, err))
			return
		}
	}
	now := s.cfg.Now()
	dup, err := s.budgets.apply(budgets, in.Batch, in.Records, now)
	if err != nil { // not counted: the gateway keeps the batch and retries it
		s.cfg.Log.Error("apply budget usage", "batch", in.Batch, "err", err)
		apiErr(w, http.StatusServiceUnavailable, "budget store unavailable")
		return
	}
	if err := s.budgets.save(now, false); err != nil {
		s.cfg.Log.Error("save budgets", "err", err) // counted in memory; the next save retries
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": len(in.Records), "duplicate": dup})
}

// BudgetsResponse is GET /api/v1/budgets.
type BudgetsResponse struct {
	Budgets []budget.Status `json:"budgets"`
	At      time.Time       `json:"at"`
}

// getBudgets: every counter with spend in its current window (admin), plus
// the org and group counters at zero. ?budget= and ?key= filter.
func (s *Server) getBudgets(w http.ResponseWriter, r *http.Request, _ Principal) {
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return
	}
	now := s.cfg.Now()
	name, key := r.URL.Query().Get("budget"), r.URL.Query().Get("key")
	out := BudgetsResponse{Budgets: []budget.Status{}, At: now.UTC()}
	sts, err := s.budgets.all(budgetsOf(org), now)
	if err != nil {
		s.cfg.Log.Error("read budgets", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "budget store unavailable")
		return
	}
	for _, st := range sts {
		if (name == "" || st.Budget == name) && (key == "" || st.Key == key) {
			out.Budgets = append(out.Budgets, st)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
