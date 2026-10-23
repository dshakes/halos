package shadow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// fakeDB is a shared pair table and budget with pgstore's semantics.
type fakeDB struct {
	mu      sync.Mutex
	rows    map[string][]byte
	at      map[string]time.Time
	spent   map[string]float64
	res     map[string]float64 // reservation id -> amount
	reserv  map[string]float64 // scope -> reserved
	failErr error
}

func newFakeDB() *fakeDB {
	return &fakeDB{rows: map[string][]byte{}, at: map[string]time.Time{}, spent: map[string]float64{}, res: map[string]float64{}, reserv: map[string]float64{}}
}

func (f *fakeDB) AppendPair(_ context.Context, id string, at time.Time, row []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return f.failErr
	}
	if _, dup := f.rows[id]; !dup {
		f.rows[id], f.at[id] = row, at
	}
	return nil
}

func (f *fakeDB) PrunePairs(_ context.Context, cutoff time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return 0, f.failErr
	}
	n := 0
	for id, at := range f.at {
		if at.Before(cutoff) {
			delete(f.rows, id)
			delete(f.at, id)
			n++
		}
	}
	return n, nil
}

func (f *fakeDB) Reserve(_ context.Context, scope, id string, amount, limit float64, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return false, f.failErr
	}
	if f.spent[scope]+f.reserv[scope]+amount > limit {
		return false, nil
	}
	f.reserv[scope] += amount
	f.res[id] = amount
	return true, nil
}

func (f *fakeDB) Settle(_ context.Context, scope, id string, _, charged float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return f.failErr
	}
	f.reserv[scope] -= f.res[id]
	delete(f.res, id)
	f.spent[scope] += charged
	return nil
}

func (f *fakeDB) Spent(_ context.Context, scope string) (float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.spent[scope], f.failErr
}

func TestDBStoreRowsMatchFileStore(t *testing.T) {
	key := make([]byte, 32)
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"plaintext", nil}, {"sealed", key}} {
		t.Run(tc.name, func(t *testing.T) {
			db := newFakeDB()
			s, err := NewDBStore(db, StoreOptions{Key: tc.key, Retention: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			p := Pair{ID: "p1", Time: time.Now().UTC(), Experiment: "exp", Request: json.RawMessage(`{"secret":"x"}`)}
			if err := s.Append(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			row := db.rows["p1"]
			if tc.key != nil && strings.Contains(string(row), "secret") {
				t.Fatal("sealed row holds plaintext")
			}
			got, err := DecodePair(row, key) // the FileStore reader opens it
			if err != nil || got.Experiment != "exp" || string(got.Request) != `{"secret":"x"}` {
				t.Fatalf("decode %+v %v", got, err)
			}
			old := Pair{ID: "old", Time: time.Now().Add(-2 * time.Hour)}
			_ = s.Append(context.Background(), old)
			if n, err := s.Prune(time.Now()); n != 1 || err != nil {
				t.Fatalf("prune %d %v", n, err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := NewDBStore(newFakeDB(), StoreOptions{Key: []byte("short")}); err == nil {
		t.Fatal("short key accepted")
	}
	s, _ := NewDBStore(newFakeDB(), StoreOptions{})
	if n, err := s.Prune(time.Now()); n != 0 || err != nil {
		t.Fatal("retention 0 must not prune")
	}
	db := newFakeDB()
	db.failErr = errors.New("connection refused")
	s, _ = NewDBStore(db, StoreOptions{Retention: time.Hour})
	if err := s.Append(context.Background(), Pair{ID: "x"}); err == nil {
		t.Fatal("append error swallowed")
	}
	if _, err := s.Prune(time.Now()); err == nil {
		t.Fatal("prune error swallowed")
	}
}

// TestSharedBudgetAcrossReplicas: two halo-shadow replicas on one budget
// accept no more work in total than the cap allows.
func TestSharedBudgetAcrossReplicas(t *testing.T) {
	ctl, _ := upstream(t, 0, 1000)
	cand, _ := upstream(t, 0, 1000)
	db := newFakeDB()
	st := &memStore{}
	mk := func() *Server {
		// $2 per job (2 sides x 1000 max_tokens x $1000/MTok); $9 shared cap.
		return New(Config{Token: "tok", Queue: 100, Workers: 4, BudgetUSD: 9, PriceOutPerMTok: 1000, Policy: orgFn(testOrg(ctl.URL, cand.URL)),
			Budget: SharedBudget{DB: db, Scope: "default", Limit: 9}}, st)
	}
	a, b := mk(), mk()
	j := job()
	j.Body = json.RawMessage(`{"model":"sonnet","max_tokens":1000,"messages":[{"role":"user","content":"hi"}]}`)
	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := range 40 {
		h := a.Handler()
		if i%2 == 1 {
			h = b.Handler()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if post(h, "tok", j).Code == http.StatusAccepted {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 4 {
		t.Fatalf("accepted %d jobs across replicas, want 4 under a shared $9 cap", ok.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Start(ctx)
	b.Start(ctx)
	waitFor(t, func() bool { return st.n() == 4 })
	waitFor(t, func() bool { return a.Spent() == 8 && b.Spent() == 8 }) // both see the global spend
}

func TestSharedBudgetUnavailableFailsClosed(t *testing.T) {
	ctl, hits := upstream(t, 1, 1)
	db := newFakeDB()
	db.failErr = errors.New("connection refused")
	s := New(Config{Token: "tok", Policy: orgFn(testOrg(ctl.URL, ctl.URL)), Budget: SharedBudget{DB: db, Scope: "default", Limit: 100}}, &memStore{})
	if w := post(s.Handler(), "tok", job()); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("job accepted without a booked reservation: %d", w.Code)
	}
	if n, _, _, _ := hits.get(); n != 0 {
		t.Fatal("upstream called without a reservation")
	}
	if s.Spent() != 0 {
		t.Fatal("spent on a failing store")
	}
	_, m := metrics(t, s.Handler(), "tok")
	if !strings.Contains(m, "halo_shadow_errors_total 1") {
		t.Fatalf("store error not counted: %s", m)
	}
}

func TestReadyzPing(t *testing.T) {
	var down atomic.Bool
	s := New(Config{Token: "tok", Policy: orgFn(testOrg("http://a", "http://b")), Ping: func(context.Context) error {
		if down.Load() {
			return errors.New("connection refused")
		}
		return nil
	}}, &memStore{})
	get := func() int {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		return w.Code
	}
	if c := get(); c != 200 {
		t.Fatalf("ready: %d", c)
	}
	down.Store(true)
	if c := get(); c != http.StatusServiceUnavailable {
		t.Fatalf("ready with the database down: %d", c)
	}
}

// TestPostgresPairsAndBudget runs DBStore and SharedBudget on a real database.
func TestPostgresPairsAndBudget(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	key := make([]byte, 32)
	s, err := NewDBStore(db, StoreOptions{Key: key, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), Pair{ID: "p", Time: time.Now().UTC(), Experiment: "exp"}); err != nil {
		t.Fatal(err)
	}
	var got []Pair
	if err := db.Pairs(context.Background(), func(row []byte) error {
		p, err := DecodePair(row, key)
		got = append(got, p)
		return err
	}); err != nil || len(got) != 1 || got[0].Experiment != "exp" {
		t.Fatalf("pairs %+v %v", got, err)
	}
	b := SharedBudget{DB: db, Scope: "s", Limit: 1}
	if ok, err := b.Reserve(context.Background(), "r1", 0.6); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := b.Reserve(context.Background(), "r2", 0.6); ok {
		t.Fatal("over cap")
	}
	if err := b.Settle(context.Background(), "r1", 0.6, 0.7); err != nil {
		t.Fatal(err)
	}
	if v, _ := b.Spent(context.Background()); v != 0.7 {
		t.Fatalf("spent %v", v)
	}
}
