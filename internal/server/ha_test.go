package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/storage"
)

// memShared is an in-process Backend with the semantics of pgstore: logs
// shared by every replica, each tailing them in one global order, a locked
// audit chain head, and one KV. It lets the replica logic be tested without
// a database; testReplicas runs the same scenarios against Postgres too.
type memShared struct {
	storage.MemKV
	mu      sync.Mutex
	streams map[string][][]byte
	audit   []AuditEntry
	docs    map[string][]byte
	pingErr error
}

func newMemShared() *memShared {
	return &memShared{streams: map[string][][]byte{}, docs: map[string][]byte{}}
}

type memLog struct {
	b      *memShared
	name   string
	replay func([]byte)
	cursor int
}

func (b *memShared) OpenLog(ctx context.Context, name string, replay func([]byte)) (storage.Log, error) {
	l := &memLog{b: b, name: name, replay: replay}
	return l, l.Catchup(ctx)
}

func (l *memLog) Append(_ context.Context, _ string, rec []byte) error {
	l.b.mu.Lock()
	recs := l.b.streams[l.name]
	l.b.streams[l.name] = append(recs, append([]byte(nil), rec...))
	pending := append([][]byte(nil), recs[l.cursor:]...)
	l.b.mu.Unlock()
	for _, r := range pending { // foreign records before ours: log order
		l.replay(r)
	}
	l.cursor = len(recs) + 1
	return nil
}

func (l *memLog) Catchup(context.Context) error {
	l.b.mu.Lock()
	pending := append([][]byte(nil), l.b.streams[l.name][l.cursor:]...)
	l.b.mu.Unlock()
	for _, r := range pending {
		l.replay(r)
	}
	l.cursor += len(pending)
	return nil
}

func (l *memLog) Close() error { return nil }

func (b *memShared) AppendAudit(_ context.Context, e AuditEntry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	head := ""
	if n := len(b.audit); n > 0 {
		head = b.audit[n-1].Hash
	}
	b.audit = append(b.audit, ChainAuditEntry(e, uint64(len(b.audit)), head))
	return nil
}

func (b *memShared) AuditEntries(context.Context) ([]AuditEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]AuditEntry(nil), b.audit...), nil
}

func (b *memShared) GetDoc(_ context.Context, kind, name string) ([]byte, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.docs[kind+"/"+name]
	return v, ok, nil
}

func (b *memShared) PutDoc(_ context.Context, kind, name string, body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.docs[kind+"/"+name] = body
	return nil
}

func (b *memShared) RolloutStates() rollout.StateStore { return rollout.DocStore{DB: b} }

func (b *memShared) Ping(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pingErr
}

// replicas starts two servers on one Backend, as two pods behind a Service.
func replicas(t *testing.T, b Backend) (*env, *env) {
	t.Helper()
	mk := func() *env {
		kills, err := controller.NewKillStore(context.Background(), b)
		if err != nil {
			t.Fatal(err)
		}
		e := newEnv(t, func(c *Config) { c.Backend, c.KillStore = b, kills })
		*e.now = time.Now().UTC() // shared expiries are judged on the database clock
		return e
	}
	return mk(), mk()
}

func TestReplicasInMemory(t *testing.T) { testReplicas(t, newMemShared()) }

func TestReplicasPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	testReplicas(t, NewPGBackend(db))
}

func testReplicas(t *testing.T, b Backend) {
	a, c := replicas(t, b)
	ctx := context.Background()

	t.Run("enrollment token issued on one replica is redeemed once on any", func(t *testing.T) {
		tok := decode[Launch](t, a.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
		w := do(c.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`)
		if w.Code != 200 {
			t.Fatalf("enroll on the other replica: %d %s", w.Code, w.Body.String())
		}
		if w := do(a.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`); w.Code != 401 {
			t.Fatalf("token reused on the issuing replica: %d", w.Code)
		}
		var m map[string]any
		if err := yaml.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		devTok, _ := m["deviceToken"].(string)

		// The device enrolled on c authenticates on a; a revocation on a holds on c.
		ring := func(e *env) int { return do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+devTok, "").Code }
		if got := ring(a); got != 200 {
			t.Fatalf("device enrolled on c rejected by a: %d", got)
		}
		var id string
		for _, d := range decode[[]Device](t, a.as(admin, "GET", "/api/v1/devices", "")) {
			id = d.ID
		}
		if w := a.as(admin, "POST", "/api/v1/devices/"+id+"/revoke", ""); w.Code != 204 {
			t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
		}
		if got := ring(c); got != 401 {
			t.Fatalf("device revoked on a still accepted by c: %d", got)
		}
		// A late lastSeen write from a replica that had not seen the
		// revocation cannot bring the device back.
		if err := c.s.devices.persist(&Device{ID: id, Hash: hashDeviceToken(devTok), UserID: dev.ID, ExpiresAt: a.now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		fresh := newEnv(t, func(cfg *Config) { cfg.Backend = b })
		*fresh.now = time.Now().UTC()
		if got := do(fresh.h, "GET", "/api/v1/fleet/ring", "Bearer "+devTok, "").Code; got != 401 {
			t.Fatalf("revocation lost on a fresh replica: %d", got)
		}
	})

	t.Run("access request decided once across replicas", func(t *testing.T) {
		w := a.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage"}`)
		if w.Code != 201 {
			t.Fatalf("request: %d %s", w.Code, w.Body.String())
		}
		id := decode[Request](t, w).ID
		if got := decode[[]Request](t, c.as(admin, "GET", "/api/v1/requests", "")); len(got) == 0 || got[0].ID != id {
			t.Fatalf("request created on a not listed by c: %+v", got)
		}
		// Another replica holds the decision claim: refused, not decided twice.
		if ok, err := b.Add(ctx, "request-claim", id, nil, time.Now().Add(time.Minute)); !ok || err != nil {
			t.Fatal(ok, err)
		}
		if w := c.as(admin, "POST", "/api/v1/requests/"+id+"/approve", ""); w.Code != 409 || !strings.Contains(w.Body.String(), "being decided") {
			t.Fatalf("approve during another replica's claim: %d %s", w.Code, w.Body.String())
		}
		_ = b.Delete(ctx, "request-claim", id)
		if w := c.as(admin, "POST", "/api/v1/requests/"+id+"/approve", ""); w.Code != 200 {
			t.Fatalf("approve on c: %d %s", w.Code, w.Body.String())
		}
		if w := a.as(admin, "POST", "/api/v1/requests/"+id+"/approve", ""); w.Code != 409 {
			t.Fatalf("second approval on a: %d %s", w.Code, w.Body.String())
		}
		if n := len(a.w.calls) + len(c.w.calls); n != 1 {
			t.Fatalf("%d PRs for one request", n)
		}
		if w := a.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"again"}`); w.Code != 201 {
			t.Fatalf("a decided request must not block a new one on another replica: %d", w.Code)
		}
	})

	t.Run("session revocation holds on every replica", func(t *testing.T) {
		u := Principal{ID: "carol@acme.example"}
		if w := c.as(u, "GET", "/api/v1/me", ""); w.Code != 200 {
			t.Fatalf("me: %d", w.Code)
		}
		if w := a.as(admin, "POST", "/api/v1/users/"+u.ID+"/revoke-sessions", ""); w.Code != 204 {
			t.Fatalf("revoke sessions: %d", w.Code)
		}
		if w := c.as(u, "GET", "/api/v1/me", ""); w.Code != 401 {
			t.Fatalf("session revoked on a still valid on c: %d", w.Code)
		}
	})

	t.Run("server-side session and login state are shared", func(t *testing.T) {
		sid, err := a.s.oidc.newSession([]string{"platform-admins"}, a.now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if g, ok := c.s.oidc.session(sid); !ok || len(g) != 1 {
			t.Fatalf("session from a unknown to c: %v %v", g, ok)
		}
		exp := time.Now().Add(time.Minute)
		if !a.s.oidc.consume("state-1", exp) || c.s.oidc.consume("state-1", exp) {
			t.Fatal("a login state must be single-use across replicas")
		}
	})

	t.Run("kill switch set on one replica is served by all", func(t *testing.T) {
		if _, err := a.s.kills.Kill(ctx, "exp-a", "ops", "bad"); err != nil {
			t.Fatal(err)
		}
		ks, _, err := c.s.kills.Killed()
		if err != nil || len(ks) != 1 || ks[0].Experiment != "exp-a" {
			t.Fatalf("kills on c: %+v %v", ks, err)
		}
		if changed, _ := c.s.kills.Kill(ctx, "exp-a", "ops", "again"); changed {
			t.Fatal("re-kill on another replica reported a change")
		}
	})

	t.Run("audit chain stays linear under concurrent writers on two replicas", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := range 40 {
			e := a
			if i%2 == 1 {
				e = c
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := e.s.AuditStrict(ctx, "ops", "test.concurrent", fmt.Sprint(i), nil); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		for _, e := range []*env{a, c} {
			resp := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?limit=500", ""))
			if !resp.Verified || resp.VerifyError != "" {
				t.Fatalf("chain does not verify: %s", resp.VerifyError)
			}
			n := 0
			for _, x := range resp.Entries {
				if x.Action == "test.concurrent" {
					n++
				}
			}
			if n != 40 {
				t.Fatalf("%d concurrent entries, want 40", n)
			}
		}
	})
}

// Without Config.KillStore, a Backend server opens the shared kill list,
// never a private in-memory one.
func TestBackendDefaultKillStoreIsShared(t *testing.T) {
	b := newMemShared()
	a := newEnv(t, func(c *Config) { c.Backend = b })
	c := newEnv(t, func(c *Config) { c.Backend = b })
	if _, err := a.s.kills.Kill(context.Background(), "exp-a", "ops", "bad"); err != nil {
		t.Fatal(err)
	}
	if ks, _, err := c.s.kills.Killed(); err != nil || len(ks) != 1 {
		t.Fatalf("kill on a not seen by c: %+v %v", ks, err)
	}
}

func TestReadyzReflectsBackend(t *testing.T) {
	b := newMemShared()
	e := newEnv(t, func(c *Config) { c.Backend = b })
	if w := do(e.h, "GET", "/readyz", "", ""); w.Code != 200 {
		t.Fatalf("readyz: %d %s", w.Code, w.Body.String())
	}
	b.mu.Lock()
	b.pingErr = errors.New("connection refused")
	b.mu.Unlock()
	if w := do(e.h, "GET", "/readyz", "", ""); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "database unreachable") {
		t.Fatalf("readyz with the database down: %d %s", w.Code, w.Body.String())
	}
	if w := do(e.h, "GET", "/healthz", "", ""); w.Code != 200 {
		t.Fatal("liveness must not depend on the database")
	}
}

// failingLog fails every read: a replica that cannot see the shared state.
type failingShared struct{ *memShared }

func (f failingShared) OpenLog(ctx context.Context, name string, replay func([]byte)) (storage.Log, error) {
	l, err := f.memShared.OpenLog(ctx, name, replay)
	return failingLog{l}, err
}

type failingLog struct{ storage.Log }

func (failingLog) Catchup(context.Context) error { return errors.New("connection refused") }

func TestReplicaFailsClosedWhenStoreUnreachable(t *testing.T) {
	b := newMemShared()
	good := newEnv(t, func(c *Config) { c.Backend = b })
	*good.now = time.Now().UTC()
	tok := decode[Launch](t, good.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	w := do(good.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`)
	var m map[string]any
	if w.Code != 200 || yaml.Unmarshal(w.Body.Bytes(), &m) != nil {
		t.Fatalf("enroll %d", w.Code)
	}
	devTok, _ := m["deviceToken"].(string)

	bad := newEnv(t, func(c *Config) { c.Backend = failingShared{b} })
	*bad.now = time.Now().UTC()
	// Device auth: 503, not 401 (and no rate-limit penalty), never a pass.
	for range authFailBurst + 2 {
		if got := do(bad.h, "GET", "/api/v1/fleet/ring", "Bearer "+devTok, "").Code; got != http.StatusServiceUnavailable {
			t.Fatalf("device auth with the store unreachable: %d", got)
		}
	}
	// Sessions: a revocation might be unseen, so no session is valid.
	if got := bad.as(dev, "GET", "/api/v1/me", "").Code; got != 401 {
		t.Fatalf("session check with the store unreachable: %d", got)
	}
}

func TestImportDataDir(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	b := NewPGBackend(db)
	ctx := context.Background()

	// A single-replica server writes its data dir, then stops.
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir = dir })
	store, err := OpenLogStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Put(Host{Report: Report{Hostname: "h1", Ring: "ring0"}})
	_ = store.Put(Host{Report: Report{Hostname: "h1", Ring: "ring1"}}) // last line per reporter wins
	_ = store.Put(Host{Report: Report{Hostname: "h2"}})
	tok := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	if w := do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`); w.Code != 200 {
		t.Fatalf("enroll %d", w.Code)
	}
	if w := e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"x"}`); w.Code != 201 {
		t.Fatalf("request %d", w.Code)
	}
	for i := range 5 {
		if err := e.s.AuditStrict(ctx, "ops", "test", fmt.Sprint(i), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.s.revoked.revoke("u", time.Now()); err != nil {
		t.Fatal(err)
	}
	st := rollout.NewState("r1")
	if err := st.Save(filepath.Join(dir, "rollouts")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "devices.jsonl"), append(mustRead(t, filepath.Join(dir, "devices.jsonl")), []byte(`{"torn`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	src, _ := e.s.auditLog.all()
	_ = e.s.Close()
	if c, ok := store.(interface{ Close() error }); ok {
		_ = c.Close()
	}

	rep, err := ImportDataDir(ctx, dir, b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"audit": int64(len(src)), "journal/devices": 1, "journal/requests": 1, "journal/session-revocations": 1, "reports": 2, "docs/rollout-state": 1}
	for k, n := range want {
		if rep.Copied[k] != n {
			t.Errorf("copied %s = %d, want %d (%v)", k, rep.Copied[k], n, rep.Copied)
		}
	}
	if rep.Skipped["devices.jsonl"] != 1 || rep.Head != src[len(src)-1].Hash {
		t.Fatalf("report %+v", rep)
	}
	// A server on the database sees the imported state.
	pg := newEnv(t, func(c *Config) { c.Backend, c.Store = b, NewPGStore(db) })
	if d := decode[[]Device](t, pg.as(admin, "GET", "/api/v1/devices", "")); len(d) != 1 {
		t.Fatalf("devices after import: %+v", d)
	}
	if hosts := pg.s.cfg.Store.All(); len(hosts) != 2 || hosts[0].Ring != "ring1" {
		t.Fatalf("reports after import: %+v", hosts)
	}
	if resp := decode[AuditResponse](t, pg.as(admin, "GET", "/api/v1/audit", "")); !resp.Verified || resp.Head != src[len(src)-1].Hash {
		t.Fatalf("audit after import: %+v", resp)
	}
	// The target must be empty: a second import is refused.
	if _, err := ImportDataDir(ctx, dir, b); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("import into a non-empty database: %v", err)
	}
}

func TestImportRefusesBrokenChain(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	dir := t.TempDir()
	l, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := l.append(AuditEntry{Actor: "a", Action: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.close()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte(strings.Replace(string(mustRead(t, p)), `"actor":"a"`, `"actor":"mallory"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportDataDir(context.Background(), dir, NewPGBackend(db)); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("tampered source imported: %v", err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
