package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// The state enterprise features added (budgets ADR-0017, workload jti
// ADR-0023, SCIM ADR-0022, audit export ADR-0016, verdicts) must be shared on
// the HA backend. Each test runs against the in-process fake and, with
// HALO_TEST_PG_DSN set, against Postgres; each fails with per-replica state.

func sharedBackends(t *testing.T, run func(t *testing.T, newBackend func() Backend)) {
	t.Run("memory", func(t *testing.T) {
		b := newMemShared()
		run(t, func() Backend { return b })
	})
	t.Run("postgres", func(t *testing.T) {
		db, _ := pgtest.OpenTest(t)
		run(t, func() Backend { return NewPGBackend(db) })
	})
}

// replicaEnv is one replica on b, on the real clock (shared expiries are
// judged on the database's).
func replicaEnv(t *testing.T, b Backend, mutate func(*Config)) *env {
	t.Helper()
	e := newEnv(t, func(c *Config) {
		c.Backend = b
		if mutate != nil {
			mutate(c)
		}
	})
	*e.now = time.Now().UTC()
	return e
}

func withBudgets(t *testing.T) func(*Config) {
	return func(c *Config) {
		c.GatewayToken = "gw-tok"
		f := filepath.Join(c.PolicyDir, "gateway.yaml")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, "\nbudgets:\n  - {name: dev-daily, scope: user, window: day, limitUSD: 10, action: enforce}\n"...)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSharedBudgets: usage reported to either replica counts against one
// counter, so two replicas grant one budget, not two; a batch retried to
// both replicas at once counts once.
func TestSharedBudgets(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, withBudgets(t)), replicaEnv(t, b, withBudgets(t))
		alice := budget.Principal{Subject: "alice@acme.example", Ring: "ga"}
		usage := func(e *env, batch string, usd float64) {
			t.Helper()
			rec := budget.Record{Principal: alice, Spend: budget.Spend{USD: usd}, At: *e.now}
			w := do(e.h, "POST", "/api/v1/gateway/budget/usage", "Bearer gw-tok", mustJSON(t, gateway.BudgetUsage{Batch: batch, Records: []budget.Record{rec}}))
			if w.Code != 200 {
				t.Fatalf("usage: %d %s", w.Code, w.Body)
			}
		}
		check := func(e *env) budget.Status {
			t.Helper()
			w := do(e.h, "POST", "/api/v1/gateway/budget/check", "Bearer gw-tok", mustJSON(t, gateway.BudgetCheck{Principal: alice}))
			if w.Code != 200 {
				t.Fatalf("check: %d %s", w.Code, w.Body)
			}
			return decode[gateway.BudgetVerdict](t, w).Budgets[0]
		}
		usage(a, "b-a", 6)
		if st := check(c); st.SpentUSD != 6 || st.Exceeded() {
			t.Fatalf("replica c sees %+v after $6 on a", st)
		}
		usage(c, "b-c", 6) // each replica alone is under $10; together they are over
		for _, e := range []*env{a, c} {
			if st := check(e); st.SpentUSD != 12 || !st.Exceeded() {
				t.Fatalf("a replica grants budget the other spent: %+v", st)
			}
		}
		var wg sync.WaitGroup
		for _, e := range []*env{a, c, a, c} {
			wg.Go(func() { usage(e, "b-retry", 1) })
		}
		wg.Wait()
		if st := check(a); st.SpentUSD != 13 {
			t.Fatalf("a batch retried on both replicas counted %v times", st.SpentUSD-12)
		}
		w := c.as(admin, "GET", "/api/v1/budgets?budget=dev-daily", "")
		if all := decode[BudgetsResponse](t, w).Budgets; len(all) != 1 || all[0].SpentUSD != 13 {
			t.Fatalf("admin view on c: %+v", all)
		}
	})
}

// TestSharedWorkloadReplay: a subject token exchanged on replica a is a
// replay on replica b.
func TestSharedWorkloadReplay(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, nil), replicaEnv(t, b, nil)
		key, exp := "jti\x00https://token.actions.githubusercontent.com\x00run-42", time.Now().Add(10*time.Minute)
		if err := a.s.rememberSubjectToken(key, exp, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := c.s.rememberSubjectToken(key, exp, time.Now()); !errors.Is(err, errReplayed) {
			t.Fatalf("token replayed on another replica: %v, want errReplayed", err)
		}
		if err := c.s.rememberSubjectToken(key+"-other", exp, time.Now()); err != nil {
			t.Fatalf("a different token: %v", err)
		}
		// An expired record no longer blocks (the token itself is expired by then).
		old := "jti\x00iss\x00old"
		if err := a.s.rememberSubjectToken(old, time.Now().Add(-exchangeIatSkew-time.Second), time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := c.s.rememberSubjectToken(old, time.Now().Add(time.Minute), time.Now()); err != nil {
			t.Fatalf("expired record blocked: %v", err)
		}
	})
}

// TestSharedSCIMDeprovision: a user deactivated through SCIM on replica a is
// refused on replica b at once: session, device token, pending enrollment,
// and the directory view.
func TestSharedSCIMDeprovision(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		scim := func(c *Config) {
			c.SCIMTokenSHA256, c.SCIMAuthoritative, c.GatewayToken = []string{sha256Hex(scimTok)}, true, gwTok
		}
		a, c := replicaEnv(t, b, scim), replicaEnv(t, b, scim)
		id := a.createSCIMUser(t, dev.ID, true)
		gid := a.createSCIMGroup(t, "eng", id)
		if g, ok := c.s.directoryGroups(dev.ID, nil); !ok || len(g) != 1 || g[0] != "eng" {
			t.Fatalf("user provisioned on a unknown to c: %v %v", g, ok)
		}
		if w := c.scim("GET", "/scim/v2/Groups/"+gid, ""); w.Code != 200 || !strings.Contains(w.Body.String(), id) {
			t.Fatalf("group on c: %d %s", w.Code, w.Body)
		}
		// The user enrolls a device on c and holds a second, unused token from c.
		tok := decode[Launch](t, c.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
		w := do(c.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`)
		var m map[string]any
		if w.Code != 200 || yaml.Unmarshal(w.Body.Bytes(), &m) != nil {
			t.Fatalf("enroll on c: %d %s", w.Code, w.Body)
		}
		devTok, _ := m["deviceToken"].(string)
		pending := decode[Launch](t, c.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
		if code := c.sessionAt(dev, time.Now().Add(-time.Minute), "GET", "/api/v1/me").Code; code != 200 {
			t.Fatalf("session on c before: %d", code)
		}

		if w := a.scim("PATCH", "/scim/v2/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`); w.Code != 200 {
			t.Fatalf("deactivate on a: %d %s", w.Code, w.Body)
		}
		if _, ok := c.s.directoryGroups(dev.ID, nil); ok {
			t.Fatal("deactivated on a, still active on c")
		}
		if code := c.sessionAt(dev, time.Now().Add(-time.Minute), "GET", "/api/v1/me").Code; code != 401 {
			t.Fatalf("session on c after deprovisioning on a: %d, want 401", code)
		}
		if code := do(c.h, "GET", "/api/v1/fleet/ring", "Bearer "+devTok, "").Code; code != 401 {
			t.Fatalf("device token on c after deprovisioning on a: %d, want 401", code)
		}
		if code := do(c.h, "POST", "/api/v1/enroll", "", `{"token":"`+pending+`"}`).Code; code != 401 {
			t.Fatalf("pending enrollment on c after deprovisioning on a: %d, want 401", code)
		}
	})
}

// TestSharedPendingRequestUnique: two replicas racing to create the same
// pending request create exactly one; once it is decided a new one is allowed.
func TestSharedPendingRequestUnique(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, nil), replicaEnv(t, b, nil)
		body := `{"kind":"mcp-server","item":"jira","justification":"triage"}`
		codes := make(chan int, 8)
		var wg sync.WaitGroup
		for i := range 8 {
			e := a
			if i%2 == 1 {
				e = c
			}
			wg.Go(func() { codes <- e.as(dev, "POST", "/api/v1/requests", body).Code })
		}
		wg.Wait()
		close(codes)
		created := 0
		for code := range codes {
			switch code {
			case 201:
				created++
			case 409:
			default:
				t.Fatalf("unexpected %d", code)
			}
		}
		if created != 1 {
			t.Fatalf("%d pending requests for one (user, kind, item) across replicas", created)
		}
		reqs := decode[[]Request](t, c.as(admin, "GET", "/api/v1/requests", ""))
		if len(reqs) != 1 {
			t.Fatalf("requests: %+v", reqs)
		}
		if w := c.as(admin, "POST", "/api/v1/requests/"+reqs[0].ID+"/deny", ""); w.Code != 200 {
			t.Fatalf("deny: %d %s", w.Code, w.Body)
		}
		if code := a.as(dev, "POST", "/api/v1/requests", body).Code; code != 201 {
			t.Fatalf("new request after the decision: %d", code)
		}
	})
}

// TestSharedVerdicts: a verdict the controller (on whichever replica leads)
// stores as a document is served by every replica.
func TestSharedVerdicts(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		c := replicaEnv(t, b, nil)
		row, _ := json.Marshal(map[string]any{"experiment": "exp-x", "verdict": "rollback", "reason": "guardrail"})
		docs, ok := b.(interface {
			PutDoc(context.Context, string, string, []byte) error
		})
		if !ok {
			t.Fatal("backend has no PutDoc")
		}
		if err := docs.PutDoc(context.Background(), "verdict", "exp-x", row); err != nil {
			t.Fatal(err)
		}
		vs, err := c.s.verdicts()
		if err != nil || vs["exp-x"].Verdict != "rollback" {
			t.Fatalf("verdicts on another replica: %+v %v", vs, err)
		}
	})
}

// recordingSink collects delivered audit events.
type recordingSink struct {
	mu   sync.Mutex
	seqs []uint64
}

func (r *recordingSink) send(_ context.Context, evs []auditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range evs {
		r.seqs = append(r.seqs, e.e.Seq)
	}
	return nil
}
func (r *recordingSink) close() {}

// TestSharedAuditExport: two replicas run the export for one sink; each
// entry reaches the sink once (one forwarder under the sink's lease, one
// shared cursor), in order, and paging works on the shared chain.
func TestSharedAuditExport(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, nil), replicaEnv(t, b, nil)
		sink := &recordingSink{}
		for _, e := range []*env{a, c} {
			e.s.forwarders = []*auditForwarder{{name: "siem", log: e.s.auditLog, sink: sink, logger: e.s.cfg.Log,
				batch: 3, poll: 20 * time.Millisecond, maxBackoff: time.Second}}
		}
		for i := range 10 {
			if err := a.s.AuditStrict(context.Background(), "ops", "test.export", fmt.Sprint(i), nil); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		for _, e := range []*env{a, c} {
			wg.Go(func() { e.s.RunAuditExport(ctx) })
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			sink.mu.Lock()
			n := len(sink.seqs)
			sink.mu.Unlock()
			if n >= 10 || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond) // a second forwarder would deliver again by now
		cancel()
		wg.Wait()
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if len(sink.seqs) != 10 {
			t.Fatalf("sink got %d entries (%v), want each of 10 once", len(sink.seqs), sink.seqs)
		}
		for i, s := range sink.seqs {
			if s != uint64(i)+1 {
				t.Fatalf("delivery order %v", sink.seqs)
			}
		}
		// Paging on the shared chain, from the other replica.
		resp := decode[AuditResponse](t, c.as(admin, "GET", "/api/v1/audit?since=4&limit=3", ""))
		if !resp.Verified || resp.Total != 10 || len(resp.Entries) != 3 || resp.Entries[0].Seq != 5 || resp.Next != 7 {
			t.Fatalf("paging: %+v", resp)
		}
		tail := decode[AuditResponse](t, c.as(admin, "GET", "/api/v1/audit?limit=2&action=test.export", ""))
		if len(tail.Entries) != 2 || tail.Entries[1].Seq != 10 {
			t.Fatalf("tail: %+v", tail)
		}
		r, err := VerifyAuditBackend(context.Background(), b)
		if err != nil || r.Error != "" || r.Entries != 10 || r.Head != resp.Head {
			t.Fatalf("verify: %+v %v", r, err)
		}
	})
}

// TestSharedAuditRotationRefused: rotation is a file-backend setting.
func TestSharedAuditRotationRefused(t *testing.T) {
	_, err := New(Config{PolicyDir: t.TempDir(), Token: "t", DevUser: "d", Backend: newMemShared(),
		Audit: AuditConfig{Rotation: AuditRotation{MaxBytes: 1 << 20}}})
	if err == nil || !strings.Contains(err.Error(), "file backend") {
		t.Fatalf("rotation on the shared backend: %v", err)
	}
}

// TestSharedDelegationRoot: an agent delegation (ADR-0024) from a session
// whose user was logged out everywhere on replica a is refused on replica b.
func TestSharedDelegationRoot(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, nil), replicaEnv(t, b, nil)
		sess := c.s.seal(cookiePayload{Sub: dev.ID, Iat: time.Now().Add(-time.Minute).UnixNano(), Exp: time.Now().Add(time.Hour).Unix()})
		if _, err := c.s.verifyParent(sess, tokenTypeSession, time.Now()); err != nil {
			t.Fatalf("live session refused: %v", err)
		}
		if w := a.as(admin, "POST", "/api/v1/users/"+dev.ID+"/revoke-sessions", ""); w.Code != 204 {
			t.Fatalf("revoke on a: %d", w.Code)
		}
		if _, err := c.s.verifyParent(sess, tokenTypeSession, time.Now()); err == nil {
			t.Fatal("a session revoked on a still delegates on c")
		}
	})
}
