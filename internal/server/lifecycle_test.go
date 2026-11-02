package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/rollout"
)

// ---- memShared support for ADR-0040 (the Postgres backend implements these in pgstore) ----

// Compact blanks dropped records instead of removing them: replicas tail by
// index, as Postgres replicas tail by id, and a nil record replays as nothing.
func (l *memLog) Compact(_ context.Context, drop func([]byte) bool) (int, error) {
	l.b.mu.Lock()
	defer l.b.mu.Unlock()
	n := 0
	for i, r := range l.b.streams[l.name] {
		if r != nil && drop(r) {
			l.b.streams[l.name][i] = nil
			n++
		}
	}
	return n, nil
}

func (b *memShared) RedactAudit(_ context.Context, bodies map[uint64][2][]byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, e := range b.audit {
		if body, ok := bodies[e.Seq]; ok {
			if cur, _ := json.Marshal(e); !bytes.Equal(cur, body[0]) {
				return errRedactRace
			}
			var r AuditEntry
			if err := json.Unmarshal(body[1], &r); err != nil {
				return err
			}
			b.audit[i] = r
		}
	}
	return nil
}

func (b *memShared) PruneAudit(context.Context, uint64) (int64, error) { return 0, nil }

// ---- helpers ----

var (
	admin2 = Principal{ID: "ops@acme.example", Groups: []string{"platform-admins"}}
	admin3 = Principal{ID: "sec@acme.example", Groups: []string{"platform-admins"}}
)

// erase2 runs the two-person erasure: rp requests it on req, cp confirms it
// on conf with the same body. It returns the confirmation's answer.
func erase2(t *testing.T, req *env, rp Principal, conf *env, cp Principal, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := req.as(rp, "POST", "/api/v1/users/erase", body)
	if w.Code != 202 {
		t.Fatalf("request erasure: %d %s", w.Code, w.Body.String())
	}
	pe := decode[PendingErasure](t, w)
	return conf.as(cp, "POST", "/api/v1/users/erase/"+pe.ID+"/confirm", body)
}

// openStores is the fleet-report store each test data dir has open. A test
// "restart" (a second fileEnv on the same dir) closes the previous one first,
// as a real restart does: OpenLogStore compacts by rename, and Windows cannot
// rename over a file another handle still holds open.
var openStores sync.Map // dir -> *logStore

// fileEnv is a single replica on a data dir, its fleet reports on disk too.
func fileEnv(t *testing.T, dir string, mutate func(*Config)) *env {
	t.Helper()
	return newEnv(t, func(c *Config) {
		if prev, ok := openStores.LoadAndDelete(dir); ok {
			_ = prev.(*logStore).Close()
		}
		st, err := OpenLogStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		openStores.Store(dir, st.(*logStore))
		t.Cleanup(func() { openStores.CompareAndDelete(dir, st.(*logStore)); _ = st.(*logStore).Close() })
		c.DataDir, c.Store = dir, st
		c.auditSigningEnableAny = true // as signedPGEnv; a mutate may turn it off
		if mutate != nil {
			mutate(c)
		}
	})
}

func auditOf(t *testing.T, e *env) AuditResponse {
	t.Helper()
	w := e.as(admin, "GET", "/api/v1/audit?limit=500", "")
	if w.Code != 200 {
		t.Fatalf("audit: %d %s", w.Code, w.Body.String())
	}
	return decode[AuditResponse](t, w)
}

func testSigner(t *testing.T) bundle.KeySigner {
	t.Helper()
	priv, _, err := bundle.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	k, err := bundle.ParseSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---- erasure ----

func TestEraseFile(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, nil)
	testErase(t, e, e)
	// Nothing on disk names the subject any more, except the session epoch
	// that keeps their sessions revoked (retained, ADR-0040).
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "session-revocations.jsonl" || d.Name() == ".lock" {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(dev.ID)) || bytes.Contains(b, []byte("devos")) {
			t.Errorf("%s still names the subject: %s", d.Name(), b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A restart replays the compacted logs: still erased, chain still verifies.
	_ = e.s.Close()
	e2 := fileEnv(t, dir, nil)
	checkErased(t, e2)
	if v, err := VerifyAuditDir(dir, AuditVerifyOptions{}); err != nil || v.Error != "" {
		t.Fatalf("verify after restart: %+v %v", v, err)
	}
}

func TestEraseReplicasInMemory(t *testing.T) {
	a, c := replicas(t, newMemShared())
	testErase(t, a, c)
}

func TestEraseReplicasPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	a, c := pgReplicas(t, db)
	testErase(t, a, c)
}

// testErase erases dev on replica a and checks every store on a and c.
func testErase(t *testing.T, a, c *env) {
	t.Helper()
	devTok := enrollDevice(t, a, dev)
	otherTok := enrollDevice(t, a, Principal{ID: "carol@acme.example"})
	for _, r := range []struct{ auth, body string }{
		{"Bearer " + devTok, report("dev-laptop", "ring1-canary", "2.1.0", false)},
		{"Bearer " + tok, strings.Replace(report("dev-mbp", "ring1-canary", "2.1.0", false), `"user":"u"`, `"user":"devos"`, 1)}, // fleet token: the OS user, an alias
		{"Bearer " + otherTok, report("carol-laptop", "ring1-canary", "2.1.0", false)},
	} {
		if w := do(a.h, "POST", "/api/v1/fleet/report", r.auth, r.body); w.Code != 204 {
			t.Fatalf("report: %d %s", w.Code, w.Body.String())
		}
	}
	if w := a.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage"}`); w.Code != 201 {
		t.Fatalf("request: %d %s", w.Code, w.Body.String())
	}
	carolReq := decode[Request](t, a.as(Principal{ID: "carol@acme.example"}, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"also"}`))

	body := func(user, reason string, dry bool, aliases ...string) string {
		b, _ := json.Marshal(EraseRequest{User: user, Aliases: aliases, Reason: reason, DryRun: dry})
		return string(b)
	}
	t.Run("refused without admin, a reason, or on oneself", func(t *testing.T) {
		for _, x := range []struct {
			who  Principal
			body string
			want int
		}{
			{dev, body(dev.ID, "dsr", false), 403},
			{Principal{}, body(dev.ID, "dsr", false), 401},
			{admin, body(dev.ID, "  ", false), 422},
			{admin, body("", "dsr", false), 422},
			{admin, body(admin.ID, "dsr", false), 403},
			{admin, body(systemActor, "dsr", false), 422},
			{admin, `{"user":`, 400},
		} {
			if w := a.as(x.who, "POST", "/api/v1/users/erase", x.body); w.Code != x.want {
				t.Errorf("%s %s: %d %s, want %d", x.who.ID, x.body, w.Code, w.Body.String(), x.want)
			}
		}
		denied := false
		for _, en := range auditOf(t, a).Entries {
			denied = denied || (en.Action == "authz.deny" && en.Actor == dev.ID && en.Details["route"] == "POST /api/v1/users/erase")
		}
		if !denied {
			t.Error("a developer's erasure attempt was not audited as authz.deny")
		}
	})

	t.Run("dry run counts and changes nothing", func(t *testing.T) {
		w := a.as(admin, "POST", "/api/v1/users/erase", body(dev.ID, "DSR-1", true, "devos"))
		rep := decode[EraseReport](t, w)
		if w.Code != 200 || !rep.DryRun || rep.Erased["devices"] != 1 || rep.Erased["requests"] != 1 || rep.Erased["fleetReports"] < 2 || rep.Erased["auditEntries"] == 0 {
			t.Fatalf("dry run: %d %+v", w.Code, rep)
		}
		if do(a.h, "GET", "/api/v1/fleet/ring", "Bearer "+devTok, "").Code != 200 {
			t.Fatal("dry run revoked the device")
		}
	})

	w := erase2(t, c, admin2, a, admin, body(dev.ID, "DSR-2026-114", false, "devos")) // requested on one replica, confirmed (and run) on the other
	rep := decode[EraseReport](t, w)
	if w.Code != 200 || len(rep.Errors) > 0 || rep.Erased["devices"] != 1 || rep.Erased["requests"] != 1 || rep.Erased["fleetReports"] < 2 || rep.Erased["auditEntries"] == 0 || !strings.HasPrefix(rep.Pseudonym, "erased-") || rep.Retained["siem"] == "" {
		t.Fatalf("erase: %d %+v", w.Code, rep)
	}
	if do(a.h, "GET", "/api/v1/fleet/ring", "Bearer "+devTok, "").Code != 401 || do(c.h, "GET", "/api/v1/fleet/ring", "Bearer "+devTok, "").Code != 401 {
		t.Fatal("the erased subject's device token still works")
	}
	for _, x := range []*env{a, c} {
		checkErased(t, x)
	}
	// Everyone else's data is untouched.
	if do(c.h, "GET", "/api/v1/fleet/ring", "Bearer "+otherTok, "").Code != 200 {
		t.Fatal("another user's device was erased")
	}
	if got := decode[[]Request](t, c.as(admin, "GET", "/api/v1/requests", "")); len(got) != 1 || got[0].ID != carolReq.ID {
		t.Fatalf("other requests: %+v", got)
	}
	var erase *AuditEntry
	for _, en := range auditOf(t, a).Entries {
		if en.Action == actionErase {
			erase = &en
		}
	}
	if erase == nil || erase.Actor != admin.ID || erase.Details["severity"] != "high" || erase.Details["reason"] != "DSR-2026-114" || erase.Target != rep.Pseudonym || erase.Details["redacted"] == "" {
		t.Fatalf("subject.erase entry: %+v", erase)
	}

	t.Run("erasing again is idempotent", func(t *testing.T) {
		w := erase2(t, c, admin2, a, admin, body(dev.ID, "DSR-2026-114 retry", false))
		if rep := decode[EraseReport](t, w); w.Code != 200 || rep.Erased["devices"] != 0 || rep.Erased["auditEntries"] != 0 {
			t.Fatalf("second erasure: %d %+v", w.Code, rep)
		}
		checkErased(t, c)
	})

	t.Run("an approver is pseudonymised in the requests they decided", func(t *testing.T) {
		if w := a.as(admin, "POST", "/api/v1/requests/"+carolReq.ID+"/deny", ""); w.Code != 200 {
			t.Fatalf("deny: %d %s", w.Code, w.Body.String())
		}
		w := erase2(t, c, admin2, a, admin3, body(admin.ID, "DSR-2026-115", false))
		rep := decode[EraseReport](t, w)
		if w.Code != 200 || rep.Erased["requestsPseudonymised"] != 1 || rep.Erased["requests"] != 0 {
			t.Fatalf("erase approver: %d %+v", w.Code, rep)
		}
		got := decode[[]Request](t, a.as(admin2, "GET", "/api/v1/requests", ""))
		if len(got) != 1 || got[0].DecidedBy != rep.Pseudonym || got[0].Status != StatusDenied {
			t.Fatalf("decided request after erasing the approver: %+v", got)
		}
		if res := decode[AuditResponse](t, c.as(admin2, "GET", "/api/v1/audit?limit=500", "")); !res.Verified {
			t.Fatalf("chain after a second erasure: %s", res.VerifyError)
		}
	})
}

// checkErased: no store e serves names dev, and the audit chain verifies.
func checkErased(t *testing.T, e *env) {
	t.Helper()
	for _, d := range decode[[]Device](t, e.as(admin2, "GET", "/api/v1/devices", "")) {
		if sameUser(d.UserID, dev.ID) {
			t.Errorf("device of the erased subject listed: %+v", d)
		}
	}
	for _, r := range decode[[]Request](t, e.as(admin2, "GET", "/api/v1/requests", "")) {
		if sameUser(r.User, dev.ID) {
			t.Errorf("request of the erased subject listed: %+v", r)
		}
	}
	for _, h := range decode[FleetResponse](t, e.as(admin2, "GET", "/api/v1/fleet", "")).Hosts {
		if sameUser(h.User, dev.ID) || h.User == "devos" {
			t.Errorf("report of the erased subject listed: %+v", h)
		}
	}
	w := e.as(admin2, "GET", "/api/v1/audit?limit=500", "")
	res := decode[AuditResponse](t, w)
	if !res.Verified {
		t.Fatalf("audit chain no longer verifies after erasure: %s", res.VerifyError)
	}
	if strings.Contains(w.Body.String(), dev.ID) || strings.Contains(w.Body.String(), "devos") {
		t.Fatalf("audit still names the subject: %s", w.Body.String())
	}
}

func TestEraseTamperedRedactionIsCaught(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, nil)
	if w := e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage"}`); w.Code != 201 {
		t.Fatal(w.Code)
	}
	if w := erase2(t, e, admin2, e, admin, `{"user":"`+dev.ID+`","reason":"DSR-3"}`); w.Code != 200 {
		t.Fatalf("erase: %d %s", w.Code, w.Body.String())
	}
	if v, _ := VerifyAuditDir(dir, AuditVerifyOptions{}); v.Error != "" {
		t.Fatalf("after erasure: %+v", v)
	}
	// Editing a redacted entry (its hash is not recomputed, by design) breaks
	// the digest its subject.erase entry vouched for.
	p := filepath.Join(dir, auditActive)
	b, _ := os.ReadFile(p)
	tampered := strings.Replace(string(b), `"kind":"mcp-server"`, `"kind":"model"`, 1)
	if tampered == string(b) {
		t.Fatal("fixture: no redacted request.create entry")
	}
	if err := os.WriteFile(p, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, _ := VerifyAuditDir(dir, AuditVerifyOptions{}); !strings.Contains(v.Error, "not vouched for") {
		t.Fatalf("tampered redacted entry: %+v", v)
	}
	// Marking an ordinary entry redacted to dodge its hash check is caught the same way.
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	last := len(lines) - 1 // the subject.erase entry: not redacted, so its hash is its proof
	lines[last] = strings.Replace(strings.Replace(lines[last], `"prev":`, `"redacted":true,"prev":`, 1), "DSR-3", "DSR-4", 1)
	_ = os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if v, _ := VerifyAuditDir(dir, AuditVerifyOptions{}); v.Error == "" {
		t.Fatalf("forged redaction mark accepted: %+v", v)
	}
}

// ---- retention ----

func TestRetentionSweepFile(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, func(c *Config) {
		c.Audit.Rotation = AuditRotation{MaxBytes: 4096}
		c.Retention = Retention{FleetReports: 24 * time.Hour, Requests: 24 * time.Hour, Devices: 24 * time.Hour, Audit: MinAuditRetention}
	})
	testRetention(t, e, e)
	if v, err := VerifyAuditDir(dir, AuditVerifyOptions{}); err != nil || v.Error != "" || v.First <= 1 {
		t.Fatalf("verify after audit retention: %+v %v", v, err)
	}
	// The deleted records are gone from disk, not just from memory.
	for _, f := range []string{"requests.jsonl", "devices.jsonl", "reports.jsonl"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if bytes.Contains(b, []byte("old-")) {
			t.Errorf("%s still holds swept records: %s", f, b)
		}
	}
	_ = e.s.Close()
	e2 := fileEnv(t, dir, nil)
	if res := auditOf(t, e2); !res.Verified {
		t.Fatalf("after restart: %s", res.VerifyError)
	}
}

func TestRetentionSweepPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	b := NewPGBackend(db)
	a, c := pgReplicas(t, db)
	for _, x := range []*env{a, c} {
		x.s.cfg.Retention = Retention{FleetReports: 24 * time.Hour, Requests: 24 * time.Hour, Devices: 24 * time.Hour, Audit: MinAuditRetention}
	}
	testRetention(t, a, c)
	if v, err := VerifyAuditBackend(context.Background(), b, AuditVerifyOptions{}); err != nil || v.Error != "" || v.First <= 1 {
		t.Fatalf("verify after audit retention: %+v %v", v, err)
	}
}

// testRetention seeds old and fresh records, moves the clock 400 days on,
// sweeps on a and checks that only the expired records are gone (on c too).
func testRetention(t *testing.T, a, c *env) {
	t.Helper()
	oldDev := Principal{ID: "old-dev@acme.example"}
	oldTok := enrollDevice(t, a, oldDev)
	if w := do(a.h, "POST", "/api/v1/fleet/report", "Bearer "+oldTok, report("old-host", "ring1-canary", "2.1.0", false)); w.Code != 204 {
		t.Fatal(w.Code)
	}
	decided := decode[Request](t, a.as(oldDev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"old-decided"}`))
	if w := a.as(admin, "POST", "/api/v1/requests/"+decided.ID+"/deny", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	pending := decode[Request](t, a.as(Principal{ID: "waiting@acme.example"}, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"still waiting"}`))
	for i := range 80 { // enough old entries to fill several 4 KiB segments on the file backend
		a.s.Audit(context.Background(), "old-actor", "test.old", strings.Repeat("x", 40), map[string]string{"i": string(rune('a' + i%26))})
	}
	for _, x := range []*env{a, c} {
		*x.now = x.now.Add(400 * 24 * time.Hour)
	}
	freshTok := enrollDevice(t, a, dev)
	if w := do(a.h, "POST", "/api/v1/fleet/report", "Bearer "+freshTok, report("fresh-host", "ring1-canary", "2.1.0", false)); w.Code != 204 {
		t.Fatal(w.Code)
	}
	for range 40 {
		a.s.Audit(context.Background(), "new-actor", "test.new", strings.Repeat("y", 40), nil)
	}

	out, err := a.s.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v (%v)", err, out)
	}
	if out["requests"] != 1 || out["devices"] != 1 || out["fleetReports"] < 1 || out["auditEntries"] == 0 {
		t.Fatalf("sweep removed %v", out)
	}
	for _, x := range []*env{a, c} {
		reqs := decode[[]Request](t, x.as(admin, "GET", "/api/v1/requests", ""))
		if len(reqs) != 1 || reqs[0].ID != pending.ID {
			t.Fatalf("requests after the sweep (a pending request is never swept): %+v", reqs)
		}
		devs := decode[[]Device](t, x.as(admin, "GET", "/api/v1/devices", ""))
		if len(devs) != 1 || devs[0].UserID != dev.ID {
			t.Fatalf("devices after the sweep: %+v", devs)
		}
		hosts := decode[FleetResponse](t, x.as(admin, "GET", "/api/v1/fleet", "")).Hosts
		if len(hosts) != 1 || hosts[0].Hostname != "fresh-host" {
			t.Fatalf("fleet after the sweep: %+v", hosts)
		}
		res := auditOf(t, x)
		if !res.Verified {
			t.Fatalf("audit after the sweep: %s", res.VerifyError)
		}
		if !slices.ContainsFunc(res.Entries, func(e AuditEntry) bool { return e.Action == actionRetention }) ||
			!slices.ContainsFunc(res.Entries, func(e AuditEntry) bool { return e.Action == "retention.sweep" }) {
			t.Fatal("the sweep was not audited")
		}
	}
	if do(a.h, "GET", "/api/v1/fleet/ring", "Bearer "+oldTok, "").Code != 401 || do(c.h, "GET", "/api/v1/fleet/ring", "Bearer "+freshTok, "").Code != 200 {
		t.Fatal("device tokens after the sweep")
	}
	if again, err := a.s.Sweep(context.Background()); err != nil || len(again) != 0 {
		t.Fatalf("second sweep: %v %v", again, err)
	}
}

func TestRetentionKeepsUndeliveredAudit(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, func(c *Config) {
		c.Audit = AuditConfig{Rotation: AuditRotation{MaxBytes: 4096}, Export: AuditExport{Sinks: []AuditSink{{Name: "siem", Type: sinkWebhook, URL: "https://siem.invalid/x"}}}}
		c.Retention = Retention{Audit: MinAuditRetention}
	})
	for range 80 {
		e.s.Audit(context.Background(), "a", "test.old", strings.Repeat("x", 60), nil)
	}
	*e.now = e.now.Add(400 * 24 * time.Hour)
	e.s.Audit(context.Background(), "a", "test.new", "", nil)
	if out, err := e.s.Sweep(context.Background()); err != nil || out["auditEntries"] != 0 {
		t.Fatalf("pruned entries the SIEM sink never received: %v %v", out, err)
	}
	e.s.forwarders[0].acked.Store(1 << 40) // the sink caught up
	if out, err := e.s.Sweep(context.Background()); err != nil || out["auditEntries"] == 0 {
		t.Fatalf("delivered entries not pruned: %v %v", out, err)
	}
}

func TestRetentionRunsOnLeaderOnly(t *testing.T) {
	b := newMemShared()
	a, _ := replicas(t, b)
	a.s.cfg.Retention = Retention{Requests: time.Hour, Interval: 10 * time.Millisecond}
	r := decode[Request](t, a.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"x"}`))
	if w := a.as(admin, "POST", "/api/v1/requests/"+r.ID+"/deny", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	*a.now = a.now.Add(48 * time.Hour)

	// Another replica holds the maintenance lease: a does not sweep.
	held, release := make(chan struct{}), make(chan struct{})
	lctx, stop := context.WithCancel(context.Background())
	go b.Leased(lctx, "maintenance", func(context.Context, rollout.Docs) { close(held); <-release })
	<-held
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.s.RunMaintenance(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(100 * time.Millisecond)
	if n := len(decode[[]Request](t, a.as(admin, "GET", "/api/v1/requests", ""))); n != 1 {
		t.Fatalf("a replica without the lease swept: %d requests left", n)
	}
	close(release)
	stop() // the leader goes away; a takes the lease and sweeps
	deadline := time.Now().Add(5 * time.Second)
	for len(decode[[]Request](t, a.as(admin, "GET", "/api/v1/requests", ""))) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the new leader never swept")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRetentionValidate(t *testing.T) {
	for _, c := range []struct {
		r  Retention
		ok bool
	}{
		{Retention{}, true},
		{Retention{FleetReports: time.Hour, Requests: 24 * time.Hour, Devices: 2 * time.Hour, Audit: MinAuditRetention}, true},
		{Retention{Requests: time.Minute}, false},
		{Retention{Audit: 24 * time.Hour}, false},
		{Retention{Devices: -time.Hour}, false},
	} {
		if err := c.r.validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.r, err)
		}
	}
}

// ---- signed checkpoints (ADR-0041) ----

func TestSignedCheckpoints(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	v := AuditVerifyOptions{Verifier: k.Verifier()}
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	ctx := context.Background()
	for range 3 {
		e.s.Audit(ctx, "alice", "experiment.kill", "exp", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("checkpoint: %v %v", ok, err)
	}
	if ok, err := e.s.Checkpoint(ctx); ok || err != nil {
		t.Fatalf("a checkpoint with nothing new since the last: %v %v", ok, err)
	}
	e.s.Audit(ctx, "alice", "experiment.unkill", "exp", nil)
	r, err := VerifyAuditDir(dir, v)
	if err != nil || r.Error != "" || r.Checkpoints != 1 || r.LastCheckpoint != 5 || r.UnsignedTail != 1 {
		t.Fatalf("signed log: %+v %v", r, err)
	}
	if res := auditOf(t, e); !res.Verified || !res.Signed || res.Checkpoints != 1 || res.LastCheckpoint != 5 {
		t.Fatalf("GET /api/v1/audit: %+v", res)
	}
	export := filepath.Join(t.TempDir(), "siem.jsonl") // what the SIEM holds: every entry so far
	orig, _ := os.ReadFile(filepath.Join(dir, auditActive))
	if err := os.WriteFile(export, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	anchor, ok, err := LastCheckpoint(export, k.Verifier())
	if err != nil || !ok || anchor.Seq != 5 {
		t.Fatalf("anchor: %+v %v %v", anchor, ok, err)
	}
	if r, err := VerifyAuditExport(export, v); err != nil || r.Error != "" {
		t.Fatalf("export: %+v %v", r, err)
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier(), Anchor: &anchor}); r.Error != "" || !r.Anchored {
		t.Fatalf("anchored: %+v", r)
	}

	entries := func() []AuditEntry {
		var out []AuditEntry
		_ = eachAuditFile(filepath.Join(dir, auditActive), func(_ []byte, e AuditEntry) bool { out = append(out, e); return true })
		return out
	}
	write := func(es []AuditEntry) {
		var b []byte
		for _, x := range es {
			line, _ := json.Marshal(x)
			b = append(append(b, line...), '\n')
		}
		if err := os.WriteFile(filepath.Join(dir, auditActive), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// rechain re-links es from scratch, as an attacker with write access can.
	rechain := func(es []AuditEntry, fixHead bool) []AuditEntry {
		var seq uint64
		head := ""
		out := make([]AuditEntry, 0, len(es))
		for _, x := range es {
			if fixHead && x.Action == actionCheckpoint {
				x.Details = map[string]string{"seq": x.Details["seq"], "head": head, "sig": x.Details["sig"], "alg": x.Details["alg"], "keyId": x.Details["keyId"]}
			}
			x = ChainAuditEntry(x, seq, head)
			out = append(out, x)
			seq, head = x.Seq, x.Hash
		}
		return out
	}

	for _, c := range []struct {
		name    string
		mutate  func([]AuditEntry) []AuditEntry
		opts    AuditVerifyOptions
		wantErr string // "" = verifies
	}{
		{"untouched", func(es []AuditEntry) []AuditEntry { return es }, v, ""},
		{"recomputed chain, checkpoint left as signed", func(es []AuditEntry) []AuditEntry {
			es[0].Actor = "mallory"
			return rechain(es, false)
		}, AuditVerifyOptions{}, "chain was recomputed"},
		{"recomputed chain and checkpoint head", func(es []AuditEntry) []AuditEntry {
			es[0].Actor = "mallory"
			return rechain(es, true)
		}, v, "signature does not verify"},
		{"checkpoints dropped and the chain recomputed", func(es []AuditEntry) []AuditEntry {
			es[0].Actor = "mallory"
			return rechain(slices.DeleteFunc(es, func(x AuditEntry) bool { return x.Action == actionCheckpoint || x.Action == actionSigningEnabled }), false)
		}, AuditVerifyOptions{Verifier: k.Verifier(), Anchor: &anchor}, "anchored checkpoint"},
		{"tail cut back past the anchored checkpoint", func(es []AuditEntry) []AuditEntry { return es[:3] }, AuditVerifyOptions{Verifier: k.Verifier(), Anchor: &anchor}, "cut from the end"},
		{"tail cut, without an anchor (undetectable from the log alone)", func(es []AuditEntry) []AuditEntry { return es[:3] }, v, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			write(c.mutate(entries()))
			t.Cleanup(func() { _ = os.WriteFile(filepath.Join(dir, auditActive), orig, 0o600) })
			r, err := VerifyAuditDir(dir, c.opts)
			if err != nil {
				t.Fatal(err)
			}
			if c.wantErr == "" && r.Error != "" || c.wantErr != "" && !strings.Contains(r.Error, c.wantErr) {
				t.Fatalf("got %q, want %q", r.Error, c.wantErr)
			}
		})
	}
}

func TestCheckpointAtRotationAndLegacyLogs(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k; c.Audit.Rotation = AuditRotation{MaxBytes: 4096} })
	e.s.Audit(context.Background(), "alice", "experiment.kill", "first", nil)
	if ok, err := e.s.Checkpoint(context.Background()); !ok || err != nil { // enables signing: the marker, then rotation checkpoints
		t.Fatal(ok, err)
	}
	for range 60 {
		e.s.Audit(context.Background(), "alice", "experiment.kill", strings.Repeat("x", 60), nil)
	}
	segs, _ := listAuditSegs(dir)
	if len(segs) < 2 {
		t.Fatalf("fixture: %d rotated segments", len(segs))
	}
	for _, sg := range segs {
		var last AuditEntry
		_ = eachAuditFile(sg.path, func(_ []byte, e AuditEntry) bool { last = e; return true })
		if last.Action != actionCheckpoint {
			t.Errorf("%s does not end with a signed checkpoint: %+v", sg.path, last)
		}
	}
	if r, err := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); err != nil || r.Error != "" || r.Checkpoints != len(segs)+1 {
		t.Fatalf("rotated signed log: %+v %v", r, err)
	}

	// A log written before ADR-0041 (no checkpoints) still verifies, with or without a key.
	legacy := t.TempDir()
	for range 5 {
		if err := AppendAuditOffline(legacy, "alice", "experiment.kill", "exp", nil, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []AuditVerifyOptions{{}, {Verifier: k.Verifier()}} {
		if r, err := VerifyAuditDir(legacy, o); err != nil || r.Error != "" || r.Entries != 5 {
			t.Fatalf("legacy log: %+v %v", r, err)
		}
	}
}

// pgReplicas is replicas on Postgres with the shared fleet report store too.
func pgReplicas(t *testing.T, db *pgstore.DB) (*env, *env) {
	t.Helper()
	b := NewPGBackend(db)
	mk := func() *env {
		kills, err := controller.NewKillStore(context.Background(), b)
		if err != nil {
			t.Fatal(err)
		}
		e := newEnv(t, func(c *Config) { c.Backend, c.KillStore, c.Store = b, kills, NewPGStore(db) })
		*e.now = time.Now().UTC() // shared expiries are judged on the database clock
		return e
	}
	return mk(), mk()
}
