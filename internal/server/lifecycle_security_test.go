package server

// Regression tests for the security review of the ADR-0040/0041 change. Each
// started as a proof of concept that passed against the first version.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/storage"
)

func logEntries(t *testing.T, dir string) []AuditEntry {
	t.Helper()
	var out []AuditEntry
	if err := eachAuditFile(filepath.Join(dir, auditActive), func(_ []byte, e AuditEntry) bool { out = append(out, e); return true }); err != nil {
		t.Fatal(err)
	}
	return out
}

func writeEntries(t *testing.T, dir string, es []AuditEntry) {
	t.Helper()
	var b []byte
	for _, x := range es {
		line, _ := json.Marshal(x)
		b = append(append(b, line...), '\n')
	}
	if err := os.WriteFile(filepath.Join(dir, auditActive), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// siemCopy copies the active segment as the SIEM's export and returns its
// path and newest checkpoint.
func siemCopy(t *testing.T, dir string, k bundle.KeySigner) (string, AuditEntry) {
	t.Helper()
	export := filepath.Join(t.TempDir(), "siem.jsonl")
	b, _ := os.ReadFile(filepath.Join(dir, auditActive))
	if err := os.WriteFile(export, b, 0o600); err != nil {
		t.Fatal(err)
	}
	a, ok, err := LastCheckpoint(export, k.Verifier())
	if err != nil || !ok {
		t.Fatalf("anchor: %v %v", ok, err)
	}
	return export, a
}

func eraseBody(user, reason string, aliases ...string) string {
	b, _ := json.Marshal(EraseRequest{User: user, Aliases: aliases, Reason: reason})
	return string(b)
}

// H1: an attacker with write access marks an entry redacted (skipping its hash
// check) and appends a chained subject.erase vouching for it. With the
// public key, only a subject.erase the audit key signed vouches.
func TestForgedRedactionRejected(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	ctx := context.Background()
	e.s.Audit(ctx, "mallory@acme.example", "experiment.kill", "prod-ring", map[string]string{"why": "sabotage"})
	for range 3 {
		e.s.Audit(ctx, "alice@acme.example", "experiment.unkill", "exp", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_, anchor := siemCopy(t, dir, k)
	_ = e.s.Close()

	es := logEntries(t, dir)
	es[0].Actor, es[0].Details, es[0].Redacted = "alice@acme.example", map[string]string{"why": "routine"}, true
	last := es[len(es)-1]
	forged := ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: "boss@acme.example", Action: actionErase, Target: "erased-xyz",
		Details: map[string]string{"severity": "high", "subject": "erased-xyz", "redacted": "1:" + es[0].redactionDigest(),
			"sig": "AAAA", "alg": bundle.AlgEd25519}}, last.Seq, last.Hash)
	writeEntries(t, dir, append(es, forged))
	r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier(), Anchor: &anchor})
	if r.Error == "" {
		t.Fatalf("forged redaction accepted with the key and an anchor: %+v", r)
	}
	delete(forged.Details, "sig") // unsigned: vouches for nothing with a key
	forged = ChainAuditEntry(forged, last.Seq, last.Hash)
	writeEntries(t, dir, append(es, forged))
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); !strings.Contains(r.Error, "unsigned subject.erase") {
		t.Fatalf("unsigned vouch accepted with the key: %+v", r)
	}
}

// H1, the legitimate path: a signed erasure verifies with the key, and
// --compare-export reports its redactions as such, not as tampering.
func TestSignedErasureVerifiesWithKey(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	if w := e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage"}`); w.Code != 201 {
		t.Fatal(w.Code)
	}
	if ok, err := e.s.Checkpoint(context.Background()); !ok || err != nil {
		t.Fatal(ok, err)
	}
	export, _ := siemCopy(t, dir, k)
	if w := erase2(t, e, admin2, e, admin, eraseBody(dev.ID, "DSR-7")); w.Code != 200 {
		t.Fatalf("erase: %d %s", w.Code, w.Body.String())
	}
	exp, err := LoadExport(export)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier(), Export: exp})
	if err != nil || r.Error != "" || r.RedactedSinceExport == 0 {
		t.Fatalf("signed erasure: %+v %v", r, err)
	}
	// An ordinary entry edited in place differs from the export: caught by content.
	es := logEntries(t, dir)
	es[len(es)-1].Details["reason"] = "DSR-8"
	writeEntries(t, dir, es)
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Export: exp}); r.Error == "" {
		t.Fatalf("edited entry passed the export comparison: %+v", r)
	}
}

// H2: deleting recent entries (a signed checkpoint among them) behind a
// forged audit.retention entry. With the key the cut must be signed; without
// it, the cut must at least be the system's and MinAuditRetention old.
func TestForgedRetentionCutRejected(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	ctx := context.Background()
	for i := range 6 {
		e.s.Audit(ctx, "mallory@acme.example", "breakglass.unlock", "x"+strconv.Itoa(i), nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.s.Audit(ctx, "alice@acme.example", "experiment.unkill", "exp", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_, anchor := siemCopy(t, dir, k)
	_ = e.s.Close()
	es := logEntries(t, dir)
	cut := es[int(anchor.Seq)-3]
	rest := es[anchor.Seq-2:]
	l := es[len(es)-1]
	for _, c := range []struct {
		name   string
		cutoff time.Time
		actor  string
		opts   AuditVerifyOptions
	}{
		{"with the key, unsigned", time.Now().Add(-400 * 24 * time.Hour), systemActor, AuditVerifyOptions{Verifier: k.Verifier(), Anchor: &anchor}},
		{"without the key, cutoff too recent", time.Now(), systemActor, AuditVerifyOptions{}},
		{"without the key, not the system's", time.Now().Add(-400 * 24 * time.Hour), "boss@acme.example", AuditVerifyOptions{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			forged := ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: c.actor, Action: actionRetention,
				Details: map[string]string{"through": strconv.FormatUint(cut.Seq, 10), "throughHash": cut.Hash, "cutoff": c.cutoff.UTC().Format(time.RFC3339)}}, l.Seq, l.Hash)
			writeEntries(t, dir, append(append([]AuditEntry(nil), rest...), forged))
			if r, _ := VerifyAuditDir(dir, c.opts); !strings.Contains(r.Error, "oldest entries were removed") && !strings.Contains(r.Error, "unsigned subject.erase or audit.retention") {
				t.Fatalf("forged cut accepted: %+v", r)
			}
		})
	}
}

// H2, the legitimate path: a sweep's signed cut verifies with the key.
func TestSignedRetentionVerifiesWithKey(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) {
		c.AuditSigner, c.Audit.Rotation, c.Retention = k, AuditRotation{MaxBytes: 4096}, Retention{Audit: MinAuditRetention}
	})
	for range 80 {
		e.s.Audit(context.Background(), "old-actor", "test.old", strings.Repeat("x", 40), nil)
	}
	*e.now = e.now.Add(400 * 24 * time.Hour)
	for range 10 {
		e.s.Audit(context.Background(), "new-actor", "test.new", "", nil)
	}
	if ok, err := e.s.Checkpoint(context.Background()); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if out, err := e.s.Sweep(context.Background()); err != nil || out["auditEntries"] == 0 {
		t.Fatalf("sweep: %v %v", out, err)
	}
	if r, err := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); err != nil || r.Error != "" || r.First <= 1 {
		t.Fatalf("signed cut: %+v %v", r, err)
	}
}

// H3: the self-erasure guard covers every alias, compared canonically.
func TestEraseRefusesSelfViaAlias(t *testing.T) {
	e := fileEnv(t, t.TempDir(), nil)
	e.s.Audit(context.Background(), admin.ID, "breakglass.unlock", "prod", nil)
	for _, alias := range []string{admin.ID, "  BOSS@acme.example ", "user:" + admin.ID} {
		if w := e.as(admin, "POST", "/api/v1/users/erase", eraseBody("nobody@acme.example", "DSR-1", alias)); w.Code != 403 {
			t.Errorf("alias %q: %d %s", alias, w.Code, w.Body.String())
		}
	}
	if w := e.as(admin, "POST", "/api/v1/users/erase", eraseBody(" Boss@Acme.Example", "DSR-1")); w.Code != 403 {
		t.Errorf("own id, other case: %d", w.Code)
	}
}

// H3, N4, N6: every erasure needs a second, different admin, who must
// resubmit what they confirm; GET shows the pending erasure.
func TestEraseNeedsSecondAdmin(t *testing.T) {
	e := fileEnv(t, t.TempDir(), nil)
	e.s.Audit(context.Background(), dev.ID, "request.create", "r1", nil)
	body := eraseBody(dev.ID, "DSR-9", "devos")
	w := e.as(admin2, "POST", "/api/v1/users/erase", body)
	pe := decode[PendingErasure](t, w)
	if w.Code != 202 || pe.ID == "" || pe.RequestedBy != admin2.ID {
		t.Fatalf("erasing a developer is not pending a second admin: %d %s", w.Code, w.Body.String())
	}
	got := decode[PendingErasure](t, e.as(admin3, "GET", "/api/v1/users/erase/"+pe.ID, ""))
	if got.User != dev.ID || got.Reason != "DSR-9" || len(got.Aliases) != 1 || got.RequestedBy != admin2.ID {
		t.Fatalf("GET pending erasure: %+v", got)
	}
	if w := e.as(dev, "GET", "/api/v1/users/erase/"+pe.ID, ""); w.Code != 403 {
		t.Fatalf("a non-admin read a pending erasure: %d", w.Code)
	}
	confirm := "/api/v1/users/erase/" + pe.ID + "/confirm"
	for _, x := range []struct {
		who  Principal
		body string
		want int
	}{
		{admin2, body, 403},                       // the requester
		{dev, body, 403},                          // not an admin
		{admin3, "", 400},                         // blind: nothing resubmitted
		{admin3, eraseBody(dev.ID, "DSR-9"), 409}, // an alias dropped
		{admin3, eraseBody("carol@acme.example", "DSR-9", "devos"), 409}, // another person
		{admin3, eraseBody(dev.ID, "DSR-10", "devos"), 409},              // another reason
	} {
		if w := e.as(x.who, "POST", confirm, x.body); w.Code != x.want {
			t.Errorf("%s confirming %s: %d %s, want %d", x.who.ID, x.body, w.Code, w.Body.String(), x.want)
		}
	}
	if w := e.as(admin3, "POST", "/api/v1/users/erase/nope/confirm", body); w.Code != 404 {
		t.Fatalf("unknown pending erasure: %d", w.Code)
	}
	// Canonically the same request (case, spacing) confirms it.
	w = e.as(admin3, "POST", confirm, eraseBody(" DEV@acme.example", "DSR-9 ", "DevOS"))
	if rep := decode[EraseReport](t, w); w.Code != 200 || rep.Erased["auditEntries"] == 0 {
		t.Fatalf("confirmed erasure: %d %s", w.Code, w.Body.String())
	}
	if w := e.as(admin3, "POST", confirm, body); w.Code != 404 {
		t.Fatalf("confirmed twice: %d", w.Code)
	}
	er := lastErase(t, e, admin3)
	if er.Actor != admin3.ID || er.Details["requestedBy"] != admin2.ID || er.Details["aliases"] != "1" || !strings.HasPrefix(er.Details["aliasHashes"], "h:") {
		t.Fatalf("subject.erase does not record both admins and the aliases: %+v", er)
	}
}

// N8: a confirmation that meets a busy erasure lock answers 503 and the
// erasure stays pending.
func TestConfirmKeepsPendingWhenLockBusy(t *testing.T) {
	b := newMemShared()
	e := newEnv(t, func(c *Config) { c.Backend = b })
	e.s.eraseMu.wait = 10 * time.Millisecond
	*e.now = time.Now().UTC() // shared expiries are judged on the store's clock
	body := eraseBody(dev.ID, "DSR-11")
	pe := decode[PendingErasure](t, e.as(admin2, "POST", "/api/v1/users/erase", body))
	if ok, _ := b.TryLock(context.Background(), "lock", "erasure", "another-replica", time.Minute); !ok {
		t.Fatal("could not hold the lock")
	}
	if w := e.as(admin3, "POST", "/api/v1/users/erase/"+pe.ID+"/confirm", body); w.Code != 503 {
		t.Fatalf("confirm under a busy lock: %d %s", w.Code, w.Body.String())
	}
	_ = b.Unlock(context.Background(), "lock", "erasure", "another-replica")
	if w := e.as(admin3, "POST", "/api/v1/users/erase/"+pe.ID+"/confirm", body); w.Code != 200 {
		t.Fatalf("the pending erasure was lost to the busy lock: %d %s", w.Code, w.Body.String())
	}
}

// N3: the subject hashes in audit entries are keyed: no dictionary of
// candidate ids reverses them without the server's key.
func TestSubjectHashNeedsServerKey(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, nil)
	b, _ := json.Marshal(EraseRequest{User: "bob@acme.example", Reason: "DSR-9", DryRun: true})
	e.as(admin, "POST", "/api/v1/users/erase", string(b))
	e.as(admin, "POST", "/api/v1/users/erase", eraseBody("bob@acme.example", "DSR-9"))
	found := 0
	for _, x := range logEntries(t, dir) {
		if x.Action != "subject.erase.preview" && x.Action != "subject.erase.request" {
			continue
		}
		found++
		h := x.Details["subject"]
		for _, salt := range []string{"", x.Target, x.Actor + x.Details["reason"]} { // the public salts of the first version
			s := sha256.Sum256([]byte(salt + "\n" + canonicalUser("bob@acme.example")))
			if h == "h:"+hex.EncodeToString(s[:8]) || strings.Contains(h, "bob") {
				t.Errorf("%s: subject hash reversible without the key: %s", x.Action, h)
			}
		}
		if h != e.s.subjectHash("bob@acme.example") {
			t.Errorf("%s: subject hash is not the keyed one", x.Action)
		}
	}
	if found != 2 {
		t.Fatalf("%d preview/request entries", found)
	}
}

func lastErase(t *testing.T, e *env, p Principal) AuditEntry {
	t.Helper()
	var er AuditEntry
	for _, x := range decode[AuditResponse](t, e.as(p, "GET", "/api/v1/audit?limit=500", "")).Entries {
		if x.Action == actionErase {
			er = x
		}
	}
	return er
}

// M1: aliases that are not identifiers are refused, so an erasure can no
// longer rewrite seqs or checkpoints and break the chain for good.
func TestEraseRefusesNonIdentityAliases(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	for range 3 {
		e.s.Audit(context.Background(), "alice@acme.example", "experiment.kill", "exp", nil)
	}
	if _, err := e.s.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"3", systemActor, "erased-abc", "ab", "pending", "admin", "ring1-canary", "2026-01-02", "2026-01-02T03:04:05Z"} {
		if w := e.as(admin, "POST", "/api/v1/users/erase", eraseBody("nobody@acme.example", "DSR-1", alias)); w.Code != 422 {
			t.Errorf("alias %q: %d %s", alias, w.Code, w.Body.String())
		}
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); r.Error != "" {
		t.Fatalf("chain after refused erasures: %+v", r)
	}
}

// M1: only identity fields are pseudonymised, never chain entries.
func TestRedactIdentityFieldsOnly(t *testing.T) {
	m := newSubjectMatcher("dev@acme.example")
	got, ok := m.redact(AuditEntry{Action: "x", Actor: "a", Details: map[string]string{
		"user": "dev@acme.example", "note": "dev@acme.example", "count": "3",
		"record": `{"who":{"user":"dev@acme.example","vendorUser":"other","agents":["dev@acme.example"]},"tools":["dev@acme.example"]}`,
	}}, "erased-1")
	if !ok || got.Details["user"] != "erased-1" || got.Details["note"] != "dev@acme.example" {
		t.Fatalf("identity keys: %+v", got.Details)
	}
	if rec := got.Details["record"]; strings.Count(rec, "erased-1") != 2 || !strings.Contains(rec, `"tools":["dev@acme.example"]`) {
		t.Fatalf("ledger record: %s", rec)
	}
	for _, a := range []string{actionCheckpoint, actionRetention, actionErase} {
		if _, ok := m.redact(AuditEntry{Action: a, Actor: "dev@acme.example"}, "erased-1"); ok {
			t.Errorf("%s redacted", a)
		}
	}
}

type slowSigner struct {
	bundle.KeySigner
	during func(ctx context.Context)
}

func (s slowSigner) Sign(ctx context.Context, d string) ([]byte, error) {
	if s.during != nil {
		s.during(ctx)
	}
	return s.KeySigner.Sign(ctx, d)
}

// M2: a burst of entries while a slow signer signs a checkpoint: the
// checkpoint is dropped (retried next interval) instead of breaking the chain.
func TestSlowCheckpointDroppedNotBroken(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	var srv *Server
	ss := slowSigner{KeySigner: k}
	e := fileEnv(t, dir, func(c *Config) {
		ss.during = func(context.Context) {
			for range 300 {
				srv.Audit(context.Background(), "viewer", "authz.deny", "/x", nil)
			}
		}
		c.AuditSigner = ss
	})
	srv = e.s
	e.s.Audit(context.Background(), "alice@acme.example", "experiment.kill", "exp", nil)
	if ok, err := e.s.Checkpoint(context.Background()); ok || err == nil {
		t.Fatalf("a checkpoint signed during a 300-entry burst was appended: %v %v", ok, err)
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{}); r.Error != "" {
		t.Fatalf("chain: %+v", r)
	}
}

// M3: an erasure compacts only the erased requests' records and the
// superseded records of rewritten ones, never another user's live request.
func TestEraseKeepsOthersRequestsOnDisk(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, nil)
	carol := Principal{ID: "carol@acme.example"}
	if w := e.as(carol, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"dev-tools"}`); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := erase2(t, e, admin2, e, admin, eraseBody("nobody@acme.example", "DSR-1", "dev-tools")); w.Code != 200 {
		t.Fatalf("erase: %d %s", w.Code, w.Body.String())
	}
	_ = e.s.Close()
	e2 := fileEnv(t, dir, nil)
	if n := len(e2.s.reqs.list(func(*Request) bool { return true })); n != 1 {
		t.Fatalf("carol's request lost on restart: %d left", n)
	}
}

// M4: retention on Postgres waits for each configured sink's own cursor; a
// cursor left by a sink no longer configured does not count.
func TestDeliveredPerConfiguredSink(t *testing.T) {
	b := newMemShared()
	e := newEnv(t, func(c *Config) {
		c.Backend = b
		c.Audit.Export = AuditExport{Sinks: []AuditSink{{Name: "siem", Type: sinkWebhook, URL: "https://siem.invalid/x"}}}
	})
	ctx := context.Background()
	_ = b.PutDoc(ctx, kindAuditCursor, "old-sink", []byte(`{"seq":999,"hash":"x"}`))
	if got, err := e.s.delivered(ctx); err != nil || got != 0 {
		t.Fatalf("an old sink's cursor stood in for the configured one: %d %v", got, err)
	}
	_ = b.PutDoc(ctx, kindAuditCursor, "siem", []byte(`{"seq":5,"hash":"x"}`))
	if got, err := e.s.delivered(ctx); err != nil || got != 5 {
		t.Fatalf("delivered: %d %v", got, err)
	}
}

// M5: one entry stamped far in the past by a skewed replica does not widen
// the Postgres retention cut past newer entries (contiguous prefix, body times).
func TestRetentionCutContiguousPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	a, _ := pgReplicas(t, db)
	b := NewPGBackend(db)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)
	for _, at := range []time.Time{old, old, now, old, now} {
		if err := b.AppendAudit(ctx, AuditEntry{Time: at, Actor: "a", Action: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	c, err := a.s.verifiedChain("test")
	if err != nil {
		t.Fatal(err)
	}
	if seq, _, _, err := a.s.auditLog.retentionCut(c, now.Add(-30*24*time.Hour), ^uint64(0)); err != nil || seq != 2 {
		t.Fatalf("cut through %d (%v), want 2", seq, err)
	}
}

// N2 (Postgres): back-dating only the `at` column cannot launder a signed
// retention cut over fresh entries: the cut reads each entry's time from its
// verified body.
func TestRetentionIgnoresAtColumnPostgres(t *testing.T) {
	db, schema := pgtest.OpenTest(t)
	b := NewPGBackend(db)
	k := testSigner(t)
	kills, _ := controller.NewKillStore(context.Background(), b)
	e := newEnv(t, func(c *Config) {
		c.Backend, c.KillStore, c.Store = b, kills, NewPGStore(db)
		c.AuditSigner, c.Retention, c.auditSigningEnableAny = k, Retention{Audit: MinAuditRetention}, true
	})
	*e.now = time.Now().UTC()
	ctx := context.Background()
	for range 50 {
		e.s.Audit(ctx, "mallory@acme.example", "breakglass.unlock", "prod", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	raw, err := sql.Open("pgx", pgtest.URL(schema))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(`UPDATE halo_audit SET at = now() - interval '400 days' WHERE seq <= 45`); err != nil {
		t.Fatal(err)
	}
	if out, err := e.s.Sweep(ctx); err != nil || out["auditEntries"] != 0 {
		t.Fatalf("fresh entries cut behind a back-dated at column: %v %v", out, err)
	}
	if r, _ := VerifyAuditBackend(ctx, b, AuditVerifyOptions{Verifier: k.Verifier()}); r.Error != "" || r.First > 0 {
		t.Fatalf("chain: %+v", r)
	}
}

// N2 (file): back-dating the last entry of each rotated segment (its hash
// left alone) cannot launder a cut: the sweep verifies the chain first, and
// refuses to sign over it.
func TestRetentionRefusesBackdatedSegments(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) {
		c.AuditSigner, c.Audit.Rotation, c.Retention = k, AuditRotation{MaxBytes: 4096}, Retention{Audit: MinAuditRetention}
	})
	ctx := context.Background()
	for range 120 {
		e.s.Audit(ctx, "mallory@acme.example", "breakglass.unlock", strings.Repeat("z", 40), nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	segs, _ := listAuditSegs(dir)
	if len(segs) < 2 {
		t.Fatalf("fixture: %d segments", len(segs))
	}
	for _, sg := range segs {
		var es []AuditEntry
		_ = eachAuditFile(sg.path, func(_ []byte, x AuditEntry) bool { es = append(es, x); return true })
		es[len(es)-1].Time = e.now.Add(-400 * 24 * time.Hour)
		var b []byte
		for _, x := range es {
			line, _ := json.Marshal(x)
			b = append(append(b, line...), '\n')
		}
		_ = os.WriteFile(sg.path, b, 0o600)
	}
	before := e.s.signRefused.Load()
	if out, err := e.s.Sweep(ctx); !errors.Is(err, errChainUnverified) || out["auditEntries"] != 0 {
		t.Fatalf("sweep over a tampered chain: %v %v", out, err)
	}
	if _, err := e.s.Checkpoint(ctx); !errors.Is(err, errChainUnverified) {
		t.Fatalf("checkpoint over a tampered chain: %v", err)
	}
	if e.s.signRefused.Load() < before+2 {
		t.Fatal("refusals not counted")
	}
}

// N1: an erasure never signs a vouch over tampered content: it refuses
// while the chain does not verify, and changes nothing.
func TestEraseRefusesTamperedChain(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	ctx := context.Background()
	e.s.Audit(ctx, "mallory@acme.example", "experiment.kill", "prod-ring", map[string]string{"why": "sabotage"})
	for range 3 {
		e.s.Audit(ctx, "alice@acme.example", "experiment.unkill", "exp", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	es := logEntries(t, dir)
	es[0].Actor, es[0].Details = "bob@acme.example", map[string]string{"why": "routine maintenance"} // frame bob
	writeEntries(t, dir, es)
	w := erase2(t, e, admin2, e, admin, eraseBody("bob@acme.example", "DSR-77"))
	if rep := decode[EraseReport](t, w); w.Code != 500 || rep.Errors["auditEntries"] == "" {
		t.Fatalf("erasure over a tampered chain: %d %s", w.Code, w.Body.String())
	}
	if got := logEntries(t, dir)[0]; got.Redacted || got.Actor != "bob@acme.example" {
		t.Fatalf("the tampered entry was redacted: %+v", got)
	}
	if _, err := e.s.Checkpoint(ctx); !errors.Is(err, errChainUnverified) {
		t.Fatalf("checkpoint over the tampered chain: %v", err)
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); r.Error == "" {
		t.Fatalf("tampered chain verifies: %+v", r)
	}
}

// N9: a head recomputed in storage is never signed: the checkpoint verifies
// the chain (its earlier signed checkpoint no longer matches) and refuses.
func TestCheckpointRefusesRecomputedChain(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	ctx := context.Background()
	for range 3 {
		e.s.Audit(ctx, "alice@acme.example", "experiment.kill", "exp", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.s.Audit(ctx, "alice@acme.example", "experiment.unkill", "exp", nil)
	es := logEntries(t, dir)
	es[0].Actor = "mallory@acme.example"
	var seq uint64
	head := ""
	for i, x := range es { // recompute every hash, as a forger can
		es[i] = ChainAuditEntry(x, seq, head)
		seq, head = es[i].Seq, es[i].Hash
	}
	writeEntries(t, dir, es)
	if ok, err := e.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("signed a recomputed head: %v %v", ok, err)
	}
}

// N5: enabling the audit key after an erasure keeps signed verification
// working (the unsigned vouch precedes the first signed checkpoint), and a
// rotated key verifies with the previous one in the key set.
func TestKeyEnabledLaterAndRotated(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, nil)
	ctx := context.Background()
	e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "exp", nil)
	if w := erase2(t, e, admin2, e, admin, eraseBody("bob@acme.example", "DSR-1")); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	_ = e.s.Close()
	k1, k2 := testSigner(t), testSigner(t)
	e1 := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k1 })
	if ok, err := e1.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("first checkpoint after an unsigned erasure: %v %v", ok, err)
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k1.Verifier()}); r.Error != "" {
		t.Fatalf("signed verify after enabling the key: %+v", r)
	}
	// After the first signed checkpoint an unsigned vouch is a forgery again.
	es := logEntries(t, dir)
	l := es[len(es)-1]
	es[0].Redacted, es[0].Target = true, "x"
	forged := ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: "boss@acme.example", Action: actionErase,
		Details: map[string]string{"subject": "erased-x", "redacted": "1:" + es[0].redactionDigest()}}, l.Seq, l.Hash)
	orig, _ := os.ReadFile(filepath.Join(dir, auditActive))
	writeEntries(t, dir, append(es, forged))
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k1.Verifier()}); r.Error == "" {
		t.Fatalf("an unsigned vouch after the first signed checkpoint was accepted: %+v", r)
	}
	_ = os.WriteFile(filepath.Join(dir, auditActive), orig, 0o600)
	_ = e1.s.Close()

	pub1 := k1.Verifier().(bundle.PublicKeyVerifier)
	e2 := fileEnv(t, dir, func(c *Config) { c.AuditSigner, c.AuditPreviousKeys = k2, []bundle.PublicKeyVerifier{pub1} })
	e2.s.Audit(ctx, "alice@acme.example", "experiment.unkill", "exp", nil)
	if ok, err := e2.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("checkpoint after rotation: %v %v", ok, err)
	}
	both := bundle.Keyring{k2.Verifier().(bundle.PublicKeyVerifier), pub1} // the current key first
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: both}); r.Error != "" || r.Checkpoints != 2 {
		t.Fatalf("verify with both keys: %+v", r)
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k2.Verifier()}); r.Error == "" {
		t.Fatalf("the old checkpoint verified without the old key: %+v", r)
	}
}

// N7: when a renewal of the erasure lock fails, the erasure's context is
// cancelled (it stops before touching the audit log).
func TestKeepAliveCancelsOnLostLock(t *testing.T) {
	kv := &storage.MemKV{}
	m := clusterMutex{kv: kv, name: "erasure", renew: 5 * time.Millisecond}
	unlock, err := m.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	_ = kv.Delete(context.Background(), "lock", "erasure")
	_, _ = kv.TryLock(context.Background(), "lock", "erasure", "another-replica", time.Minute) // taken over
	ctx, cancel := context.WithCancel(context.Background())
	stop := m.keepAlive(cancel)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a lost lock did not stop the erasure")
	}
}

// M2 (residual): the window check runs at append time, under the lock that
// orders appends, on every backend.
func TestCheckpointStaleAtAppend(t *testing.T) {
	cp := AuditEntry{Action: actionCheckpoint, Details: map[string]string{"seq": "10"}}
	for _, c := range []struct {
		head uint64
		ok   bool
	}{{10, true}, {10 + checkpointWindow - checkpointMargin - 1, true}, {10 + checkpointWindow - checkpointMargin, false}, {9, false}} {
		if err := checkpointStale(cp, c.head); (err == nil) != c.ok {
			t.Errorf("head %d: %v", c.head, err)
		}
	}
}

// M2 (residual, Postgres): the head-row lock's transaction refuses a stale
// checkpoint, whatever happened between signing and appending.
func TestCheckpointStaleAtAppendPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	b := NewPGBackend(db)
	ctx := context.Background()
	for range checkpointWindow {
		if err := b.AppendAudit(ctx, AuditEntry{Time: time.Now().UTC(), Actor: "a", Action: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	cp := AuditEntry{Time: time.Now().UTC(), Actor: systemActor, Action: actionCheckpoint, Details: map[string]string{"seq": "1", "head": strings.Repeat("0", 64)}}
	if err := b.AppendAudit(ctx, cp); !errors.Is(err, errCheckpointStale) {
		t.Fatalf("stale checkpoint appended: %v", err)
	}
}

// M6: the erasure lock is renewed while an erasure runs.
func TestClusterLockKeepAlive(t *testing.T) {
	var clock atomic.Int64
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock.Store(t0.UnixNano())
	kv := &storage.MemKV{Now: func() time.Time { return time.Unix(0, clock.Load()) }}
	m := clusterMutex{kv: kv, name: "erasure", renew: 5 * time.Millisecond}
	unlock, err := m.Lock()
	if err != nil {
		t.Fatal(err)
	}
	stop := m.keepAlive(nil)
	clock.Store(t0.Add(25 * time.Second).UnixNano())
	time.Sleep(50 * time.Millisecond) // renewals extend it to t0+55s
	clock.Store(t0.Add(50 * time.Second).UnixNano())
	if ok, _ := kv.TryLock(context.Background(), "lock", "erasure", "other", clusterLockTTL); ok {
		t.Fatal("the lock lapsed while held: another replica took it")
	}
	stop()
	unlock()
}

// L1: a signer that hangs at rotation stalls appends for rotationSignTimeout
// at most; the segment rotates without the checkpoint.
func TestRotationSignTimeout(t *testing.T) {
	old := rotationSignTimeout
	rotationSignTimeout = 20 * time.Millisecond
	t.Cleanup(func() { rotationSignTimeout = old })
	dir := t.TempDir()
	hang := slowSigner{KeySigner: testSigner(t), during: func(ctx context.Context) { <-ctx.Done() }}
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = hang; c.Audit.Rotation = AuditRotation{MaxBytes: 4096} })
	start := time.Now()
	for range 60 {
		e.s.Audit(context.Background(), "alice@acme.example", "experiment.kill", strings.Repeat("x", 60), nil)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("appends stalled %s behind a hung signer", d)
	}
	if segs, _ := listAuditSegs(dir); len(segs) == 0 {
		t.Fatal("no rotation")
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{}); r.Error != "" {
		t.Fatalf("chain: %+v", r)
	}
}

// L3: the checkpoint signer is not an oracle for arbitrary head strings.
func TestCheckpointSignerRefusesNonHashHead(t *testing.T) {
	sign := checkpointSigner(testSigner(t))
	if _, err := sign(context.Background(), strings.Repeat("0", 32), 1, 1, "not a hash", time.Now()); err == nil {
		t.Fatal("signed a non-hash head")
	}
	if _, err := sign(context.Background(), strings.Repeat("0", 32), 1, 1, strings.Repeat("ab", 32), time.Now()); err != nil {
		t.Fatal(err)
	}
}

type failingHosts struct{ Store }

func (failingHosts) RemoveHosts(func(Host) bool, bool) (int, error) {
	return 0, errors.New("pq: connection to db.internal:5432 password=hunter2 failed")
}
func (failingHosts) PruneHosts(time.Time) (int, error) { return 0, nil }

// L4: a preview never stores the subject in clear, and a store error never
// reaches the response or the audit entry.
func TestErasePreviewAndErrorsNamedSafely(t *testing.T) {
	dir := t.TempDir()
	e := fileEnv(t, dir, func(c *Config) { c.Store = failingHosts{NewMemStore()} })
	b, _ := json.Marshal(EraseRequest{User: dev.ID, Reason: "DSR-1", DryRun: true})
	if w := e.as(admin, "POST", "/api/v1/users/erase", string(b)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := erase2(t, e, admin2, e, admin, eraseBody(dev.ID, "DSR-1"))
	if w.Code != 500 || strings.Contains(w.Body.String(), "hunter2") || !strings.Contains(w.Body.String(), errStoreFailed) {
		t.Fatalf("store error in the response: %d %s", w.Code, w.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, auditActive))
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), dev.ID) {
		t.Fatalf("audit log holds the store error or the subject: %s", raw)
	}
}
