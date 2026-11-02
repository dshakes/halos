package server

// Round-3 regression tests (signing marker and since, ADR-0041) and the
// tampering invariant: every storage tampering fails signed verification.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"math/rand/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// signedPGEnv is one replica on Postgres with an audit key.
func signedPGEnv(t *testing.T, db *pgstore.DB, k bundle.KeySigner, mutate func(*Config)) *env {
	t.Helper()
	b := NewPGBackend(db)
	kills, err := controller.NewKillStore(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *Config) {
		c.Backend, c.KillStore, c.Store, c.AuditSigner = b, kills, NewPGStore(db), k
		c.AuditSigningEnable = true // tests enable signing over logs that already hold entries; the round-4 tests turn it off
		if mutate != nil {
			mutate(c)
		}
	})
	*e.now = time.Now().UTC()
	return e
}

// plantUnsigned returns entries x (rewritten as a forged redaction), an
// unsigned subject.erase vouching for it and an unsigned audit.retention
// cutting everything before it: the round-3 forgery.
func plantUnsigned(x AuditEntry) (xr, vouch, cut AuditEntry) {
	xr = x
	xr.Redacted, xr.Actor, xr.Target, xr.Details = true, "erased-zzz", "something-else-entirely", map[string]string{"user": "erased-zzz"}
	now := time.Now().UTC()
	vouch = AuditEntry{Time: now, Actor: systemActor, Action: actionErase,
		Details: map[string]string{"subject": "erased-zzz", "redacted": strconv.FormatUint(x.Seq, 10) + ":" + xr.redactionDigest()}}
	cut = AuditEntry{Time: now, Actor: systemActor, Action: actionRetention, Details: map[string]string{
		"through": strconv.FormatUint(x.Seq-1, 10), "throughHash": x.Prev, "cutoff": now.Add(-31 * 24 * time.Hour).Format(time.RFC3339)}}
	return xr, vouch, cut
}

// H1 (file): unsigned vouches planted after signing was enabled stay
// forgeries even once the prefix holding every signed entry is deleted: the
// server refuses to sign over them, offline verification with the key fails,
// and a restarted server (its signing record) refuses too.
func TestUnsignedVouchAfterPrefixCut(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	ctx := context.Background()
	mut := func(c *Config) { c.AuditSigner = k }
	e := fileEnv(t, dir, mut)
	for i := range 5 {
		e.s.Audit(ctx, "alice@acme.example", "policy.change", "x"+strconv.Itoa(i), nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "exp-critical", map[string]string{"user": "bob@acme.example"})
	_ = e.s.Close()
	es := logEntries(t, dir)
	x := es[len(es)-1]
	xr, v, r := plantUnsigned(x)
	v = ChainAuditEntry(v, x.Seq, x.Hash)
	r = ChainAuditEntry(r, v.Seq, v.Hash)
	writeEntries(t, dir, append(es, v, r))

	e2 := fileEnv(t, dir, mut)
	e2.s.Audit(ctx, "carol@acme.example", "policy.change", "y", nil)
	if _, err := e2.s.Checkpoint(ctx); !errors.Is(err, errChainUnverified) {
		t.Fatalf("server signed over planted unsigned vouches: %v", err)
	}
	_ = e2.s.Close()
	var kept []AuditEntry
	for _, en := range logEntries(t, dir) {
		switch {
		case en.Seq < x.Seq:
		case en.Seq == x.Seq:
			kept = append(kept, xr)
		default:
			kept = append(kept, en)
		}
	}
	writeEntries(t, dir, kept)
	if res, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); res.Error == "" {
		t.Fatalf("history deleted and seq %d rewritten verifies with the key: %+v", x.Seq, res)
	}
	e3 := fileEnv(t, dir, mut)
	e3.s.Audit(ctx, "dave@acme.example", "policy.change", "z", nil)
	if ok, err := e3.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("restarted server signed over a chain that lost every signed entry: %v %v", ok, err)
	}
	if a := auditOf(t, e3); a.Verified {
		t.Fatal("GET /api/v1/audit reports the chain verified")
	}
}

// H1 (Postgres, live): the same through the head-row protocol.
func TestUnsignedVouchPostgresLive(t *testing.T) {
	db, schema := pgtest.OpenTest(t)
	k := testSigner(t)
	e := signedPGEnv(t, db, k, nil)
	b := e.s.cfg.Backend.(*PGBackend)
	ctx := context.Background()
	for range 5 {
		e.s.Audit(ctx, "alice@acme.example", "policy.change", "x", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "exp-critical", map[string]string{"user": "bob@acme.example"})
	var x AuditEntry
	_ = b.EachAuditDesc(ctx, func(_ []byte, en AuditEntry) bool { x = en; return false })
	xr, v, r := plantUnsigned(x)
	for _, en := range []AuditEntry{v, r} {
		if err := b.AppendAudit(ctx, en); err != nil {
			t.Fatal(err)
		}
	}
	e.s.Audit(ctx, "carol@acme.example", "policy.change", "y", nil)
	if _, err := e.s.Checkpoint(ctx); !errors.Is(err, errChainUnverified) {
		t.Fatalf("server signed over planted unsigned vouches: %v", err)
	}
	raw, err := sql.Open("pgx", pgtest.URL(schema))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	body, _ := json.Marshal(xr)
	if _, err := raw.Exec(`DELETE FROM halo_audit WHERE seq < $1`, int64(x.Seq)); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE halo_audit SET entry = $1 WHERE seq = $2`, body, int64(x.Seq)); err != nil {
		t.Fatal(err)
	}
	if r, _ := VerifyAuditBackend(ctx, b, AuditVerifyOptions{Verifier: k.Verifier()}); r.Error == "" {
		t.Fatalf("verifies with the key: %+v", r)
	}
	e.s.auditLog.dropCache()
	if _, err := e.s.verifiedChain("after cache drop"); err == nil {
		t.Fatal("live server re-verified the tampered chain")
	}
	fresh := signedPGEnv(t, db, k, nil) // a new replica: no memory, only the signing record
	if ok, err := fresh.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("a fresh replica signed over it: %v %v", ok, err)
	}
}

// M1: retention of an idle log keeps the newest checkpoint, so the process
// keeps signing (checkpoints, cuts) and the chain keeps verifying.
func TestIdleRetentionKeepsSigning(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	k := testSigner(t)
	e := signedPGEnv(t, db, k, func(c *Config) { c.Retention = Retention{Audit: MinAuditRetention} })
	b := e.s.cfg.Backend.(*PGBackend)
	start := *e.now
	ctx := context.Background()
	for range 5 {
		e.s.Audit(ctx, "alice@acme.example", "policy.change", "x", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	*e.now = start.Add(40 * 24 * time.Hour)
	if out, err := e.s.Sweep(ctx); err != nil || out["auditEntries"] == 0 {
		t.Fatalf("sweep: %v %v", out, err)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("checkpoint after an idle cut: %v %v", ok, err)
	}
	*e.now = start.Add(80 * 24 * time.Hour)
	if _, err := e.s.Sweep(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if r, _ := VerifyAuditBackend(ctx, b, AuditVerifyOptions{Verifier: k.Verifier()}); r.Error != "" || r.Checkpoints == 0 {
		t.Fatalf("offline verify: %+v", r)
	}
}

// M2: a replica whose cached chain predates another replica's redactions
// re-verifies once instead of refusing an erasure.
func TestStaleCacheReverifiesOnce(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	a, b := pgReplicas(t, db)
	ctx := context.Background()
	a.s.Audit(ctx, "bob@acme.example", "request.approve", "r1", map[string]string{"user": "carol@acme.example"})
	a.s.Audit(ctx, "alice@acme.example", "policy.change", "x", nil)
	if _, err := b.s.verifiedChain("warm"); err != nil {
		t.Fatal(err)
	}
	if w := erase2(t, a, admin2, a, admin3, eraseBody("bob@acme.example", "DSR-1")); w.Code != 200 {
		t.Fatalf("erase bob on a: %d %s", w.Code, w.Body.String())
	}
	if w := erase2(t, b, admin2, b, admin3, eraseBody("carol@acme.example", "DSR-2")); w.Code != 200 {
		t.Fatalf("erase carol on b (stale cache): %d %s", w.Code, w.Body.String())
	}
	if res := decode[AuditResponse](t, b.as(admin, "GET", "/api/v1/audit?limit=500", "")); !res.Verified {
		t.Fatalf("chain after both erasures: %s", res.VerifyError)
	}
}

// A tampered old row inside the cached verified prefix is never redacted:
// the erasure re-verifies from scratch and refuses.
func TestCachedPrefixTamperRefusesErasure(t *testing.T) {
	db, schema := pgtest.OpenTest(t)
	k := testSigner(t)
	e := signedPGEnv(t, db, k, nil)
	ctx := context.Background()
	e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "exp", map[string]string{"user": "bob@acme.example"})
	for range 3 {
		e.s.Audit(ctx, "alice@acme.example", "policy.change", "x", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	raw, _ := sql.Open("pgx", pgtest.URL(schema))
	defer func() { _ = raw.Close() }()
	var x AuditEntry
	_ = e.s.cfg.Backend.EachAudit(ctx, 1, func(_ []byte, en AuditEntry) bool { x = en; return false })
	x.Target = "exp-innocent"
	body, _ := json.Marshal(x)
	if _, err := raw.Exec(`UPDATE halo_audit SET entry = $1 WHERE seq = 1`, body); err != nil {
		t.Fatal(err)
	}
	w := erase2(t, e, admin2, e, admin3, eraseBody("bob@acme.example", "DSR-3"))
	if rep := decode[EraseReport](t, w); w.Code != 500 || rep.Errors["auditEntries"] == "" {
		t.Fatalf("erasure over a tampered cached row: %d %s", w.Code, w.Body.String())
	}
}

// L1: the shared chain is read a page at a time, each page under its own
// timeout, so a log of any size can be verified.
func TestEachAuditPaged(t *testing.T) {
	b := newMemShared()
	ctx := context.Background()
	n := 2*auditPage + 7
	for range n {
		_ = b.AppendAudit(ctx, AuditEntry{Time: time.Now().UTC(), Actor: "a", Action: "x"})
	}
	cb := &countingAudit{memShared: b}
	seen := 0
	if _, err := eachAuditPaged(ctx, cb, 1, func(_ []byte, e AuditEntry) bool { seen++; return true }); err != nil {
		t.Fatal(err)
	}
	if seen != n || cb.calls != 3 {
		t.Fatalf("read %d of %d entries in %d pages", seen, n, cb.calls)
	}
	if r, err := VerifyAuditBackend(ctx, cb, AuditVerifyOptions{}); err != nil || r.Error != "" || r.Entries != uint64(n) {
		t.Fatalf("verify: %+v %v", r, err)
	}
}

type countingAudit struct {
	*memShared
	calls int
}

func (c *countingAudit) EachAudit(ctx context.Context, from uint64, fn func([]byte, AuditEntry) bool) error {
	c.calls++
	return c.memShared.EachAudit(ctx, from, fn)
}

// L2: a redaction swaps a row only if it still holds the body read.
func TestRedactCompareAndSwap(t *testing.T) {
	check := func(t *testing.T, e *env) {
		t.Helper()
		ctx := context.Background()
		e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "exp", nil)
		c, err := e.s.verifiedChain("t")
		if err != nil {
			t.Fatal(err)
		}
		red, err := e.s.auditLog.redactions(c, newSubjectMatcher("bob@acme.example"), "erased-1")
		if err != nil || len(red) != 1 {
			t.Fatalf("redactions: %v %v", red, err)
		}
		for seq, r := range red { // another erasure got there first
			r.old = append([]byte(nil), r.old...)
			r.old[len(r.old)-2] ^= 1
			red[seq] = r
		}
		if err := e.s.auditLog.redact(red); err == nil {
			t.Fatal("redacted a row that changed since it was read")
		}
	}
	t.Run("file", func(t *testing.T) { check(t, fileEnv(t, t.TempDir(), nil)) })
	t.Run("postgres", func(t *testing.T) {
		db, _ := pgtest.OpenTest(t)
		check(t, signedPGEnv(t, db, testSigner(t), nil))
	})
}

// L3: once the current key has signed, an entry signed by a previous key is
// refused (a leaked old key cannot sign new history).
func TestPreviousKeyBoundedByCurrent(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := testSigner(t), testSigner(t)
	ctx := context.Background()
	pub := func(k bundle.KeySigner) bundle.PublicKeyVerifier { return k.Verifier().(bundle.PublicKeyVerifier) }
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k1 })
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	e = fileEnv(t, dir, func(c *Config) { c.AuditSigner, c.AuditPreviousKeys = k2, []bundle.PublicKeyVerifier{pub(k1)} })
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	ring := bundle.Keyring{pub(k2), pub(k1)}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: ring}); r.Error != "" {
		t.Fatalf("rotation: %+v", r)
	}
	// The old key signs again (leaked): a checkpoint signed by k1 after k2's.
	e = fileEnv(t, dir, func(c *Config) { c.AuditSigner, c.AuditPreviousKeys = k1, []bundle.PublicKeyVerifier{pub(k2)} })
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if _, err := e.s.Checkpoint(ctx); !errors.Is(err, errChainUnverified) { // k1 as current, k2 previous: k2 signed after k1 did
		t.Fatalf("server with the old key as current: %v", err)
	}
	_ = e.s.Close()
	es := logEntries(t, dir)
	l := es[len(es)-1]
	cp, err := checkpointSigner(k1)(ctx, logOf(t, es), sinceOf(t, es), l.Seq, l.Hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeEntries(t, dir, append(es, ChainAuditEntry(cp, l.Seq, l.Hash)))
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: ring}); r.Error == "" {
		t.Fatalf("an entry signed by the previous key after the current key took over verified: %+v", r)
	}
}

func logOf(t *testing.T, es []AuditEntry) string {
	t.Helper()
	for _, e := range es {
		if e.Action == actionSigningEnabled {
			return e.Details["log"]
		}
	}
	t.Fatal("no audit.signing.enabled entry")
	return ""
}

func sinceOf(t *testing.T, es []AuditEntry) uint64 {
	t.Helper()
	for _, e := range es {
		if e.Action == actionSigningEnabled {
			return e.Seq
		}
	}
	t.Fatal("no audit.signing.enabled entry")
	return 0
}

// ---- the tampering invariant ----

// tamperings each change a legitimately built, signed chain in storage the
// way someone with write access could. Every one must fail verification with
// the key and the SIEM's newest checkpoint as anchor. anchorIdx is the index
// of the newest checkpoint.
var tamperings = []struct {
	name string
	f    func(es []AuditEntry, anchorIdx int, r *rand.Rand) []AuditEntry
}{
	{"edit a body", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		i := r.IntN(a)
		es[i] = cloneEntry(es[i])
		es[i].Target += "-edited"
		return es
	}},
	{"back-date a body", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		i := r.IntN(len(es) - 1)
		es[i] = cloneEntry(es[i])
		es[i].Time = es[i].Time.Add(-400 * 24 * time.Hour)
		return es
	}},
	{"delete the prefix", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry { return es[1+r.IntN(min(3, a)):] }},
	{"delete a middle entry", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		i := 1 + r.IntN(len(es)-2)
		return append(es[:i:i], es[i+1:]...)
	}},
	{"truncate the tail", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry { return es[:a-r.IntN(min(3, a))] }},
	{"insert an unsigned vouch", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		i := r.IntN(a)
		x := cloneEntry(es[i])
		x.Redacted, x.Target = true, "forged"
		es[i] = x
		l := es[len(es)-1]
		return append(es, ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: systemActor, Action: actionErase,
			Details: map[string]string{"subject": "erased-f", "redacted": strconv.FormatUint(x.Seq, 10) + ":" + x.redactionDigest()}}, l.Seq, l.Hash))
	}},
	{"insert an unsigned cut", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		j := 1 + r.IntN(a)
		cut := es[j-1]
		kept := es[j:]
		l := kept[len(kept)-1]
		old := time.Now().UTC().Add(-400 * 24 * time.Hour)
		return append(kept, ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: systemActor, Action: actionRetention,
			Details: map[string]string{"through": strconv.FormatUint(cut.Seq, 10), "throughHash": cut.Hash, "cutoff": old.Format(time.RFC3339)}}, l.Seq, l.Hash))
	}},
	{"recompute the chain", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		i := r.IntN(a)
		es[i] = cloneEntry(es[i])
		es[i].Actor = "mallory@acme.example"
		return rechainFrom(es, i)
	}},
	// Forgeries of signed entries, each re-chained so only the signature (or
	// what it binds) can catch it.
	{"patch a checkpoint's since", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		es[a] = cloneEntry(es[a])
		n, _ := strconv.ParseUint(es[a].Details["since"], 10, 64)
		es[a].Details["since"] = strconv.FormatUint(n+1, 10)
		return rechainFrom(es, a)
	}},
	{"corrupt a checkpoint signature", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		es[a] = cloneEntry(es[a])
		sig := []byte(es[a].Details["sig"])
		sig[0] ^= 'A' ^ 'B'
		es[a].Details["sig"] = string(sig)
		return rechainFrom(es, a)
	}},
	{"relocate a checkpoint", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		cp, l := cloneEntry(es[a]), es[len(es)-1]
		cp.Details["seq"], cp.Details["head"] = strconv.FormatUint(l.Seq, 10), l.Hash
		return append(es, ChainAuditEntry(cp, l.Seq, l.Hash))
	}},
	{"a checkpoint from another log", func(es []AuditEntry, a int, r *rand.Rand) []AuditEntry {
		es[a] = cloneEntry(es[a])
		es[a].Details["log"] = strings.Repeat("ab", 16)
		return rechainFrom(es, a)
	}},
}

// rechainFrom recomputes every hash from es[i] on, as a storage writer can.
func rechainFrom(es []AuditEntry, i int) []AuditEntry {
	seq, head := es[i].Seq-1, es[i].Prev
	for j := i; j < len(es); j++ {
		es[j] = ChainAuditEntry(es[j], seq, head)
		seq, head = es[j].Seq, es[j].Hash
	}
	return es
}

func cloneEntry(e AuditEntry) AuditEntry {
	e.Details = maps.Clone(e.Details)
	return e
}

// buildSigned runs a random sequence of legitimate operations (appends,
// checkpoints, erasures, retention cuts) and ends with a checkpoint.
func buildSigned(t *testing.T, e *env, seed uint64) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	ctx := context.Background()
	subjects := []string{"ann@acme.example", "ben@acme.example", "cat@acme.example"}
	for range 30 {
		subj := subjects[r.IntN(len(subjects))]
		switch op := r.IntN(10); {
		case op < 6:
			e.s.Audit(ctx, subj, "policy.change", "ring-"+strconv.Itoa(r.IntN(5)), map[string]string{"user": subjects[r.IntN(len(subjects))]})
		case op < 8:
			if _, err := e.s.Checkpoint(ctx); err != nil {
				t.Fatalf("seed %d: checkpoint: %v", seed, err)
			}
		case op < 9:
			rep := e.s.erase(ctx, newSubjectMatcher(subj), EraseRequest{User: subj, Reason: "DSR"}, admin.ID, admin2.ID)
			if len(rep.Errors) > 0 {
				t.Fatalf("seed %d: erase: %v", seed, rep.Errors)
			}
		default:
			*e.now = e.now.Add(40 * 24 * time.Hour)
			if _, err := e.s.Sweep(ctx); err != nil {
				t.Fatalf("seed %d: sweep: %v", seed, err)
			}
		}
	}
	e.s.Audit(ctx, "zed@acme.example", "policy.change", "last", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("seed %d: final checkpoint: %v %v", seed, ok, err)
	}
}

func newestCheckpoint(t *testing.T, es []AuditEntry) int {
	t.Helper()
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Action == actionCheckpoint {
			return i
		}
	}
	t.Fatal("no checkpoint")
	return 0
}

func TestTamperingInvariantFile(t *testing.T) {
	for seed := range uint64(3) {
		k := testSigner(t)
		dir := t.TempDir()
		e := fileEnv(t, dir, func(c *Config) {
			c.AuditSigner, c.Audit.Rotation, c.Retention = k, AuditRotation{MaxBytes: 4096}, Retention{Audit: MinAuditRetention}
		})
		buildSigned(t, e, seed)
		_ = e.s.Close()
		var es []AuditEntry
		segs, _ := listAuditSegs(dir)
		for _, p := range append(segPaths(segs), filepath.Join(dir, auditActive)) {
			_ = eachAuditFile(p, func(_ []byte, x AuditEntry) bool { es = append(es, x); return true })
		}
		a := newestCheckpoint(t, es)
		anchor := es[a]
		opts := AuditVerifyOptions{Verifier: k.Verifier(), Anchor: &anchor}
		verify := func(es []AuditEntry) AuditVerifyResult {
			d := t.TempDir()
			writeEntries(t, d, es)
			r, err := VerifyAuditDir(d, opts)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		if r := verify(es); r.Error != "" {
			t.Fatalf("seed %d: the legitimate chain does not verify: %+v", seed, r)
		}
		checkTamperings(t, seed, es, a, k, func(o AuditVerifyOptions) { opts = o }, verify)
	}
}

// checkTamperings applies every tampering, verifying with the key and the
// anchor, then with the key alone; key-only, everything but the
// anchor-only tamperings (tail truncation) must still fail.
func checkTamperings(t *testing.T, seed uint64, es []AuditEntry, a int, k bundle.KeySigner, setOpts func(AuditVerifyOptions), verify func([]AuditEntry) AuditVerifyResult) {
	t.Helper()
	anchor := es[a]
	for _, mode := range []string{"anchored", "key-only"} {
		o := AuditVerifyOptions{Verifier: k.Verifier()}
		if mode == "anchored" {
			o.Anchor = &anchor
		}
		setOpts(o)
		for _, tm := range tamperings {
			if mode == "key-only" && tm.name == "truncate the tail" { // deletion of the tail: only an anchor catches it (ADR-0041)
				continue
			}
			r := rand.New(rand.NewPCG(seed, 7))
			if res := verify(tm.f(slicesClone(es), a, r)); res.Error == "" {
				t.Errorf("seed %d %s: %s: verifies", seed, mode, tm.name)
			}
		}
	}
}

func TestTamperingInvariantPostgres(t *testing.T) {
	scratchDB, scratch := pgtest.OpenTest(t)
	raw, err := sql.Open("pgx", pgtest.URL(scratch))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	sb := NewPGBackend(scratchDB)
	for seed := range uint64(3) {
		db, _ := pgtest.OpenTest(t)
		k := testSigner(t)
		e := signedPGEnv(t, db, k, func(c *Config) { c.Retention = Retention{Audit: MinAuditRetention} })
		buildSigned(t, e, seed)
		var es []AuditEntry
		if _, err := eachAuditPaged(context.Background(), e.s.cfg.Backend, 1, func(_ []byte, x AuditEntry) bool { es = append(es, x); return true }); err != nil {
			t.Fatal(err)
		}
		a := newestCheckpoint(t, es)
		anchor := es[a]
		opts := AuditVerifyOptions{Verifier: k.Verifier(), Anchor: &anchor}
		verify := func(es []AuditEntry) AuditVerifyResult {
			if _, err := raw.Exec(`DELETE FROM halo_audit`); err != nil {
				t.Fatal(err)
			}
			for _, x := range es {
				b, _ := json.Marshal(x)
				if _, err := raw.Exec(`INSERT INTO halo_audit (seq, hash, prev, entry, at) VALUES ($1, $2, $3, $4, $5)`, int64(x.Seq), x.Hash, x.Prev, b, x.Time); err != nil { //nolint:gosec // test seqs are small
					t.Fatal(err)
				}
			}
			if n := len(es); n > 0 { // the head row is writable too: the tamperer keeps it consistent
				if _, err := raw.Exec(`UPDATE halo_audit_head SET seq = $1, hash = $2`, int64(es[n-1].Seq), es[n-1].Hash); err != nil { //nolint:gosec // test seqs are small
					t.Fatal(err)
				}
			}
			r, err := VerifyAuditBackend(context.Background(), sb, opts)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		if r := verify(es); r.Error != "" {
			t.Fatalf("seed %d: the legitimate chain does not verify: %+v", seed, r)
		}
		checkTamperings(t, seed, es, a, k, func(o AuditVerifyOptions) { opts = o }, verify)
	}
}

func slicesClone(es []AuditEntry) []AuditEntry { return append([]AuditEntry(nil), es...) }
