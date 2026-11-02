package server

// Round-4 regression tests: what the server can refuse on its own, and what
// only an external anchor catches (ADR-0041 "What signatures prove").

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

func pubOf(k bundle.KeySigner) bundle.PublicKeyVerifier {
	return k.Verifier().(bundle.PublicKeyVerifier)
}

// R4-A: the signing record and the signed tail deleted, history forged with
// a "legacy" unsigned vouch, then a restart: the server does not write a new
// marker over the non-empty log without --audit-signing-enable, and offline
// verification with the key fails.
func TestRecordDeleteResignRefused(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	for i := range 4 {
		e.s.Audit(ctx, "alice@acme.example", "policy.change", "x"+strconv.Itoa(i), map[string]string{"user": "alice@acme.example"})
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.s.Audit(ctx, "mallory@acme.example", "experiment.kill", "prod", nil) // the evidence
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	es := logEntries(t, dir)
	kept := append([]AuditEntry(nil), es[:sinceOf(t, es)-1]...)
	x := cloneEntry(kept[0])
	x.Redacted, x.Actor, x.Target = true, "erased-zzz", "nothing"
	kept[0] = x
	l := kept[len(kept)-1]
	kept = append(kept, ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: systemActor, Action: actionErase,
		Details: map[string]string{"subject": "erased-zzz", "redacted": "1:" + x.redactionDigest()}}, l.Seq, l.Hash))
	writeEntries(t, dir, kept)
	if err := os.Remove(filepath.Join(dir, kindAuditSigning+".json")); err != nil {
		t.Fatal(err)
	}

	e2 := fileEnv(t, dir, func(c *Config) { c.AuditSigner, c.auditSigningEnableAny = k, false })
	e2.s.Audit(ctx, "carol@acme.example", "policy.change", "y", nil)
	before := e2.s.signRefused.Load()
	if ok, err := e2.s.Checkpoint(ctx); ok || !errors.Is(err, errSigningNotEnabled) {
		t.Fatalf("a restarted server re-signed a non-empty unsigned log: %v %v", ok, err)
	}
	if e2.s.signRefused.Load() == before {
		t.Fatal("refusal not counted")
	}
	_ = e2.s.Close()
	if res, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); res.Error == "" && res.Checkpoints > 0 {
		t.Fatalf("offline verification with the key passes: %+v", res)
	}
}

// R4-A (2): a long-lived replica keeps since in memory and refuses a
// signing record rewritten to another since.
func TestSigningRecordMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.s.enableAny = false // only the first start enables
	if err := e.s.auditLog.writeSigningRecord(signingRecord{Since: 99, Log: "00000000000000000000000000000000"}); err != nil {
		t.Fatal(err)
	}
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if _, err := e.s.Checkpoint(ctx); !errors.Is(err, errChainUnverified) {
		t.Fatalf("signed despite a rewritten signing record: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, kindAuditSigning+".json")) // record gone: memory still holds since
	if _, err := e.s.verifiedChain("t"); err == nil {
		t.Fatal("a signed chain without its signing record verified")
	}
}

// R4-B: a leaked previous key rewrites the tail after the rotation: the
// server, whose record says the current key has signed, refuses, and offline
// verification with both keys requires the newest checkpoint by the first.
func TestLeakedPreviousKeyRefused(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := testSigner(t), testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k1 })
	e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "prod", map[string]string{"user": "bob@acme.example"})
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	nK1 := len(logEntries(t, dir))
	mut2 := func(c *Config) { c.AuditSigner, c.AuditPreviousKeys = k2, []bundle.PublicKeyVerifier{pubOf(k1)} }
	e = fileEnv(t, dir, mut2)
	e.s.Audit(ctx, "mallory@acme.example", "experiment.kill", "prod2", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	es := logEntries(t, dir)
	kept := append([]AuditEntry(nil), es[:nK1]...)
	x := cloneEntry(kept[0])
	x.Redacted, x.Actor, x.Target, x.Details = true, "erased-zzz", "nothing", map[string]string{"user": "erased-zzz"}
	kept[0] = x
	list, since, log := "1:"+x.redactionDigest(), strconv.FormatUint(sinceOf(t, es), 10), logOf(t, es)
	sig, err := k1.Sign(ctx, eraseMsg(log, since, "erased-zzz", list))
	if err != nil {
		t.Fatal(err)
	}
	l := kept[len(kept)-1]
	kept = append(kept, ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: "admin@acme.example", Action: actionErase,
		Details: map[string]string{"subject": "erased-zzz", "redacted": list, "since": since, "log": log, "alg": k1.Type(), "sig": base64.StdEncoding.EncodeToString(sig)}}, l.Seq, l.Hash))
	writeEntries(t, dir, kept)

	e3 := fileEnv(t, dir, mut2)
	e3.s.Audit(ctx, "carol@acme.example", "policy.change", "y", nil)
	if ok, err := e3.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("the current key signed over a tail rewritten by the previous key: %v %v", ok, err)
	}
	_ = e3.s.Close()
	ring := bundle.Keyring{pubOf(k2), pubOf(k1)}
	if res, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: ring, RequireCurrentKey: true}); res.Error == "" {
		t.Fatalf("offline verification with both keys passes: %+v", res)
	}
}

// R4-C: an emptied audit table, or rows deleted from its end, no longer
// match the head row.
func TestPostgresHeadRowCatchesDeletion(t *testing.T) {
	db, schema := pgtest.OpenTest(t)
	k := testSigner(t)
	e := signedPGEnv(t, db, k, nil)
	ctx := context.Background()
	for range 3 {
		e.s.Audit(ctx, "a@acme.example", "policy.change", "x", nil)
	}
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.s.Audit(ctx, "a@acme.example", "policy.change", "tail", nil)
	raw, _ := sql.Open("pgx", pgtest.URL(schema))
	defer func() { _ = raw.Close() }()
	for _, q := range []string{`DELETE FROM halo_audit WHERE seq = (SELECT max(seq) FROM halo_audit)`, `DELETE FROM halo_audit`} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
		if r, _ := VerifyAuditBackend(ctx, e.s.cfg.Backend, AuditVerifyOptions{Verifier: k.Verifier()}); r.Error == "" {
			t.Fatalf("%s: verifies: %+v", q, r)
		}
	}
}
