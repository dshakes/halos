package server

// Round-5 regression tests: the one-shot enable, the signing record at
// rotation time, a signed log without its key, log replacement, rotation
// on an idle deployment and restoring a backup.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

func noEnable(c *Config) { c.auditSigningEnableAny = false }

// L4 (P1): the record deleted, signed entries kept, restart without the
// enable: refused.
func TestRecordDeletedRestartRefused(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	_ = os.Remove(filepath.Join(dir, kindAuditSigning+".json"))
	e2 := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k; noEnable(c) })
	e2.s.Audit(ctx, "a@acme.example", "x.y", "2", nil)
	if ok, err := e2.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("signed with the record missing and no enable: %v %v", ok, err)
	}
}

// L1 (P2, P3): the enable is consumed by its first use and must name the
// current head; a stale value is refused.
func TestSigningEnableIsOneShotAndHeadBound(t *testing.T) {
	ctx := context.Background()
	t.Run("consumed: a later record deletion is not healed", func(t *testing.T) {
		dir := t.TempDir()
		k := testSigner(t)
		e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
		e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
		if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
			t.Fatal(ok, err)
		}
		_ = os.Remove(filepath.Join(dir, kindAuditSigning+".json"))
		e.s.Audit(ctx, "a@acme.example", "x.y", "2", nil)
		if ok, err := e.s.Checkpoint(ctx); ok || err == nil {
			t.Fatalf("a record deleted at runtime was healed by a used enable: %v %v", ok, err)
		}
	})
	t.Run("head-bound", func(t *testing.T) {
		dir := t.TempDir()
		k := testSigner(t)
		for i := range 3 {
			if err := AppendAuditOffline(dir, "a@acme.example", "x.y", strconv.Itoa(i), nil, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		stale := fileEnv(t, dir, func(c *Config) { c.AuditSigner, c.AuditSigningEnableHead = k, 2; noEnable(c) })
		if ok, err := stale.s.Checkpoint(ctx); ok || err == nil {
			t.Fatalf("a stale enable value was honoured: %v %v", ok, err)
		}
		_ = stale.s.Close()
		e := fileEnv(t, dir, func(c *Config) { c.AuditSigner, c.AuditSigningEnableHead = k, 3; noEnable(c) })
		if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
			t.Fatalf("the current head's enable: %v %v", ok, err)
		}
		if e.s.enableHead != 0 {
			t.Fatal("the enable was not cleared after use")
		}
	})
}

// M1 (P7): a leaked previous key rewrites the tail after the current key
// signed; the rotation-time checkpoint consults the signing record too.
func TestRotationCheckpointChecksRecord(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := testSigner(t), testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k1 })
	e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "prod", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	nK1 := len(logEntries(t, dir))
	mut2 := func(c *Config) {
		c.AuditSigner, c.AuditPreviousKeys = k2, []bundle.PublicKeyVerifier{pubOf(k1)}
		noEnable(c)
	}
	e = fileEnv(t, dir, mut2)
	e.s.Audit(ctx, "mallory@acme.example", "experiment.kill", "evidence", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	es := logEntries(t, dir)
	kept := append([]AuditEntry(nil), es[:nK1]...)
	l := kept[len(kept)-1]
	kept = append(kept, ChainAuditEntry(AuditEntry{Time: time.Now().UTC(), Actor: "x", Action: "policy.change", Target: "innocent"}, l.Seq, l.Hash))
	l = kept[len(kept)-1]
	cp, err := checkpointSigner(k1)(ctx, logOf(t, es), sinceOf(t, es), l.Seq, l.Hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeEntries(t, dir, append(kept, ChainAuditEntry(cp, l.Seq, l.Hash)))

	e3 := fileEnv(t, dir, func(c *Config) { mut2(c); c.Audit.Rotation = AuditRotation{MaxBytes: 4096} })
	for i := range 40 {
		e3.s.Audit(ctx, "carol@acme.example", "policy.change", strconv.Itoa(i), nil)
	}
	_ = e3.s.Close()
	segs, _ := listAuditSegs(dir)
	if len(segs) == 0 {
		t.Fatal("fixture: no rotation")
	}
	var es2 []AuditEntry
	for _, p := range append(segPaths(segs), filepath.Join(dir, auditActive)) {
		_ = eachAuditFile(p, func(_ []byte, x AuditEntry) bool { es2 = append(es2, x); return true })
	}
	for _, x := range es2 {
		if x.Action == actionCheckpoint && x.Details["keyId"] == bundle.KeyID(k2.Verifier()) {
			t.Fatalf("the rotation checkpoint signed over a tail rewritten by the previous key: seq %d", x.Seq)
		}
	}
}

// M3 (P5): a signed log served without its key refuses erasure and
// retention cuts instead of writing unsigned vouches.
func TestSignedLogWithoutKeyRefusesVouching(t *testing.T) {
	dir := t.TempDir()
	k := testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	e.s.Audit(ctx, "ann@acme.example", "policy.change", "x", map[string]string{"user": "ann@acme.example"})
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	e2 := fileEnv(t, dir, func(c *Config) { noEnable(c); c.Retention = Retention{Audit: MinAuditRetention} })
	rep := e2.s.erase(ctx, newSubjectMatcher("ann@acme.example"), EraseRequest{User: "ann@acme.example", Reason: "DSR"}, admin.ID, admin2.ID)
	if rep.Errors["auditEntries"] == "" || len(rep.Erased) > 0 {
		t.Fatalf("erasure without the key: %+v", rep)
	}
	if _, err := e2.s.pruneAudit(ctx, time.Now()); !errors.Is(err, errSignedNoKey) {
		t.Fatalf("retention cut without the key: %v", err)
	}
	_ = e2.s.Close()
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier()}); r.Error != "" {
		t.Fatalf("signed verification broken: %+v", r)
	}
}

// L4 (P6): a live process refuses a log swapped for another deployment's
// signed by the same key with the same since (memory holds the log id).
func TestLiveLogSwapRefused(t *testing.T) {
	k := testSigner(t)
	ctx := context.Background()
	other := t.TempDir()
	eo := fileEnv(t, other, func(c *Config) { c.AuditSigner = k })
	eo.s.Audit(ctx, "staging@acme.example", "x.y", "", nil)
	_, _ = eo.s.Checkpoint(ctx)
	_ = eo.s.Close()
	dir := t.TempDir()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	e.s.Audit(ctx, "prod@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	writeEntries(t, dir, logEntries(t, other))
	b, _ := os.ReadFile(filepath.Join(other, kindAuditSigning+".json"))
	_ = os.WriteFile(filepath.Join(dir, kindAuditSigning+".json"), b, 0o600)
	e.s.auditLog.dropCache()
	e.s.Audit(ctx, "a@acme.example", "x.y", "after", nil)
	if ok, err := e.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("a live process signed over a swapped log: %v %v", ok, err)
	}
}

// L4: memory since mismatch (record and chain both replaced with another since).
func TestMemorySinceMismatchRefused(t *testing.T) {
	k := testSigner(t)
	ctx := context.Background()
	other := t.TempDir()
	eo := fileEnv(t, other, func(c *Config) { c.AuditSigner = k })
	for i := range 3 {
		eo.s.Audit(ctx, "staging@acme.example", "x.y", strconv.Itoa(i), nil)
	}
	_, _ = eo.s.Checkpoint(ctx) // since 4
	_ = eo.s.Close()
	dir := t.TempDir()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	e.s.Audit(ctx, "prod@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil { // since 2
		t.Fatal(ok, err)
	}
	writeEntries(t, dir, logEntries(t, other))
	b, _ := os.ReadFile(filepath.Join(other, kindAuditSigning+".json"))
	_ = os.WriteFile(filepath.Join(dir, kindAuditSigning+".json"), b, 0o600)
	e.s.auditLog.dropCache()
	e.s.vmuSetKnownLog("") // isolate the since check from the log-id check
	if _, err := e.s.verifiedChain("t"); err == nil {
		t.Fatal("a chain with another since verified in a process that saw since 2")
	}
}

func (s *Server) vmuSetKnownLog(v string) {
	s.auditLog.vmu.Lock()
	s.auditLog.knownLog = v
	s.auditLog.vmu.Unlock()
}

// L4: TestLeakedPreviousKeyRefused and the fresh replica of
// TestUnsignedVouchPostgresLive with the enable off.
func TestLeakedPreviousKeyRefusedEnableOff(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := testSigner(t), testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k1 })
	e.s.Audit(ctx, "bob@acme.example", "experiment.kill", "prod", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	nK1 := len(logEntries(t, dir))
	mut2 := func(c *Config) {
		c.AuditSigner, c.AuditPreviousKeys = k2, []bundle.PublicKeyVerifier{pubOf(k1)}
		noEnable(c)
	}
	e = fileEnv(t, dir, mut2)
	e.s.Audit(ctx, "mallory@acme.example", "experiment.kill", "evidence", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	es := logEntries(t, dir)
	kept := append([]AuditEntry(nil), es[:nK1]...)
	l := kept[len(kept)-1]
	cp, _ := checkpointSigner(k1)(ctx, logOf(t, es), sinceOf(t, es), l.Seq, l.Hash, time.Now())
	writeEntries(t, dir, append(kept, ChainAuditEntry(cp, l.Seq, l.Hash)))
	e3 := fileEnv(t, dir, mut2)
	e3.s.Audit(ctx, "carol@acme.example", "policy.change", "y", nil)
	if ok, err := e3.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("enable off: the current key signed over the previous key's tail: %v %v", ok, err)
	}
}

func TestFreshReplicaEnableOffPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	k := testSigner(t)
	e := signedPGEnv(t, db, k, nil)
	ctx := context.Background()
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if err := e.s.cfg.Backend.(*PGBackend).PutDoc(ctx, kindAuditSigning, "since", []byte(`{}`)); err != nil { // record wiped
		t.Fatal(err)
	}
	fresh := signedPGEnv(t, db, k, noEnable)
	fresh.s.Audit(ctx, "a@acme.example", "x.y", "2", nil)
	if ok, err := fresh.s.Checkpoint(ctx); ok || !errors.Is(err, errChainUnverified) {
		t.Fatalf("a fresh replica with the enable off re-recorded a wiped record: %v %v", ok, err)
	}
}

// L5: after a rotation on an idle deployment the new key signs a checkpoint
// at once (Checkpoint does not skip a head that is a previous key's
// checkpoint), so verification with the new key first passes.
func TestRotationIdleCheckpointsNewKey(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := testSigner(t), testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k1 })
	e.s.Audit(ctx, "a@acme.example", "x.y", "", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	e2 := fileEnv(t, dir, func(c *Config) {
		c.AuditSigner, c.AuditPreviousKeys = k2, []bundle.PublicKeyVerifier{pubOf(k1)}
		noEnable(c)
	})
	if ok, err := e2.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("no new-key checkpoint on an idle deployment: %v %v", ok, err)
	}
	_ = e2.s.Close()
	ring := bundle.Keyring{pubOf(k2), pubOf(k1)}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: ring, RequireCurrentKey: true}); r.Error != "" {
		t.Fatalf("verify with the new key first: %+v", r)
	}
}

// L3: restoring a backup of a signed log. The record restored with it keeps
// the server signing; the SIEM copy holds entries past the backup that the
// restored log reuses, so --compare-export must be re-baselined to the
// backup's head.
func TestRestoreBackupRebaseline(t *testing.T) {
	dir, backup := t.TempDir(), t.TempDir()
	k := testSigner(t)
	ctx := context.Background()
	e := fileEnv(t, dir, func(c *Config) { c.AuditSigner = k })
	e.s.Audit(ctx, "a@acme.example", "x.y", "1", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	for _, f := range []string{auditActive, kindAuditSigning + ".json"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		_ = os.WriteFile(filepath.Join(backup, f), b, 0o600)
	}
	backupHead := logEntries(t, dir)[len(logEntries(t, dir))-1].Seq
	e = fileEnv(t, dir, func(c *Config) { c.AuditSigner = k; noEnable(c) })
	e.s.Audit(ctx, "a@acme.example", "x.y", "after backup", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = e.s.Close()
	siem := filepath.Join(t.TempDir(), "siem.jsonl")
	b, _ := os.ReadFile(filepath.Join(dir, auditActive))
	_ = os.WriteFile(siem, b, 0o600)

	for _, f := range []string{auditActive, kindAuditSigning + ".json"} { // restore
		b, _ := os.ReadFile(filepath.Join(backup, f))
		if err := fsutil.WriteAtomic(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e = fileEnv(t, dir, func(c *Config) { c.AuditSigner = k; noEnable(c) })
	e.s.Audit(ctx, "a@acme.example", "x.y", "after restore", nil)
	if ok, err := e.s.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("restored log with its record: %v %v", ok, err)
	}
	_ = e.s.Close()
	full, err := LoadExport(siem)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier(), Export: full}); r.Error == "" {
		t.Fatal("the full SIEM copy matched a restored log that reused its seqs")
	}
	base := map[uint64]ExportedEntry{}
	for seq, x := range full {
		if seq <= backupHead {
			base[seq] = x
		}
	}
	if r, _ := VerifyAuditDir(dir, AuditVerifyOptions{Verifier: k.Verifier(), Export: base}); r.Error != "" {
		t.Fatalf("re-baselined to the backup's head: %+v", r)
	}
}
