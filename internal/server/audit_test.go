package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// all returns every entry as stored, across segments (tests only: production
// reads stream).
func (l *auditLog) all() ([]AuditEntry, error) {
	snap, err := l.snapshot()
	if err != nil {
		return nil, err
	}
	defer snap.close()
	var out []AuditEntry
	err = snap.from(0, func(_ []byte, e AuditEntry) bool { out = append(out, e); return true })
	return out, err
}

func appendN(t *testing.T, l *auditLog, from, n int, at func(i int) time.Time) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := l.append(AuditEntry{Time: at(i), Actor: "u", Action: "a", Target: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
}

func segFiles(t *testing.T, dir string) []string {
	t.Helper()
	segs, err := listAuditSegs(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range segs {
		out = append(out, filepath.Base(s.path))
	}
	return out
}

func TestAuditRotationChainsAcrossSegments(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	every := func(i int) time.Time { return base.Add(time.Duration(i) * time.Minute) }
	for _, c := range []struct {
		name     string
		rot      AuditRotation
		wantSegs int
	}{
		{"size", AuditRotation{MaxBytes: 700}, 4},        // ~230-byte entries: 3 per segment -> 3 rotated + active
		{"age", AuditRotation{MaxAgeSeconds: 3 * 60}, 3}, // 3 minutes per segment
		{"off", AuditRotation{}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			l, err := openAuditLog(dir)
			if err != nil {
				t.Fatal(err)
			}
			l.rot = c.rot
			appendN(t, l, 0, 10, every)
			_ = l.close()
			segs := segFiles(t, dir)
			if c.wantSegs > 0 && len(segs) < c.wantSegs-1 {
				t.Fatalf("rotated segments: %v", segs)
			}
			if c.wantSegs == 0 && len(segs) != 0 {
				t.Fatalf("rotation off but rotated: %v", segs)
			}
			// each segment's first entry links to the previous segment's last
			prevLast := ""
			for _, p := range append(segs, auditActive) {
				var first, last *AuditEntry
				if err := eachAuditFile(filepath.Join(dir, p), func(_ []byte, e AuditEntry) bool {
					if first == nil {
						first = &e
					}
					last = &e
					return true
				}); err != nil {
					t.Fatal(err)
				}
				if first == nil {
					t.Fatalf("segment %s is empty", p)
				}
				if first.Prev != prevLast || (p != auditActive && p != auditSegName(first.Seq)) {
					t.Fatalf("segment %s: first seq %d prev %q, want prev %q", p, first.Seq, first.Prev, prevLast)
				}
				prevLast = last.Hash
			}
			r, err := VerifyAuditDir(dir)
			if err != nil || r.Error != "" || r.Entries != 10 || r.Segments != len(segs)+1 || r.Head != prevLast {
				t.Fatalf("verify: %+v %v", r, err)
			}
			// restart continues the chain, still across segments
			l2, err := openAuditLog(dir)
			if err != nil {
				t.Fatal(err)
			}
			l2.rot = c.rot
			appendN(t, l2, 10, 5, every)
			all, err := l2.all()
			_ = l2.close()
			if err != nil || len(all) != 15 || VerifyAuditChain(all) != nil {
				t.Fatalf("after restart: %d entries, %v, %v", len(all), err, VerifyAuditChain(all))
			}
		})
	}
}

func TestAuditRotationCrashAfterRename(t *testing.T) {
	dir := t.TempDir()
	l, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 3, func(int) time.Time { return ksNow })
	_ = l.close()
	// what a crash between the rename and the new active's creation leaves
	if err := os.Rename(filepath.Join(dir, auditActive), filepath.Join(dir, auditSegName(1))); err != nil {
		t.Fatal(err)
	}
	if r, err := VerifyAuditDir(dir); err != nil || r.Error != "" || r.Entries != 3 {
		t.Fatalf("verify without an active segment: %+v %v", r, err)
	}
	l2, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l2.close() })
	appendN(t, l2, 3, 1, func(int) time.Time { return ksNow })
	if all, _ := l2.all(); len(all) != 4 || VerifyAuditChain(all) != nil {
		t.Fatalf("chain after crash recovery: %d, %v", len(all), VerifyAuditChain(all))
	}
}

func TestAuditRotationFailureKeepsAppending(t *testing.T) {
	dir := t.TempDir()
	l, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.close() })
	l.rot = AuditRotation{MaxBytes: 4096}
	appendN(t, l, 0, 1, func(int) time.Time { return ksNow })
	// a stray file where the segment would go: rotation must refuse to overwrite it
	if err := os.WriteFile(filepath.Join(dir, auditSegName(1)), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l.rot.MaxBytes = 4096
	l.size = 4096 // force the next append over the bound
	appendN(t, l, 1, 2, func(int) time.Time { return ksNow })
	if got := l.rotateErrs.Load(); got != 2 {
		t.Fatalf("rotate errors: %d", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, auditSegName(1))); string(b) != "keep\n" {
		t.Fatalf("segment overwritten: %q", b)
	}
	if err := os.Remove(filepath.Join(dir, auditSegName(1))); err != nil {
		t.Fatal(err)
	}
	if all, _ := l.all(); len(all) != 3 || VerifyAuditChain(all) != nil {
		t.Fatalf("entries after failed rotation: %d, %v", len(all), VerifyAuditChain(all))
	}
}

func TestAuditEndpointAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir = dir; c.Audit.Rotation = AuditRotation{MaxBytes: 4096} })
	for i := range 40 {
		e.s.Audit(t.Context(), "u"+fmt.Sprint(i%2), "experiment.kill", fmt.Sprint(i), map[string]string{"reason": strings.Repeat("r", 100)})
	}
	if segs := segFiles(t, dir); len(segs) < 2 {
		t.Fatalf("expected rotation: %v", segs)
	}
	r := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?limit=5", ""))
	if !r.Verified || r.Total != 40 || len(r.Entries) != 5 || r.Entries[0].Seq != 36 || r.Next != 40 {
		t.Fatalf("tail: verified=%v total=%d %v next=%d (%s)", r.Verified, r.Total, len(r.Entries), r.Next, r.VerifyError)
	}
	// forward paging crosses segment boundaries without gaps or repeats
	var seqs []uint64
	for next := uint64(0); ; {
		p := decode[AuditResponse](t, e.as(admin, "GET", fmt.Sprintf("/api/v1/audit?since=%d&limit=7", next), ""))
		for _, en := range p.Entries {
			seqs = append(seqs, en.Seq)
		}
		if len(p.Entries) == 0 {
			break
		}
		next = p.Next
	}
	for i, s := range seqs {
		if s != uint64(i)+1 {
			t.Fatalf("paged seqs: %v", seqs)
		}
	}
	if len(seqs) != 40 {
		t.Fatalf("paged %d entries", len(seqs))
	}
	if f := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?actor=u1&limit=3", "")); len(f.Entries) != 3 || f.Entries[2].Seq != 40 || f.Entries[0].Seq != 36 {
		t.Fatalf("filtered tail: %+v", f.Entries)
	}
	// tampering in a rotated segment is detected (the cache is keyed on size/mtime)
	seg := filepath.Join(dir, segFiles(t, dir)[0])
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg, []byte(strings.Replace(string(b), `"actor":"u0"`, `"actor":"zz"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?limit=1", "")); r.Verified || r.VerifyError == "" {
		t.Fatal("tampered rotated segment verified")
	}
	if v, err := VerifyAuditDir(dir); err != nil || v.Error == "" {
		t.Fatalf("VerifyAuditDir missed the tamper: %+v %v", v, err)
	}
	// a removed segment breaks the chain from genesis (reported, not a 500)
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	if w := e.as(admin, "GET", "/api/v1/audit", ""); w.Code != 200 || decode[AuditResponse](t, w).Verified {
		t.Fatalf("removed segment: %d %s", w.Code, w.Body)
	}
}

func TestAuditRotationNeedsDataDir(t *testing.T) {
	cfg := Config{Token: tok, DevUser: "u", Audit: AuditConfig{Rotation: AuditRotation{MaxBytes: 1 << 20}}}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "data dir") {
		t.Fatalf("rotation without data dir: %v", err)
	}
}

func TestAuditTailBounded(t *testing.T) {
	l := &auditLog{}
	appendN(t, l, 0, 25, func(int) time.Time { return ksNow })
	snap, _ := l.snapshot()
	defer snap.close()
	for _, n := range []int{1, 3, 25, 100} {
		got, err := snap.tail(n, func(AuditEntry) bool { return true })
		if err != nil || len(got) != min(n, 25) || got[len(got)-1].Seq != 25 || got[0].Seq != uint64(25-min(n, 25)+1) {
			t.Fatalf("tail(%d): %d entries, %v", n, len(got), err)
		}
	}
}
