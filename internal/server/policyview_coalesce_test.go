package server

import (
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// copyTree copies the regular files under src into dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPolicyHolderCoalescedWalkSeesEveryEdit: reads share one directory walk,
// but a read that starts after an edit still observes it (the walk it waits for
// started after the read did), however many other readers are in flight.
func TestPolicyHolderCoalescedWalkSeesEveryEdit(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, "../../examples/acme-corp", dir)
	p := &policyHolder{dir: dir, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if org, _, err := p.Get(); org == nil || err != nil {
		t.Fatalf("fixture did not load: %v", err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				p.Get()
			}
		}()
	}
	defer func() { stop.Store(true); wg.Wait() }()

	f := filepath.Join(dir, "halos.yaml")
	good, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		bad := append([]byte("rings: [this is not valid\n"), good...)
		if i%2 == 1 {
			bad = good
		}
		if err := os.WriteFile(f, bad, 0o644); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(time.Duration(i+1) * time.Minute) // distinct mtimes: no timestamp-granularity luck
		if err := os.Chtimes(f, at, at); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.Get(); (err != nil) != (i%2 == 0) {
			t.Fatalf("edit %d: read right after it returned err=%v, want an error for an invalid file only", i, err)
		}
	}
}
