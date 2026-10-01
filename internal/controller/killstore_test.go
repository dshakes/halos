package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKillStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenKillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for _, step := range []struct {
		name        string
		kill        bool
		exp         string
		wantChanged bool
	}{
		{"kill", true, "a", true},
		{"kill again is a no-op", true, "a", false},
		{"kill another", true, "b", true},
		{"unkill", false, "a", true},
		{"unkill again is a no-op", false, "a", false},
		{"unkill never-killed", false, "zzz", false},
	} {
		set := s.Unkill
		if step.kill {
			set = s.Kill
		}
		changed, err := set(ctx, step.exp, "alice", "why")
		if err != nil || changed != step.wantChanged {
			t.Fatalf("%s: changed=%v err=%v", step.name, changed, err)
		}
	}
	if _, err := s.Kill(ctx, "", "x", ""); err == nil {
		t.Fatal("empty name accepted")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Kill(cctx, "c", "x", ""); err == nil {
		t.Fatal("cancelled context ignored")
	}
	recs, v, err := s.Killed()
	if err != nil || len(recs) != 1 || recs[0].Experiment != "b" || recs[0].By != "alice" || v != 3 {
		t.Fatalf("killed=%+v version=%d err=%v", recs, v, err)
	}

	// Another process appends (halo controller run on the shared data dir) and
	// the file has a torn line from a crash: both are handled.
	other, err := OpenKillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Kill(ctx, "c", Actor, "rollback"); err != nil {
		t.Fatal(err)
	}
	_ = other.Close()
	f, err := os.OpenFile(filepath.Join(dir, "killswitch.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"experiment":"d","kil`)
	_ = f.Close()
	recs, v, err = s.Killed()
	if err != nil || len(recs) != 2 || recs[0].Experiment != "b" || recs[1].Experiment != "c" || v != 4 {
		t.Fatalf("after external append: %+v v=%d err=%v", recs, v, err)
	}

	// Reopen: state replays, torn line terminated so the next record survives.
	re, err := OpenKillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := re.Kill(ctx, "e", "bob", ""); err != nil {
		t.Fatal(err)
	}
	_ = re.Close()
	re, err = OpenKillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = re.Close() }()
	recs, _, _ = re.Killed()
	if len(recs) != 3 || recs[2].Experiment != "e" {
		t.Fatalf("after reopen: %+v", recs)
	}

	mem, _ := OpenKillStore("")
	if ch, err := mem.Kill(ctx, "x", "y", ""); !ch || err != nil {
		t.Fatalf("memory store: %v %v", ch, err)
	}
}
