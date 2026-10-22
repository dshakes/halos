package storage

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDirLog(t *testing.T) {
	ctx := context.Background()
	if l, err := Dir("").OpenLog(ctx, "x", func([]byte) {}); l != nil || err != nil {
		t.Fatalf("empty Dir must be memory only: %v %v", l, err)
	}
	dir := filepath.Join(t.TempDir(), "sub") // created on open
	var got []string
	l, err := Dir(dir).OpenLog(ctx, "devices", func(b []byte) { got = append(got, string(b)) })
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{`{"a":1}`, `{"a":2}`} {
		if err := l.Append(ctx, "k", []byte(r)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Catchup(ctx); err != nil || len(got) != 0 {
		t.Fatalf("a file log has no other writers: %v %v", got, err)
	}
	if err := CloseLog(&sync.Mutex{}, l); err != nil {
		t.Fatal(err)
	}
	if err := CloseLog(&sync.Mutex{}, nil); err != nil {
		t.Fatal("nil log close:", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "devices.jsonl")); err != nil || string(b) != "{\"a\":1}\n{\"a\":2}\n" {
		t.Fatalf("file %q %v", b, err)
	}
	l2, err := Dir(dir).OpenLog(ctx, "devices", func(b []byte) { got = append(got, string(b)) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()
	if len(got) != 2 || got[1] != `{"a":2}` {
		t.Fatalf("replay %v", got)
	}
	if err := l.Append(ctx, "", []byte("{}")); err == nil {
		t.Fatal("append to a closed log must fail")
	}
}

func TestDirLogMkdirError(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Dir(filepath.Join(f, "sub")).OpenLog(context.Background(), "x", func([]byte) {}); err == nil {
		t.Fatal("want error: parent is a file")
	}
}

func TestMemKV(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	kv := &MemKV{Now: func() time.Time { return now }}
	exp := now.Add(time.Minute)

	if ok, err := kv.Add(ctx, "ns", "k", []byte("v1"), exp); !ok || err != nil {
		t.Fatalf("first add: %v %v", ok, err)
	}
	if ok, _ := kv.Add(ctx, "ns", "k", []byte("v2"), exp); ok {
		t.Fatal("second add of a live key succeeded")
	}
	if ok, _ := kv.Add(ctx, "other", "k", nil, exp); !ok {
		t.Fatal("namespaces must not collide")
	}
	if v, ok, _ := kv.Get(ctx, "ns", "k"); !ok || string(v) != "v1" {
		t.Fatalf("get %q %v", v, ok)
	}
	if err := kv.Put(ctx, "ns", "k", []byte("v3"), exp); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := kv.Take(ctx, "ns", "k"); !ok || string(v) != "v3" {
		t.Fatalf("take %q %v", v, ok)
	}
	if _, ok, _ := kv.Take(ctx, "ns", "k"); ok {
		t.Fatal("take is single-use")
	}

	_ = kv.Put(ctx, "ns", "old", []byte("x"), exp)
	now = exp.Add(time.Second) // expired
	if _, ok, _ := kv.Get(ctx, "ns", "old"); ok {
		t.Fatal("expired entry visible to Get")
	}
	if _, ok, _ := kv.Take(ctx, "ns", "old"); ok {
		t.Fatal("expired entry taken")
	}
	_ = kv.Put(ctx, "ns", "old2", []byte("x"), now.Add(-time.Second))
	if ok, _ := kv.Add(ctx, "ns", "old2", []byte("y"), now.Add(time.Minute)); !ok {
		t.Fatal("add over an expired entry must succeed")
	}
	if err := kv.Delete(ctx, "ns", "old2"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := kv.Get(ctx, "ns", "old2"); ok {
		t.Fatal("deleted entry visible")
	}
}

func TestMemKVConcurrentTake(t *testing.T) {
	ctx := context.Background()
	kv := &MemKV{}
	_ = kv.Put(ctx, "enroll", "tok", []byte("p"), time.Now().Add(time.Minute))
	var mu sync.Mutex
	wins := 0
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, _ := kv.Take(ctx, "enroll", "tok"); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d takers won a single-use token", wins)
	}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"devices": true, "session-revocations": true, "a1": true,
		"": false, "Devices": false, "a/b": false, "a b": false, "x'y": false,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": false, // 65
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v", name, got)
		}
	}
}

func TestCtxBounded(t *testing.T) {
	ctx, cancel := Ctx()
	defer cancel()
	if d, ok := ctx.Deadline(); !ok || time.Until(d) > OpTimeout {
		t.Fatalf("deadline %v %v", d, ok)
	}
}
