package storage

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemKVLock(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	kv := &MemKV{Now: func() time.Time { return now }}
	if ok, _ := kv.TryLock(ctx, "lock", "scim", "a", 30*time.Second); !ok {
		t.Fatal("free lock not taken")
	}
	if ok, _ := kv.TryLock(ctx, "lock", "scim", "b", 30*time.Second); ok {
		t.Fatal("held lock taken by another owner")
	}
	if ok, _ := kv.TryLock(ctx, "lock", "scim", "a", 30*time.Second); !ok {
		t.Fatal("owner cannot extend its own lock")
	}
	now = now.Add(31 * time.Second) // a's lock expired
	if ok, _ := kv.TryLock(ctx, "lock", "scim", "b", 30*time.Second); !ok {
		t.Fatal("expired lock not taken over")
	}
	if err := kv.Unlock(ctx, "lock", "scim", "a"); err != nil { // the old holder's late release
		t.Fatal(err)
	}
	if ok, _ := kv.TryLock(ctx, "lock", "scim", "c", 30*time.Second); ok {
		t.Fatal("a stale owner's Unlock released the new holder's lock")
	}
	if err := kv.Unlock(ctx, "lock", "scim", "b"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := kv.TryLock(ctx, "lock", "scim", "c", 30*time.Second); !ok {
		t.Fatal("released lock not free")
	}
}

func TestMemKVRaise(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	kv := &MemKV{Now: func() time.Time { return now }}
	_ = kv.Raise(ctx, "e", "u", 50, now.Add(time.Hour))
	_ = kv.Raise(ctx, "e", "u", 40, now.Add(2*time.Hour)) // older epoch, later expiry
	if v, _, _ := kv.Get(ctx, "e", "u"); string(v) != "50" {
		t.Fatalf("epoch moved backwards: %s", v)
	}
	now = now.Add(90 * time.Minute) // past the first expiry, inside the second
	if v, ok, _ := kv.Get(ctx, "e", "u"); !ok || string(v) != "50" {
		t.Fatalf("expiry not extended: %s %v", v, ok)
	}
	_ = kv.Raise(ctx, "e", "u", 60, now.Add(time.Hour))
	if v, _, _ := kv.Get(ctx, "e", "u"); string(v) != "60" {
		t.Fatalf("epoch not raised: %s", v)
	}
}

// TestCoalescer: concurrent callers share runs, and every caller is served by
// a run that started after it called (never by one already in flight).
func TestCoalescer(t *testing.T) {
	var c Coalescer
	var runs atomic.Int64
	gate := make(chan struct{})
	var startedAt sync.Map
	fn := func() error {
		n := runs.Add(1)
		startedAt.Store(n, time.Now())
		if n == 1 {
			<-gate // hold the first run open while others arrive
		}
		return nil
	}
	var wg sync.WaitGroup
	wg.Go(func() { _ = c.Do(fn) })
	for runs.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	arrived := time.Now()
	for range 50 {
		wg.Go(func() { _ = c.Do(fn) })
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	// The in-flight run plus one shared follow-up (a third only if a caller
	// was slow to arrive, never one per caller).
	if n := runs.Load(); n < 2 || n > 3 {
		t.Fatalf("%d runs for 51 callers, want 2 or 3", n)
	}
	if s, _ := startedAt.Load(int64(2)); !s.(time.Time).After(arrived) {
		t.Fatal("waiters were served by a run that started before they arrived")
	}
}
