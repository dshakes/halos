package pgstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLeases is a LeaseStore on a fake clock with the same rules as the SQL
// upsert in DB.Acquire, plus error injection to model a partition.
type fakeLeases struct {
	mu   sync.Mutex
	now  func() time.Time
	m    map[string]fakeLease
	down map[string]bool // replica (holder before "#term") -> its calls fail
}

type fakeLease struct {
	holder string
	token  int64
	exp    time.Time
}

func (f *fakeLeases) Acquire(ctx context.Context, name, holder string, ttl time.Duration) (int64, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down[strings.SplitN(holder, "#", 2)[0]] {
		return 0, false, errors.New("connection refused")
	}
	now := f.now()
	if f.m == nil {
		f.m = map[string]fakeLease{}
	}
	l, held := f.m[name]
	live := held && now.Before(l.exp)
	switch {
	case !held:
		l.token = 1
	case live && l.holder != holder:
		return 0, false, nil
	case !live || l.holder != holder:
		l.token++
	}
	l.holder, l.exp = holder, now.Add(ttl)
	f.m[name] = l
	return l.token, true, nil
}

func (f *fakeLeases) Release(_ context.Context, name, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down[strings.SplitN(holder, "#", 2)[0]] {
		return errors.New("connection refused")
	}
	if l, ok := f.m[name]; ok && l.holder == holder && f.now().Before(l.exp) {
		l.exp = f.now()
		f.m[name] = l
	}
	return nil
}

func (f *fakeLeases) setDown(holder string, down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down == nil {
		f.down = map[string]bool{}
	}
	f.down[holder] = down
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newPair(clk *fakeClock, store LeaseStore) (a, b *Elector) {
	mk := func(h string) *Elector {
		e := &Elector{Store: store, Name: "controller", Holder: h, TTL: 15 * time.Second, Log: quiet(), Now: clk.Now}
		e.defaults()
		return e
	}
	return mk("a"), mk("b")
}

func TestElectorTick(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(0, 0)}
	store := &fakeLeases{now: clk.Now}
	a, b := newPair(clk, store)

	lead, tok, wait := a.tick(ctx)
	if !lead || tok != 1 || wait != 5*time.Second || !a.Leader() || a.Token() != 1 {
		t.Fatalf("a: lead=%v tok=%d wait=%v", lead, tok, wait)
	}
	if lead, _, _ := b.tick(ctx); lead || b.Leader() {
		t.Fatal("b leads while a holds the lease")
	}
	clk.Add(5 * time.Second)
	if lead, tok, _ := a.tick(ctx); !lead || tok != 1 {
		t.Fatalf("renewal must keep the token: lead=%v tok=%d", lead, tok)
	}

	// Partition: a cannot reach the store. It keeps leading only until
	// TTL-Renew after its last successful renewal started, then steps down.
	store.setDown("a", true)
	clk.Add(5 * time.Second) // t=10: deadline is 5+10=15
	if lead, _, wait := a.tick(ctx); !lead || wait != 5*time.Second {
		t.Fatalf("a should still lead before its deadline: %v wait=%v", lead, wait)
	}
	clk.Add(5 * time.Second) // t=15: at the deadline
	if lead, _, _ := a.tick(ctx); lead || a.Leader() {
		t.Fatal("a must step down at its renewal deadline")
	}
	// The lease (renewed at t=5 for 15s) is still live on the store's clock:
	// nobody leads in the gap, so there is never a second leader.
	if lead, _, _ := b.tick(ctx); lead {
		t.Fatal("b took an unexpired lease")
	}
	clk.Add(5 * time.Second) // t=20: expired
	lead, tok, _ = b.tick(ctx)
	if !lead || tok != 2 {
		t.Fatalf("b failover: lead=%v tok=%d, want token 2", lead, tok)
	}
	// a comes back: the lease is b's now.
	store.setDown("a", false)
	if lead, _, _ := a.tick(ctx); lead {
		t.Fatal("a leads alongside b after the partition heals")
	}
	if a.changes.Load() != 2 || b.changes.Load() != 1 {
		t.Fatalf("changes a=%d b=%d", a.changes.Load(), b.changes.Load())
	}
}

func TestElectorStepsDownWhenLeaseTaken(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(0, 0)}
	store := &fakeLeases{now: clk.Now}
	a, _ := newPair(clk, store)
	if lead, _, _ := a.tick(ctx); !lead {
		t.Fatal("a should lead")
	}
	// Simulate a's clock running slow: the lease expired on the store and
	// another holder took it while a still thinks it is inside its deadline.
	store.mu.Lock()
	store.m["controller"] = fakeLease{holder: "c", token: 7, exp: clk.Now().Add(time.Hour)}
	store.mu.Unlock()
	if lead, _, _ := a.tick(ctx); lead || a.Leader() || a.Token() != 0 {
		t.Fatal("a must step down when the store says the lease is someone else's")
	}
}

func TestElectorDefaults(t *testing.T) {
	e := &Elector{TTL: time.Second, Renew: 2 * time.Second}
	e.defaults()
	if e.Renew != time.Second/3 || e.Now == nil || e.Log == nil {
		t.Fatalf("%+v", e)
	}
	e = &Elector{}
	e.defaults()
	if e.TTL != 15*time.Second || e.Renew != 5*time.Second {
		t.Fatalf("%+v", e)
	}
}

func TestElectorMetrics(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	a, _ := newPair(clk, &fakeLeases{now: clk.Now})
	var buf bytes.Buffer
	a.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `halo_leader{lease="controller"} 0`) {
		t.Fatal(buf.String())
	}
	a.tick(context.Background())
	buf.Reset()
	a.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `halo_leader{lease="controller"} 1`) || !strings.Contains(buf.String(), `halo_leader_changes_total{lease="controller"} 1`) {
		t.Fatal(buf.String())
	}
}

// TestElectorRunFailover runs two replicas' Run loops on real (short) time:
// exactly one runs lead at any moment, and when the leader's process stops
// (its context ends, releasing the lease) the other takes over with a
// higher fencing token.
func TestElectorRunFailover(t *testing.T) {
	store := &fakeLeases{now: time.Now}
	var active atomic.Int32
	var overlap atomic.Bool
	tokens := make(chan int64, 16)
	lead := func(ctx context.Context, tok int64) {
		if active.Add(1) > 1 {
			overlap.Store(true)
		}
		tokens <- tok
		<-ctx.Done()
		active.Add(-1)
	}
	mk := func(h string) *Elector {
		return &Elector{Store: store, Name: "controller", Holder: h, TTL: 300 * time.Millisecond, Log: quiet()}
	}
	actx, stopA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	a := mk("a")
	go func() { defer close(doneA); a.Run(actx, lead) }()
	first := <-tokens

	bctx, stopB := context.WithCancel(context.Background())
	defer stopB()
	doneB := make(chan struct{})
	b := mk("b")
	go func() { defer close(doneB); b.Run(bctx, lead) }()
	time.Sleep(250 * time.Millisecond) // several renewals: b must stay a follower
	if b.Leader() || !a.Leader() {
		t.Fatal("b leads while a renews")
	}

	stopA() // a shuts down: stops lead, releases the lease
	<-doneA
	select {
	case second := <-tokens:
		if second <= first {
			t.Fatalf("token %d after %d: fencing token must grow", second, first)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("b never took over")
	}
	if !b.Leader() || a.Leader() {
		t.Fatal("after failover b must lead alone")
	}
	stopB()
	<-doneB
	if overlap.Load() {
		t.Fatal("two leaders ran at once")
	}
}

// TestElectorRunCrashFailover: the leader dies without releasing (its store
// calls start failing); it must stop leading on its own before the follower
// can take over, and the follower takes over once the lease expires.
func TestElectorRunCrashFailover(t *testing.T) {
	store := &fakeLeases{now: time.Now}
	var mu sync.Mutex
	var events []string
	lead := func(name string) func(context.Context, int64) {
		return func(ctx context.Context, _ int64) {
			mu.Lock()
			events = append(events, "start "+name)
			mu.Unlock()
			<-ctx.Done()
			mu.Lock()
			events = append(events, "stop "+name)
			mu.Unlock()
		}
	}
	mk := func(h string) *Elector {
		return &Elector{Store: store, Name: "controller", Holder: h, TTL: 300 * time.Millisecond, Log: quiet()}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := mk("a"), mk("b")
	done := make(chan struct{}, 2)
	go func() { a.Run(ctx, lead("a")); done <- struct{}{} }()
	deadline := time.Now().Add(2 * time.Second)
	for !a.Leader() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	go func() { b.Run(ctx, lead("b")); done <- struct{}{} }()
	store.setDown("a", true)
	for !b.Leader() && time.Now().Before(deadline.Add(2*time.Second)) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	<-done
	mu.Lock()
	defer mu.Unlock()
	want := []string{"start a", "stop a", "start b", "stop b"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v, want %v (a must stop before b starts)", events, want)
	}
}
