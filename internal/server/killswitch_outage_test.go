package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
)

// flakyRemote is a KMS-like kill key that can be slow or down. It honors
// its context, as the real backends do.
type flakyRemote struct {
	bundle.ECDSASigner
	delay time.Duration
	down  atomic.Bool
	n     atomic.Int32
}

func (f *flakyRemote) Remote() bool { return true }

func (f *flakyRemote) Sign(ctx context.Context, msg string) ([]byte, error) {
	f.n.Add(1)
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.down.Load() {
		return nil, errors.New("kms: ServiceUnavailable")
	}
	return f.ECDSASigner.Sign(ctx, msg)
}

func newFlaky(t *testing.T, delay time.Duration) (*flakyRemote, bundle.ECDSAVerifier) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &flakyRemote{ECDSASigner: bundle.ECDSASigner{Key: k}, delay: delay}, bundle.ECDSAVerifier{Key: &k.PublicKey}
}

// M2: a remote sign slower than the poll's own timeout is not abandoned:
// the poll that gave up gets an error (nothing cached yet), and the next
// poll is served by the signature that finished meanwhile, with no new KMS call.
func TestKillSigSlowRemoteStillServes(t *testing.T) {
	f, v := newFlaky(t, 200*time.Millisecond)
	var c killSigCache
	at := time.Unix(1000, 0)
	l := gateway.KillList{Version: 1, Experiments: []string{}, IssuedAt: at}
	pollCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.sign(pollCtx, f, l, slog.Default()); err == nil {
		t.Fatal("first poll should time out: nothing to serve yet")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		signed := c.env.Signature != nil
		c.mu.Unlock()
		if signed || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.IssuedAt = at.Add(time.Second)
	env, err := c.sign(context.Background(), f, l, slog.Default())
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if _, err := gateway.VerifyKillList(context.Background(), v, env, at, time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := f.n.Load(); n != 1 {
		t.Fatalf("%d remote signs, want 1 (the detached one)", n)
	}
}

// M2: during an outage an unchanged list keeps being served from the cache
// (bounded by killSigStale, counted), and a changed list is an error, never
// the stale list presented as current.
func TestKillSigOutage(t *testing.T) {
	f, v := newFlaky(t, 0)
	var c killSigCache
	ctx := context.Background()
	at := time.Unix(1000, 0)
	l := gateway.KillList{Version: 1, Experiments: []string{}, IssuedAt: at}
	first, err := c.sign(ctx, f, l, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	f.down.Store(true)
	l.IssuedAt = at.Add(killSigTTL + time.Second) // past the TTL: a re-sign is attempted and fails
	env, err := c.sign(ctx, f, l, slog.Default())
	if err != nil || string(env.Signature) != string(first.Signature) {
		t.Fatalf("outage, unchanged list: err %v (cached served: %v)", err, string(env.Signature) == string(first.Signature))
	}
	if c.staleHit.Load() != 1 || c.failures.Load() != 1 {
		t.Fatalf("stale %d failures %d", c.staleHit.Load(), c.failures.Load())
	}
	if _, err := gateway.VerifyKillList(ctx, v, env, l.IssuedAt, gateway.DefaultKillMaxAge); err != nil {
		t.Fatalf("cached envelope no longer acceptable to pollers: %v", err)
	}
	changed := l
	changed.Version, changed.Experiments = 2, []string{"bad-canary"}
	if env, err := c.sign(ctx, f, changed, slog.Default()); err == nil {
		t.Fatalf("changed list during an outage answered with %q", env.Payload)
	}
	l.IssuedAt = at.Add(killSigStale + time.Second)
	if _, err := c.sign(ctx, f, l, slog.Default()); err == nil {
		t.Fatal("cache served past killSigStale")
	}
	f.down.Store(false) // recovery: signed fresh again
	env, err = c.sign(ctx, f, changed, slog.Default())
	if err != nil || string(env.Signature) == string(first.Signature) {
		t.Fatalf("after recovery: %v", err)
	}
	if got, err := gateway.VerifyKillList(ctx, v, env, changed.IssuedAt, time.Minute); err != nil || len(got.Experiments) != 1 {
		t.Fatalf("recovered list: %+v %v", got, err)
	}
}

// M2: the mutex is not held across the remote call: while a slow sign runs,
// another poll for a list already cached and fresh is answered at once.
func TestKillSigNoLockAcrossRemote(t *testing.T) {
	f, _ := newFlaky(t, 0)
	var c killSigCache
	ctx := context.Background()
	at := time.Unix(1000, 0)
	l := gateway.KillList{Version: 1, Experiments: []string{}, IssuedAt: at}
	if _, err := c.sign(ctx, f, l, slog.Default()); err != nil {
		t.Fatal(err)
	}
	f.delay = 2 * time.Second
	changed := l
	changed.Version, changed.Experiments, changed.IssuedAt = 2, []string{"x"}, at.Add(time.Second)
	go func() { _, _ = c.sign(ctx, f, changed, slog.Default()) }() // slow sign of a new list
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	locked := c.mu.TryLock()
	if locked {
		c.mu.Unlock()
	}
	if !locked || time.Since(start) > time.Second {
		t.Fatal("cache mutex held across the remote sign")
	}
}
