package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
)

// hangingRemote blocks every Sign until release is closed.
type hangingRemote struct {
	bundle.ECDSASigner
	release chan struct{}
	n       atomic.Int32
}

func (h *hangingRemote) Remote() bool { return true }

func (h *hangingRemote) Sign(ctx context.Context, msg string) ([]byte, error) {
	h.n.Add(1)
	select {
	case <-h.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return h.ECDSASigner.Sign(ctx, msg)
}

// R1: with the signer hanging, 200 polls for 200 distinct lists cost one
// in-flight sign and a bounded number of goroutines; when the signer comes
// back, only the newest list is signed next.
func TestKillSigBoundedDuringHang(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &hangingRemote{ECDSASigner: bundle.ECDSASigner{Key: k}, release: make(chan struct{})}
	var c killSigCache
	quiet := slog.New(slog.DiscardHandler)
	before := runtime.NumGoroutine()
	at := time.Unix(1000, 0)
	for i := 1; i <= 200; i++ {
		l := gateway.KillList{Version: uint64(i), Experiments: []string{fmt.Sprintf("exp-%d", i)}, IssuedAt: at.Add(time.Duration(i) * time.Millisecond)}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
		if _, err := c.sign(ctx, h, l, quiet); err == nil {
			t.Fatal("hanging signer produced an envelope")
		}
		cancel()
	}
	if n := h.n.Load(); n != 1 {
		t.Fatalf("%d sign calls in flight, want 1", n)
	}
	if g := runtime.NumGoroutine() - before; g > 5 {
		t.Fatalf("%d goroutines leaked for 200 distinct lists", g)
	}
	close(h.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		v, idle := c.list.Version, c.inflight == nil && c.pending == nil
		c.mu.Unlock()
		if (v == 200 && idle) || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := h.n.Load(); n != 2 {
		t.Fatalf("%d sign calls after release, want 2 (the hung one, then only the newest)", n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.list.Version != 200 || c.list.Experiments[0] != "exp-200" {
		t.Fatalf("cache holds %+v, want the newest list", c.list)
	}
}
