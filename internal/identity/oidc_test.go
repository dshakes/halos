package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestOIDCDiscoveryShared: discovery never holds a lock across the network.
// Concurrent first requests share one discovery, each waits only as long as
// its own ctx allows, and a failed discovery is served from a negative cache
// for discoveryRetry instead of every request asking the issuer again.
func TestOIDCDiscoveryShared(t *testing.T) {
	var hits atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		http.Error(w, "down", http.StatusBadGateway)
	}))
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer srv.Close()
	defer unblock()
	v, err := NewOIDCJWT(srv.URL, aud, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	v.now = func() time.Time { return time.Unix(0, now.Load()) }

	// The issuer hangs: a request with a short deadline is not held hostage.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := v.Claims(ctx, "x.y.z"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrDiscovery) {
			t.Fatalf("waiter past its deadline: %v, want ErrDiscovery", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a request waited on a slow discovery past its own deadline")
	}
	// Many concurrent requests join the one discovery in flight.
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Claims(context.Background(), "x.y.z"); !errors.Is(err, ErrDiscovery) {
				t.Errorf("concurrent waiter: %v, want ErrDiscovery", err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	unblock()
	wg.Wait()
	if n := hits.Load(); n != 1 {
		t.Fatalf("issuer asked %d times, want 1 shared discovery", n)
	}
	// The failure is cached: no request asks the issuer within discoveryRetry...
	if _, err := v.Claims(context.Background(), "x.y.z"); !errors.Is(err, ErrDiscovery) || hits.Load() != 1 {
		t.Fatalf("negative cache: %v, %d hits", err, hits.Load())
	}
	// ...and discovery is retried after it.
	now.Add(int64(discoveryRetry))
	if _, err := v.Claims(context.Background(), "x.y.z"); !errors.Is(err, ErrDiscovery) || hits.Load() != 2 {
		t.Fatalf("retry after discoveryRetry: %v, %d hits", err, hits.Load())
	}
}
