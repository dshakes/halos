package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/bundle"
	"github.com/halos-dev/halos/internal/gateway"
)

func TestAccessKillSwitch(t *testing.T) {
	privPEM, pubPEM, err := bundle.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := bundle.ParseEd25519Signer(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	var authOK atomic.Bool
	ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authOK.Store(r.Header.Get("Authorization") == "Bearer gw-tok")
		env, _ := gateway.SignKillList(signer.Key, gateway.KillList{Version: 1, Experiments: []string{"shadow"}, IssuedAt: time.Now()})
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer ks.Close()
	var mirrored atomic.Int32
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mirrored.Add(1)
		w.WriteHeader(202)
	}))
	defer mirror.Close()

	t.Setenv("HALO_TEST_KILL_TOKEN", "gw-tok")
	c := trustedCfg(testPolicy(t))
	c.ShadowURL = mirror.URL + "/mirror"
	c.KillswitchURL, c.KillswitchToken, c.KillswitchPubkey = ks.URL, "{vault://env/halo-test-kill-token}", string(pubPEM)
	hdrs := map[string][]string{"x-acme-user": {"alice"}, "x-acme-groups": {"ai-platform"}, "x-claude-code-session-id": {"sess-1"}}

	k := &fakeKong{}
	poller := c.killSwitch(k)
	if poller == nil || c.killSwitch(k) != poller {
		t.Fatalf("poller not shared: %v logs=%v", poller, k.logs)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(poller.Killed().Experiments) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !authOK.Load() || len(poller.Killed().Experiments) != 1 {
		t.Fatalf("kill list not fetched (auth ok=%v)", authOK.Load())
	}
	fk := &fakeKong{peer: "10.0.0.1", path: "/v1/messages", body: []byte(firstTurn), hdrs: hdrs}
	c.access(fk)
	if fk.exitStatus != 0 || fk.set["x-halo-ring"] != "ring0" {
		t.Fatalf("exit=%d set=%v", fk.exitStatus, fk.set)
	}
	time.Sleep(200 * time.Millisecond) // mirroring is async
	if n := mirrored.Load(); n != 0 {
		t.Fatalf("killed shadow experiment still mirrored %d request(s)", n)
	}

	// Invalid pubkey: the good poller keeps running, the error is logged once
	// per minute, and the request is flagged but still served.
	bad := c
	bad.KillswitchPubkey = "not a pem"
	bk := &fakeKong{}
	first, second := bad.killSwitch(bk), bad.killSwitch(bk) // second call: rate-limited
	if first != poller || second != poller || strings.Count(strings.Join(bk.logs, "\n"), "killswitch config") != 1 {
		t.Fatalf("bad config logs: %v", bk.logs)
	}
	now := time.Now()
	killNow = func() time.Time { return now.Add(2 * time.Minute) }
	t.Cleanup(func() { killNow = time.Now })
	bad.killSwitch(bk)
	if n := strings.Count(strings.Join(bk.logs, "\n"), "killswitch config"); n != 2 {
		t.Fatalf("expected a second log after a minute, got %d: %v", n, bk.logs)
	}
	fk2 := &fakeKong{peer: "10.0.0.1", path: "/v1/messages", body: []byte(firstTurn), hdrs: hdrs}
	bad.access(fk2)
	if fk2.exitStatus != 0 || fk2.set["x-halo-killswitch"] != "misconfigured" {
		t.Fatalf("misconfig not flagged/served: exit=%d set=%v", fk2.exitStatus, fk2.set)
	}
}

func TestKillSwitchURLMustBeHTTPS(t *testing.T) {
	_, pubPEM, _ := bundle.GenerateKeyPair()
	for _, tt := range []struct {
		url      string
		insecure bool
		ok       bool
	}{
		{"https://halo.example/api/v1/gateway/killswitch", false, true},
		{"http://halo.example/x", false, false},
		{"http://halo.example/x", true, true},
		{"http://127.0.0.1:1/x", false, true},
		{"ftp://halo.example/x", true, false},
	} {
		c := Config{KillswitchURL: tt.url, KillswitchToken: "t", KillswitchPubkey: string(pubPEM), KillswitchAllowInsecure: tt.insecure}
		_, bad := c.killPoller(&fakeKong{})
		if bad == tt.ok {
			t.Errorf("%s insecure=%v: misconfigured=%v, want %v", tt.url, tt.insecure, bad, !tt.ok)
		}
		killMu.Lock()
		if e := kills[tt.url]; e != nil && e.cancel != nil {
			e.cancel()
		}
		delete(kills, tt.url)
		killMu.Unlock()
	}
}

// A rotated token/pubkey replaces the poller: old ones are cancelled, not leaked.
func TestKillSwitchRotationDoesNotLeakPollers(t *testing.T) {
	_, pubPEM, _ := bundle.GenerateKeyPair()
	ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) }))
	defer ks.Close()
	c := Config{KillswitchURL: ks.URL, KillswitchToken: "t0", KillswitchPubkey: string(pubPEM)}
	first := c.killSwitch(&fakeKong{})
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	var last *gateway.KillSwitch
	for i := 1; i <= 20; i++ {
		c.KillswitchToken = fmt.Sprintf("t%d", i)
		last = c.killSwitch(&fakeKong{})
	}
	if last == first {
		t.Fatal("rotation did not replace the poller")
	}
	killMu.Lock()
	e := kills[ks.URL] // one entry per URL, however many rotations
	killMu.Unlock()
	t.Cleanup(func() { e.cancel() })
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base+4 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > base+4 {
		t.Fatalf("goroutines %d after 20 rotations (base %d): pollers leaked", g, base)
	}
}
