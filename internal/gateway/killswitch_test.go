package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

func killKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestKillListSignVerify(t *testing.T) {
	pub, priv := killKeys(t)
	otherPub, _ := killKeys(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	good, err := SignKillList(priv, KillList{Version: 3, Experiments: []string{"a"}, IssuedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	tampered := good
	tampered.Payload = []byte(`{"version":3,"experiments":[],"issuedAt":"2026-09-01T12:00:00Z"}`)
	flipped := KillEnvelope{Payload: good.Payload, Signature: slices.Clone(good.Signature)}
	flipped.Signature[0] ^= 1
	// A signature by the same key over the bare payload (no domain prefix) must not verify.
	bare := KillEnvelope{Payload: good.Payload, Signature: ed25519.Sign(priv, good.Payload)}
	stale, _ := SignKillList(priv, KillList{IssuedAt: now.Add(-time.Hour)})
	future, _ := SignKillList(priv, KillList{IssuedAt: now.Add(5 * time.Minute)})

	for _, tc := range []struct {
		name string
		pub  ed25519.PublicKey
		env  KillEnvelope
		ok   bool
	}{
		{"valid", pub, good, true},
		{"tampered payload", pub, tampered, false},
		{"flipped signature", pub, flipped, false},
		{"no domain separation", pub, bare, false},
		{"wrong key", otherPub, good, false},
		{"short key", pub[:5], good, false},
		{"stale", pub, stale, false},
		{"from the future", pub, future, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := VerifyKillList(tc.pub, tc.env, now, 10*time.Minute)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && (l.Version != 3 || !slices.Equal(l.Experiments, []string{"a"})) {
				t.Fatalf("list = %+v", l)
			}
		})
	}
	if _, err := SignKillList(priv[:10], KillList{}); err == nil {
		t.Fatal("short private key accepted")
	}
}

// killServer serves whatever envelope/status the test sets.
type killServer struct {
	mu     sync.Mutex
	status int
	env    KillEnvelope
	auth   string
}

func (k *killServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.auth = r.Header.Get("Authorization")
	if k.status != http.StatusOK {
		w.WriteHeader(k.status)
		return
	}
	_ = json.NewEncoder(w).Encode(k.env)
}

func (k *killServer) set(status int, env KillEnvelope) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.status, k.env = status, env
}

func TestKillSwitchPoller(t *testing.T) {
	pub, priv := killKeys(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	ks := &killServer{}
	srv := httptest.NewServer(ks)
	defer srv.Close()
	k, err := NewKillSwitch(srv.URL, "gw-token", pub, 0, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	if err != nil {
		t.Fatal(err)
	}
	k.Now = func() time.Time { return now }
	sign := func(at time.Time, exps ...string) KillEnvelope {
		env, err := SignKillList(priv, KillList{Version: uint64(len(exps)), Experiments: exps, IssuedAt: at})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	ctx := context.Background()

	// Never fetched: nothing killed.
	ks.set(http.StatusServiceUnavailable, KillEnvelope{})
	if err := k.Refresh(ctx); err == nil || len(k.Killed().Experiments) != 0 {
		t.Fatalf("never-fetched: err=%v list=%v", err, k.Killed())
	}

	ks.set(http.StatusOK, sign(now.Add(-time.Second), "exp-a"))
	if err := k.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if ks.auth != "Bearer gw-token" {
		t.Fatalf("auth header = %q", ks.auth)
	}
	if got := k.Killed().Experiments; !slices.Equal(got, []string{"exp-a"}) {
		t.Fatalf("killed = %v", got)
	}

	// Failures of every kind keep the last-known list.
	forged := sign(now, "")
	forged.Payload = []byte(fmt.Sprintf(`{"version":9,"experiments":[],"issuedAt":%q}`, now.Format(time.RFC3339)))
	for name, set := range map[string]func(){
		"http 500": func() { ks.set(http.StatusInternalServerError, KillEnvelope{}) },
		"forged":   func() { ks.set(http.StatusOK, forged) },
		"replayed": func() { ks.set(http.StatusOK, sign(now.Add(-time.Minute))) }, // older than current
		"stale":    func() { ks.set(http.StatusOK, sign(now.Add(-time.Hour))) },
	} {
		set()
		if err := k.Refresh(ctx); err == nil {
			t.Fatalf("%s: refresh succeeded", name)
		}
		if got := k.Killed().Experiments; !slices.Equal(got, []string{"exp-a"}) {
			t.Fatalf("%s: last-known list lost: %v", name, got)
		}
	}
	srv.Close()
	if err := k.Refresh(ctx); err == nil || !slices.Equal(k.Killed().Experiments, []string{"exp-a"}) {
		t.Fatalf("server down: err=%v list=%v", err, k.Killed())
	}

	// A newer list replaces it (unkill).
	srv2 := httptest.NewServer(ks)
	defer srv2.Close()
	k.URL = srv2.URL
	ks.set(http.StatusOK, sign(now))
	if err := k.Refresh(ctx); err != nil || len(k.Killed().Experiments) != 0 {
		t.Fatalf("unkill: err=%v list=%v", err, k.Killed())
	}
}

func TestNewKillSwitchValidates(t *testing.T) {
	pub, _ := killKeys(t)
	for _, tc := range []struct{ url, tok string }{{"", "t"}, {"https://x", ""}, {"not a url", "t"}, {"http://halo.example/x", "t"}, {"ftp://halo.example/x", "t"}} {
		if _, err := NewKillSwitch(tc.url, tc.tok, pub, 0, nil, false); err == nil {
			t.Errorf("%q/%q accepted", tc.url, tc.tok)
		}
	}
	if _, err := NewKillSwitch("https://x", "t", pub[:3], 0, nil, false); err == nil {
		t.Error("bad key accepted")
	}
	for _, u := range []string{"http://halo.example/x", "http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]/x"} {
		_, err := NewKillSwitch(u, "t", pub, 0, nil, true)
		if err != nil {
			t.Errorf("%s with allowInsecureInCluster: %v", u, err)
		}
	}
	for _, u := range []string{"http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]/x"} {
		if _, err := NewKillSwitch(u, "t", pub, 0, nil, false); err != nil {
			t.Errorf("loopback %s rejected: %v", u, err)
		}
	}
}

func TestKillSwitchApplyRoutesControl(t *testing.T) {
	org := testOrg()
	// Find a user in the canary treatment and a session the shadow samples.
	var treated RequestInfo
	for i := 0; i < 5000 && treated.UserID == ""; i++ {
		req := RequestInfo{UserID: fmt.Sprintf("u%d", i), ModelAlias: "sonnet", SessionID: fmt.Sprintf("s%d", i), FirstTurn: true}
		if d := Decide(org, req); d.Variant == "direct" && len(d.Shadow) > 0 {
			treated = req
		}
	}
	if treated.UserID == "" {
		t.Fatal("no treated+shadowed user found")
	}

	var nilKS *KillSwitch
	if nilKS.Apply(org) != org {
		t.Fatal("nil kill switch must return org unchanged")
	}
	k := &KillSwitch{}
	if k.Apply(org) != org {
		t.Fatal("empty kill list must return org unchanged")
	}
	k.killed = map[string]bool{"sonnet-canary": true, "sonnet-shadow": true, "not-in-policy": true}
	d := Decide(k.Apply(org), treated)
	if d.Experiment != "" || d.Variant != "" || len(d.Shadow) != 0 {
		t.Fatalf("killed experiments still assigned: %+v", d)
	}
	if d.Upstream != "https://orch.internal:8443" || d.UpstreamModel != "us.anthropic.claude-sonnet-4-5" {
		t.Fatalf("killed user not on control route: %+v", d)
	}
	if _, ok := d.Headers[HeaderExperiment]; ok {
		t.Fatal("experiment header stamped for a killed experiment")
	}
	if org.Experiments[0].Status != "running" || org.Experiments[1].Status != "running" {
		t.Fatal("Apply mutated the shared policy snapshot")
	}
	if d := Decide(org, treated); d.Variant != "direct" {
		t.Fatalf("unkilled org changed: %+v", d)
	}
}
