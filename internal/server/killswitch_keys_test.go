package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
)

// countingRemote is a KMS-like kill key: ECDSA P-256, Remote, counts signs.
type countingRemote struct {
	bundle.ECDSASigner
	mu sync.Mutex
	n  int
}

func (c *countingRemote) Sign(ctx context.Context, msg string) ([]byte, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.ECDSASigner.Sign(ctx, msg)
}

func (c *countingRemote) Remote() bool { return true }

func (c *countingRemote) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// ADR-0038: a remotely held (KMS / HSM) ECDSA kill key signs the list; the
// signed envelope is cached for killSigTTL so pollers do not cost a KMS call
// each, a kill re-signs at once, and pollers accept the cached envelope.
func TestKillswitchRemoteKeyCache(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rs := &countingRemote{ECDSASigner: bundle.ECDSASigner{Key: k}}
	e := newEnv(t, func(c *Config) { c.KillKey, c.GatewayToken = rs, gwTok })
	v := bundle.ECDSAVerifier{Key: &k.PublicKey}
	get := func() gateway.KillEnvelope {
		t.Helper()
		w := do(e.h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
		if w.Code != 200 {
			t.Fatalf("killswitch: %d %s", w.Code, w.Body)
		}
		return decode[gateway.KillEnvelope](t, w)
	}
	first := get()
	if first.Alg != bundle.AlgECDSAP256 || first.KeyID != bundle.KeyID(v) {
		t.Fatalf("envelope %+v", first)
	}
	if _, err := gateway.VerifyKillList(context.Background(), v, first, *e.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	*e.now = e.now.Add(time.Second)
	if again := get(); string(again.Signature) != string(first.Signature) || rs.count() != 1 {
		t.Fatalf("not cached: %d signs", rs.count())
	}
	// a kill changes the list: signed at once
	if _, err := e.s.KillExperiment(context.Background(), "cli-ab", "halo-controller", "r"); err != nil {
		t.Fatal(err)
	}
	l, err := gateway.VerifyKillList(context.Background(), v, get(), *e.now, time.Minute)
	if err != nil || !slices.Equal(l.Experiments, []string{"cli-ab"}) || rs.count() != 2 {
		t.Fatalf("kill not re-signed: %+v %v (%d signs)", l, err, rs.count())
	}
	// past the TTL the same list is re-signed with a fresh IssuedAt
	*e.now = e.now.Add(killSigTTL + time.Second)
	l2, err := gateway.VerifyKillList(context.Background(), v, get(), *e.now, time.Minute)
	if err != nil || rs.count() != 3 || !l2.IssuedAt.After(l.IssuedAt) {
		t.Fatalf("not refreshed after TTL: %v (%d signs)", err, rs.count())
	}
	// the enrollment endpoint serves the ECDSA public key
	w := do(e.h, "GET", "/enroll/killswitch.pub", "", "")
	pv, err := bundle.ParseVerifier(w.Body.Bytes())
	if w.Code != 200 || err != nil || bundle.KeyID(pv) != bundle.KeyID(v) {
		t.Fatalf("killswitch.pub: %d %v", w.Code, err)
	}
}

func TestKillSigCache(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctx := context.Background()
	at := time.Unix(100, 0)
	l := gateway.KillList{Version: 1, Experiments: []string{}, IssuedAt: at}

	// In-process keys are not cached: every response is signed fresh, as before.
	var local killSigCache
	a, _ := local.sign(ctx, bundle.ECDSASigner{Key: k}, l, slog.Default())
	b, _ := local.sign(ctx, bundle.ECDSASigner{Key: k}, l, slog.Default())
	if string(a.Signature) == string(b.Signature) { // ECDSA is randomized: equal means a cached copy
		t.Fatal("local key response was cached")
	}

	// A change at the same instant as the cached envelope is still signed
	// strictly newer, so pollers accept it.
	var c killSigCache
	rs := &countingRemote{ECDSASigner: bundle.ECDSASigner{Key: k}}
	first, _ := c.sign(ctx, rs, l, slog.Default())
	changed := l
	changed.Version, changed.Experiments = 2, []string{"x"}
	second, err := c.sign(ctx, rs, changed, slog.Default())
	if err != nil || rs.count() != 2 {
		t.Fatalf("change not re-signed: %v", err)
	}
	v := bundle.ECDSAVerifier{Key: &k.PublicKey}
	l1, _ := gateway.VerifyKillList(ctx, v, first, at, time.Minute)
	l2, err := gateway.VerifyKillList(ctx, v, second, at, time.Minute)
	if err != nil || !l2.IssuedAt.After(l1.IssuedAt) {
		t.Fatalf("same-instant change not strictly newer: %v %v", l1.IssuedAt, l2.IssuedAt)
	}
}
