package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// Break-glass lockout follow-up review (N1, N2).

// testBGCIDRs are the documentation ranges tests send from (httptest uses 192.0.2.1).
var testBGCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}

// TestBreakGlassRequiresCIDRs (N1): enabling break-glass without allowed
// ranges is refused at start; a sealed hash alone is fine.
func TestBreakGlassRequiresCIDRs(t *testing.T) {
	base := Config{PolicyDir: t.TempDir(), Token: "t", SessionKey: []byte(strings.Repeat("k", 32))}
	cfg := base
	cfg.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t)}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "allowed CIDRs") {
		t.Fatalf("enabled without CIDRs: %v", err)
	}
	cfg.BreakGlass = BreakGlass{Hash: testBreakGlassHash(t)}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("sealed without CIDRs: %v", err)
	}
	_ = s.Close()
}

// TestBreakGlassBroadCIDRs (L-b): ranges too broad to protect the lockout
// are refused at start (sealed or enabled); wide but accepted ones warn.
func TestBreakGlassBroadCIDRs(t *testing.T) {
	newWith := func(cidrs ...string) (string, error) {
		var buf bytes.Buffer
		var ps []netip.Prefix
		for _, c := range cidrs {
			ps = append(ps, netip.MustParsePrefix(c))
		}
		s, err := New(Config{PolicyDir: t.TempDir(), Token: "t", SessionKey: []byte(strings.Repeat("k", 32)), Log: slog.New(slog.NewTextHandler(&buf, nil)),
			BreakGlass: BreakGlass{Enabled: true, Hash: testBreakGlassHash(t), AllowedCIDRs: ps}})
		if err == nil {
			_ = s.Close()
		}
		return buf.String(), err
	}
	for _, c := range []struct {
		cidrs  []string
		refuse bool
		warn   bool
	}{
		{[]string{"0.0.0.0/0"}, true, false},
		{[]string{"10.8.0.0/16", "0.0.0.0/0"}, true, false},
		{[]string{"::/0"}, true, false},
		{[]string{"10.0.0.0/7"}, true, false},
		{[]string{"2001:db8::/31"}, true, false},
		{[]string{"10.0.0.0/8"}, false, true},
		{[]string{"10.16.0.0/12"}, false, true},
		{[]string{"2001:db8::/32"}, false, true},
		{[]string{"10.8.0.0/16", "2001:db8::/48", "192.0.2.10/32"}, false, false},
	} {
		log, err := newWith(c.cidrs...)
		if (err != nil) != c.refuse || (c.refuse && !strings.Contains(err.Error(), "too broad")) {
			t.Errorf("%v: err %v, want refused=%v", c.cidrs, err, c.refuse)
		}
		if got := strings.Contains(log, "CIDRs are wide"); !c.refuse && got != c.warn {
			t.Errorf("%v: warned=%v, want %v (%s)", c.cidrs, got, c.warn, log)
		}
	}
	// A sealed (not enabled) configuration is refused too: enabling must not be the first check.
	if _, err := New(Config{PolicyDir: t.TempDir(), Token: "t", SessionKey: []byte(strings.Repeat("k", 32)),
		BreakGlass: BreakGlass{Hash: testBreakGlassHash(t), AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}); err == nil {
		t.Fatal("sealed 0.0.0.0/0 accepted")
	}
}

// failCount is a shared Backend whose failure count can be made unreadable
// for one replica.
type failCount struct {
	*memShared
	fail *atomic.Bool
}

func (f failCount) CountAuthFailure(ctx context.Context, key string, w time.Duration) (int64, error) {
	if f.fail.Load() {
		return 0, errors.New("count unavailable")
	}
	return f.memShared.CountAuthFailure(ctx, key, w)
}

// TestBreakGlassUnlockStaleLocalCount (L-a): after an unlock on replica a,
// replica b whose shared-count read fails must not re-lock from a stale
// count of its own.
func TestBreakGlassUnlockStaleLocalCount(t *testing.T) {
	old := breakGlassGlobalFails
	breakGlassGlobalFails = 3
	t.Cleanup(func() { breakGlassGlobalFails = old })
	shared := newMemShared()
	var bFail atomic.Bool
	mk := func(be Backend) *env {
		return newEnv(t, func(c *Config) {
			c.Backend = be
			c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t), AllowedCIDRs: testBGCIDRs}
		})
	}
	a, b := mk(failCount{shared, new(atomic.Bool)}), mk(failCount{shared, &bFail})
	shared.Now = func() time.Time { return *a.now }
	for i := range 3 { // all on b: b's failures reach the budget and lock
		b.breakGlassFrom(fmt.Sprintf("198.51.100.%d", i+1), "breakglass", "wrong but long enough password")
	}
	if !a.s.breakGlassLocked() {
		t.Fatal("not locked")
	}
	if w := a.as(admin, "POST", "/api/v1/breakglass/unlock", ""); w.Code != 200 {
		t.Fatalf("unlock on a: %d", w.Code)
	}
	bFail.Store(true)
	b.breakGlassFrom("198.51.100.9", "breakglass", "wrong but long enough password")
	if b.s.breakGlassLocked() {
		t.Fatal("b re-locked from its own stale count after an unlock on a")
	}
	if w := b.breakGlassFrom("203.0.113.9", "breakglass", bgPassword); w.Code != http.StatusOK {
		t.Fatalf("correct password on b after unlock: %d", w.Code)
	}
}

// TestBreakGlassLockoutDoS (N1, the reviewer's proof ported): attackers
// outside the allowed range cannot move the global counter, so the correct
// password from an allowed address still works.
func TestBreakGlassLockoutDoS(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t), AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
	})
	for i := range 20 { // 20 attackers, one guess each
		if w := e.breakGlassFrom(fmt.Sprintf("203.0.113.%d", i+1), "breakglass", "wrong-password-wrong-password"); w.Code != http.StatusNotFound {
			t.Fatalf("outsider %d: %d", i, w.Code)
		}
	}
	if n := len(e.s.bgLock.fails); n != 0 {
		t.Fatalf("outsiders moved the global counter: %d", n)
	}
	if w := e.breakGlassFrom("198.51.100.7", "breakglass", bgPassword); w.Code != http.StatusOK {
		t.Fatalf("legit admin after 20 distributed outsider failures: %d %s", w.Code, w.Body)
	}
}

// TestBreakGlassUnlock (N1): an SSO admin lifts the lockout without the
// locked path, audited at high severity; tokens and non-admins cannot.
func TestBreakGlassUnlock(t *testing.T) {
	old := breakGlassGlobalFails
	breakGlassGlobalFails = 2
	t.Cleanup(func() { breakGlassGlobalFails = old })
	e := newEnv(t, func(c *Config) {
		c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t), AllowedCIDRs: testBGCIDRs}
	})
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		e.breakGlassFrom(ip, "breakglass", "wrong but long enough password")
	}
	if w := e.breakGlassFrom("198.51.100.9", "breakglass", bgPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("not locked: %d", w.Code)
	}
	tok, _ := e.mintToken(t, `{"name":"ops","role":"admin"}`)
	if w := e.bearer(tok, "POST", "/api/v1/breakglass/unlock", ""); w.Code != http.StatusForbidden {
		t.Fatalf("token unlocked: %d", w.Code)
	}
	if w := e.as(dev, "POST", "/api/v1/breakglass/unlock", ""); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin unlocked: %d", w.Code)
	}
	w := e.as(admin, "POST", "/api/v1/breakglass/unlock", "")
	if w.Code != 200 || !decode[map[string]bool](t, w)["wasLocked"] {
		t.Fatalf("unlock: %d %s", w.Code, w.Body)
	}
	u := auditBy(e.auditActions(t), admin.ID, "breakglass.unlock")
	if len(u) != 1 || u[0].Details["severity"] != "high" {
		t.Fatalf("unlock audit: %+v", u)
	}
	if w := e.breakGlassFrom("198.51.100.9", "breakglass", bgPassword); w.Code != http.StatusOK {
		t.Fatalf("after unlock: %d", w.Code)
	}
	// The count was reset: one more failure does not re-lock at once.
	e.breakGlassFrom("198.51.100.1", "breakglass", "wrong but long enough password")
	if e.s.breakGlassLocked() {
		t.Fatal("unlock did not reset the failure count")
	}
}

// TestBreakGlassLockoutAcrossReplicas (N2): the lock is shared, so every
// replica locks when the shared count crosses the budget, and exactly one
// lockout entry is audited.
func TestBreakGlassLockoutAcrossReplicas(t *testing.T) {
	old := breakGlassGlobalFails
	breakGlassGlobalFails = 3
	t.Cleanup(func() { breakGlassGlobalFails = old })
	shared := newMemShared()
	mk := func() *env {
		return newEnv(t, func(c *Config) {
			c.Backend = shared
			c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t), AllowedCIDRs: testBGCIDRs}
		})
	}
	a, b := mk(), mk()
	shared.Now = func() time.Time { return *a.now }
	a.breakGlassFrom("198.51.100.1", "breakglass", "wrong but long enough password")
	b.breakGlassFrom("198.51.100.2", "breakglass", "wrong but long enough password")
	a.breakGlassFrom("198.51.100.3", "breakglass", "wrong but long enough password") // third, on a: crosses
	for name, e := range map[string]*env{"a": a, "b": b} {
		if w := e.breakGlassFrom("203.0.113.9", "breakglass", bgPassword); w.Code != http.StatusTooManyRequests {
			t.Fatalf("replica %s not locked: %d", name, w.Code)
		}
	}
	b.breakGlassFrom("198.51.100.4", "breakglass", "wrong but long enough password") // past the budget on b: no second entry
	// A failure racing past the lock check on another replica must not audit a
	// second lockout: only the write that created the lock does.
	if b.s.breakGlassFailed() {
		t.Fatal("a second replica would audit the lockout again")
	}
	var n int
	for _, x := range a.auditActions(t) {
		if x.Action == "breakglass.lockout" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("lockout audited %d times across replicas, want once", n)
	}
	if w := b.as(admin, "POST", "/api/v1/breakglass/unlock", ""); w.Code != 200 {
		t.Fatalf("unlock on b: %d", w.Code)
	}
	if w := a.breakGlassFrom("203.0.113.9", "breakglass", bgPassword); w.Code != http.StatusOK {
		t.Fatalf("a still locked after unlock on b: %d", w.Code)
	}
}

// TestBreakGlassLockoutPostgres (N2): the same across real Postgres
// replicas, and unlock resets the shared count.
func TestBreakGlassLockoutPostgres(t *testing.T) {
	old := breakGlassGlobalFails
	breakGlassGlobalFails = 3
	t.Cleanup(func() { breakGlassGlobalFails = old })
	db, schema := pgtest.OpenTest(t)
	db2, _ := pgtest.OpenTest(t, schema)
	mk := func(b Backend) *env {
		e := newEnv(t, func(c *Config) {
			c.Backend = b
			c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t), AllowedCIDRs: testBGCIDRs}
		})
		*e.now = time.Now() // the database expires the lock on its own clock
		return e
	}
	a, b := mk(NewPGBackend(db)), mk(NewPGBackend(db2))
	for i, e := range []*env{a, b, a} {
		e.breakGlassFrom(fmt.Sprintf("198.51.100.%d", i+1), "breakglass", "wrong but long enough password")
	}
	if w := b.breakGlassFrom("203.0.113.9", "breakglass", bgPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("b not locked: %d", w.Code)
	}
	var n int
	for _, x := range a.auditActions(t) {
		if x.Action == "breakglass.lockout" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("lockout audited %d times, want once", n)
	}
	if w := a.as(admin, "POST", "/api/v1/breakglass/unlock", ""); w.Code != 200 {
		t.Fatalf("unlock: %d", w.Code)
	}
	b.breakGlassFrom("198.51.100.5", "breakglass", "wrong but long enough password")
	if b.s.breakGlassLocked() {
		t.Fatal("unlock did not reset the shared count")
	}
	if w := b.breakGlassFrom("203.0.113.9", "breakglass", bgPassword); w.Code != http.StatusOK {
		t.Fatalf("after unlock: %d", w.Code)
	}
}
