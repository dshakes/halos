package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionEpoch(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir = dir })
	cookie := func(sub string) *http.Cookie {
		*e.now = e.now.Add(time.Second)
		return &http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: sub, Exp: e.now.Add(time.Hour).Unix(), Iat: e.now.UnixNano()})}
	}
	req := func(h http.Handler, method, path string, c *http.Cookie) int {
		r := httptest.NewRequest(method, path, nil)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	laptop, phone, other := cookie(dev.ID), cookie(dev.ID), cookie("other@acme.example")
	if c := req(e.h, "GET", "/api/v1/me", phone); c != 200 {
		t.Fatalf("fresh session: %d", c)
	}
	if c := req(e.h, "POST", "/auth/logout", laptop); c != 204 {
		t.Fatalf("logout: %d", c)
	}
	for name, c := range map[string]*http.Cookie{"logged-out cookie": laptop, "same user, other browser": phone} {
		if code := req(e.h, "GET", "/api/v1/me", c); code != 401 {
			t.Errorf("%s still valid: %d", name, code)
		}
	}
	if c := req(e.h, "GET", "/api/v1/me", other); c != 200 {
		t.Errorf("other user logged out too: %d", c)
	}
	again := cookie(dev.ID)
	if c := req(e.h, "GET", "/api/v1/me", again); c != 200 {
		t.Fatalf("new login after logout: %d", c)
	}
	adm := cookie(admin.ID)
	adm.Value = e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Add(time.Hour).Unix(), Iat: e.now.UnixNano()})
	if c := req(e.h, "POST", "/api/v1/users/"+dev.ID+"/revoke-sessions", again); c != 403 {
		t.Errorf("developer revoking sessions: %d", c)
	}
	if c := req(e.h, "POST", "/api/v1/users/"+dev.ID+"/revoke-sessions", adm); c != 204 {
		t.Fatalf("admin revoke: %d", c)
	}
	if c := req(e.h, "GET", "/api/v1/me", again); c != 401 {
		t.Errorf("admin-revoked session still valid: %d", c)
	}
	// Revocations survive a restart.
	s2, err := New(e.s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if c := req(s2.Handler(), "GET", "/api/v1/me", phone); c != 401 {
		t.Errorf("revoked session resurrected by restart: %d", c)
	}
	if c := req(s2.Handler(), "GET", "/api/v1/me", other); c != 200 {
		t.Errorf("other user after restart: %d", c)
	}
}

func TestDeviceTokenExpires(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.DeviceTTL = time.Hour })
	tok, d, err := e.s.devices.mint(dev, e.s.cfg.Now())
	if err != nil || !d.ExpiresAt.Equal(e.now.Add(time.Hour)) || !d.LastAuth.Equal(*e.now) {
		t.Fatalf("mint: %+v %v", d, err)
	}
	ring := func() *httptest.ResponseRecorder { return do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+tok, "") }
	if w := ring(); w.Code != 200 {
		t.Fatalf("fresh device: %d %s", w.Code, w.Body)
	}
	*e.now = e.now.Add(time.Hour)
	for range authFailBurst + 2 { // expired is not a guessing attempt: never rate limited
		if w := ring(); w.Code != 401 || !strings.Contains(w.Body.String(), "re-enroll") {
			t.Fatalf("expired device: %d %s", w.Code, w.Body)
		}
	}
	if w := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+tok, `{"hostname":"h"}`); w.Code != 401 {
		t.Errorf("expired device report: %d", w.Code)
	}
}

func TestAuthLimiterEvictsWithoutForgiving(t *testing.T) {
	var a authLimiter
	for range authFailBurst {
		a.fail("attacker")
	}
	if !a.blocked("attacker") || a.blocked("never-seen") || len(a.m) != 1 {
		t.Fatal("setup")
	}
	for i := range maxLimiters {
		a.fail(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if len(a.m) > maxLimiters {
		t.Fatalf("unbounded: %d", len(a.m))
	}
	if !a.blocked("attacker") {
		t.Fatal("eviction forgave a blocked IP")
	}
}
