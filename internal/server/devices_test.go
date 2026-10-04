package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var devTokRe = regexp.MustCompile(`deviceToken: ["']?([A-Za-z0-9_-]+)`)

// enrollDevice runs the portal flow and returns the minted device token.
func enrollDevice(t testing.TB, e *env, p Principal) string {
	t.Helper()
	lt := decode[Launch](t, e.as(p, "POST", "/api/v1/launch/laptop", "")).Token
	w := do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+lt+`"}`)
	m := devTokRe.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	return m[1]
}

func TestDeviceFlow(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir = dir })
	dt := enrollDevice(t, e, dev)

	// ring endpoint: live from policy for the bound user
	want := decode[Me](t, e.as(dev, "GET", "/api/v1/me", "")).Ring
	w := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "")
	if got := decode[map[string]string](t, w); w.Code != 200 || got["ring"] != want || got["subject"] != dev.ID {
		t.Fatalf("ring: %d %s want ring %q subject %q", w.Code, w.Body.String(), want, dev.ID)
	}
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+tok, "").Code; c != 401 { // fleet token is not a device token
		t.Errorf("fleet token on ring endpoint: %d", c)
	}

	// report: user/device forced from binding, payload claims ignored
	body := `{"hostname":"lap1","user":"victim@acme.example","ring":"r","digest":"d"}`
	if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+dt, body).Code; c != 204 {
		t.Fatalf("device report: %d", c)
	}
	hosts := e.s.cfg.Store.All()
	if len(hosts) != 1 || hosts[0].User != dev.ID || hosts[0].Device == "" {
		t.Fatalf("stored report not forced from binding: %+v", hosts)
	}
	// fleet token still works and keeps payload identity
	if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+tok, `{"hostname":"ci1","user":"ci"}`).Code; c != 204 {
		t.Errorf("fleet token report: %d", c)
	}

	// admin list has no hash; developers cannot list/revoke
	if c := e.as(dev, "GET", "/api/v1/devices", "").Code; c != 403 {
		t.Errorf("dev list devices: %d", c)
	}
	lw := e.as(admin, "GET", "/api/v1/devices", "")
	if strings.Contains(lw.Body.String(), "hash") {
		t.Errorf("hash leaked: %s", lw.Body.String())
	}
	devs := decode[[]Device](t, lw)
	if len(devs) != 1 || devs[0].UserID != dev.ID {
		t.Fatalf("devices: %+v", devs)
	}

	// hashed only at rest: neither memory nor disk holds the token
	b, err := os.ReadFile(filepath.Join(dir, "devices.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), dt) || !strings.Contains(string(b), hashDeviceToken(dt)) {
		t.Fatalf("token must be stored as sha256 only: %s", b)
	}

	// revoke -> rejected everywhere, and persists across restart
	if c := e.as(dev, "POST", "/api/v1/devices/"+devs[0].ID+"/revoke", "").Code; c != 403 {
		t.Errorf("dev revoke: %d", c)
	}
	if c := e.as(admin, "POST", "/api/v1/devices/nope/revoke", "").Code; c != 404 {
		t.Errorf("revoke unknown: %d", c)
	}
	if c := e.as(admin, "POST", "/api/v1/devices/"+devs[0].ID+"/revoke", "").Code; c != 204 {
		t.Fatalf("revoke: %d", c)
	}
	for _, c := range []int{do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code, do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+dt, body).Code} {
		if c != 401 {
			t.Errorf("revoked token accepted: %d", c)
		}
	}
	e2 := newEnv(t, func(c *Config) { c.DataDir = dir })
	if c := do(e2.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 401 {
		t.Errorf("revocation lost on restart: %d", c)
	}
}

func TestDeviceTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir = dir })
	dt := enrollDevice(t, e, dev)
	e2 := newEnv(t, func(c *Config) { c.DataDir = dir })
	if c := do(e2.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 200 {
		t.Errorf("token lost on restart: %d", c)
	}
}

func TestFailedAuthRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	dt := enrollDevice(t, e, dev) // before the burst: enrollment shares the per-IP failure budget
	for i := 0; i < authFailBurst; i++ {
		if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+"bad", "").Code; c != 401 {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+"bad", "").Code; c != 429 {
		t.Errorf("want 429 after burst, got %d", c)
	}
	// even a valid token from the blocked IP is throttled; other IPs are unaffected
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 429 {
		t.Errorf("blocked IP got %d", c)
	}
	r := httptestReq(dt)
	r.RemoteAddr = "203.0.113.9:1234"
	if w := serve(e, r); w.Code != 200 {
		t.Errorf("other IP got %d", w.Code)
	}
}

func TestDeviceStoreDupOnJSON(t *testing.T) { // Device JSON never carries a hash when listed
	b, _ := json.Marshal(Device{ID: "x"})
	if strings.Contains(string(b), "hash") {
		t.Error(string(b))
	}
}

func httptestReq(bearer string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/fleet/ring", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	return r
}

func serve(e *env, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// A device reporting another machine's hostname (or a fleet-token client
// claiming a device id) must not overwrite that machine's row.
func TestDeviceCannotOverwriteOtherHost(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir, c.Store = dir, mustOpen(t, dir) })
	a, b := enrollDevice(t, e, dev), enrollDevice(t, e, dev)
	report := func(auth, body string) {
		t.Helper()
		if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+auth, body).Code; c != 204 {
			t.Fatalf("report: %d", c)
		}
	}
	da, _ := e.s.devices.lookup(a, e.s.cfg.Now())
	report(a, `{"hostname":"lap1","ring":"ga","digest":"good"}`)
	report(b, `{"hostname":"lap1","ring":"ga","digest":"evil"}`)
	report(tok, `{"hostname":"lap1","device":"`+da.ID+`","digest":"fleet"}`)
	live := e.s.cfg.Store
	for i := 0; i < 2; i++ { // live, then replayed from disk
		s := live
		if i == 1 {
			_ = live.(io.Closer).Close() // reopening compacts via rename, which Windows refuses over an open file
			s = mustOpen(t, dir)
		}
		hosts := s.All()
		digests := map[string]string{}
		for _, h := range hosts {
			digests[h.Device] = h.Digest
		}
		if len(hosts) != 3 || digests[da.ID] != "good" || digests[""] != "fleet" {
			t.Fatalf("rows overwritten: %+v", hosts)
		}
	}
}

func mustOpen(t *testing.T, dir string) Store {
	t.Helper()
	s, err := OpenLogStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.(io.Closer).Close() }) // Windows cannot delete an open file
	return s
}

func TestClientIPTrustedProxies(t *testing.T) {
	s := &Server{cfg: Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")}}}
	tests := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"no proxy: XFF ignored", "203.0.113.9:1", []string{"1.2.3.4"}, "203.0.113.9"},
		{"trusted proxy: client from XFF", "10.0.0.5:1", []string{"198.51.100.7"}, "198.51.100.7"},
		{"spoofed left entries ignored", "10.0.0.5:1", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"chain of trusted hops", "10.0.0.5:1", []string{"198.51.100.7", "10.1.1.1"}, "198.51.100.7"},
		{"garbage after trusted", "10.0.0.5:1", []string{"not-an-ip"}, "10.0.0.5"},
		{"all trusted", "10.0.0.5:1", []string{"10.2.2.2"}, "10.2.2.2"},
		{"ipv6 proxy", "[::1]:1", []string{"2001:db8::1"}, "2001:db8::1"},
		{"no XFF", "10.0.0.5:1", nil, "10.0.0.5"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remote
		for _, v := range tt.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := s.clientIP(r); got != tt.want {
			t.Errorf("%s: got %s want %s", tt.name, got, tt.want)
		}
	}
}

// Rate limiting follows the XFF client only behind a trusted proxy.
func TestRateLimitBehindProxy(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")} })
	for i := 0; i <= authFailBurst; i++ {
		r := httptestReq("bad")
		r.RemoteAddr = "192.0.2.1:1"
		r.Header.Set("X-Forwarded-For", "198.51.100.1")
		serve(e, r)
	}
	blocked := httptestReq("bad")
	blocked.RemoteAddr = "192.0.2.1:1"
	blocked.Header.Set("X-Forwarded-For", "198.51.100.1")
	if c := serve(e, blocked).Code; c != 429 {
		t.Fatalf("attacker behind proxy not limited: %d", c)
	}
	other := httptestReq("bad")
	other.RemoteAddr = "192.0.2.1:1"
	other.Header.Set("X-Forwarded-For", "198.51.100.2")
	if c := serve(e, other).Code; c != 401 {
		t.Fatalf("other client behind same proxy throttled: %d", c)
	}
}
