package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

// asH is env.as with extra request headers.
func (e *env) asH(p Principal, method, url, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if p.ID != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: p.ID, Groups: p.Groups, Exp: e.now.Add(time.Hour).Unix()})})
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func killEnv(t *testing.T) *env {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newEnv(t, func(c *Config) { c.KillKey, c.GatewayToken = priv, gwTok })
}

// Cookie-authenticated state changes are refused when the browser says the
// request is cross-site, by Origin or by Fetch Metadata (Sec-Fetch-Site),
// which a page on another site cannot forge.
func TestCSRFStateChangingRequests(t *testing.T) {
	e := newEnv(t, nil)
	body := `{"kind":"mcp-server","item":"jira","justification":"need it"}`
	for _, tc := range []struct {
		name string
		hdr  map[string]string
		ok   bool
	}{
		{"cli, no browser headers", nil, true},
		{"same origin", map[string]string{"Origin": "http://example.com", "Sec-Fetch-Site": "same-origin"}, true},
		{"cross origin", map[string]string{"Origin": "https://evil.example"}, false},
		{"opaque origin", map[string]string{"Origin": "null"}, false},
		{"sibling subdomain", map[string]string{"Origin": "https://evil.example.com"}, false},
		{"fetch metadata cross-site, no Origin", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"fetch metadata same-site, no Origin", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"fetch metadata cross-site, spoofed Origin", map[string]string{"Origin": "http://example.com", "Sec-Fetch-Site": "cross-site"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.s.reqs.mu.Lock()
			clear(e.s.reqs.byID)
			e.s.reqs.mu.Unlock()
			e.s.revoked.mu.Lock()
			clear(e.s.revoked.before) // the previous case's logout ended dev's sessions
			e.s.revoked.mu.Unlock()
			w := e.asH(dev, "POST", "/api/v1/requests", body, tc.hdr)
			if got := w.Code != http.StatusForbidden; got != tc.ok {
				t.Fatalf("POST /api/v1/requests: %d %s, want allowed=%v", w.Code, w.Body, tc.ok)
			}
			lw := e.asH(dev, "POST", "/auth/logout", "", tc.hdr)
			if got := lw.Code != http.StatusForbidden; got != tc.ok {
				t.Fatalf("POST /auth/logout: %d, want allowed=%v", lw.Code, tc.ok)
			}
		})
	}
	// Reads stay readable cross-site (no state change; CORS keeps the body from the page).
	if w := e.asH(dev, "GET", "/api/v1/me", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != 200 {
		t.Fatalf("GET cross-site: %d", w.Code)
	}
}

// Session and login-state cookies: HttpOnly, SameSite=Lax, scoped Path,
// bounded MaxAge, and Secure whenever the portal is served over https.
func TestCookieAttributes(t *testing.T) {
	o := newOIDCEnv(t, "[platform-admins]")
	o.iss.SetLogin(map[string]any{"email": "boss@acme.example", "email_verified": true})
	sc, back := o.login(t)
	w := o.callback(sc, back)
	c := cookieOf(w, sessionCookie)
	if w.Code != http.StatusFound || c == nil {
		t.Fatalf("callback: %d", w.Code)
	}
	for _, tc := range []struct {
		c      *http.Cookie
		path   string
		maxAge int
	}{{sc, "/auth", 600}, {c, "/", int(sessionTTL.Seconds())}} {
		if !tc.c.HttpOnly || !tc.c.Secure || tc.c.SameSite != http.SameSiteLaxMode || tc.c.Path != tc.path || tc.c.MaxAge != tc.maxAge {
			t.Errorf("cookie %s = %+v, want HttpOnly Secure Lax Path=%s MaxAge=%d", tc.c.Name, tc.c, tc.path, tc.maxAge)
		}
	}
	// Loopback http portal (local dev): Secure would make the browser drop it.
	plain := newEnv(t, func(c *Config) { c.Portal.BaseURL = "http://127.0.0.1:8080" })
	rw := httptest.NewRecorder()
	plain.s.setCookie(rw, sessionCookie, "v", "/", sessionTTL)
	if pc := cookieOf(rw, sessionCookie); pc == nil || pc.Secure || !pc.HttpOnly || pc.SameSite != http.SameSiteLaxMode {
		t.Fatalf("http cookie = %+v", pc)
	}
}

// Failed enrollments are rate limited per client IP like every other token
// endpoint, and a blocked attempt does not burn a valid token.
func TestEnrollRateLimited(t *testing.T) {
	e := newEnv(t, nil)
	enroll := func(tok string) int {
		return do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`).Code
	}
	for i := 0; i < authFailBurst; i++ {
		if c := enroll("guess"); c != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d", i, c)
		}
	}
	if c := enroll("guess"); c != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: %d, want 429", authFailBurst, c)
	}
	good := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	if c := enroll(good); c != http.StatusTooManyRequests {
		t.Fatalf("blocked IP with a valid token: %d, want 429", c)
	}
	e.s.enroll.mu.Lock()
	_, kept := e.s.enroll.m[hashTok(good)]
	e.s.enroll.mu.Unlock()
	if !kept {
		t.Fatal("a rate-limited attempt burned a valid enrollment token")
	}
	// Another client is unaffected.
	r := httptest.NewRequest("POST", "/api/v1/enroll", strings.NewReader(`{"token":"`+good+`"}`))
	r.RemoteAddr = "198.51.100.7:1234"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("other client: %d %s", w.Code, w.Body)
	}
}

// Failed logins (OIDC callbacks) are rate limited per IP, with their own
// budget: a burst of bad callbacks from an office NAT must not lock its
// devices out of /fleet endpoints.
func TestLoginCallbackRateLimited(t *testing.T) {
	e := newEnv(t, nil)
	dt := enrollDevice(t, e, dev)
	for i := 0; i < authFailBurst; i++ {
		if c := do(e.h, "GET", "/auth/callback?state=x&code=y", "", "").Code; c != http.StatusBadRequest {
			t.Fatalf("bad callback %d: %d", i, c)
		}
	}
	if c := do(e.h, "GET", "/auth/callback?state=x&code=y", "", "").Code; c != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: %d, want 429", authFailBurst, c)
	}
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 200 {
		t.Fatalf("device auth from the same IP: %d, want 200 (separate budget)", c)
	}
}

// The gateway kill-list token is rate limited per IP on failure; a client
// that keeps guessing is refused even with the right token until it cools down.
func TestGatewayKillswitchRateLimited(t *testing.T) {
	_, h, _ := newKillServer(t, true)
	for i := 0; i < authFailBurst; i++ {
		if c := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer guess-0123456789abcdef", "").Code; c != 401 {
			t.Fatalf("guess %d: %d", i, c)
		}
	}
	for _, auth := range []string{"Bearer guess-0123456789abcdef", "Bearer " + gwTok} {
		if c := do(h, "GET", "/api/v1/gateway/killswitch", auth, "").Code; c != http.StatusTooManyRequests {
			t.Fatalf("%q after burst: %d, want 429", auth[:12], c)
		}
	}
	r := httptest.NewRequest("GET", "/api/v1/gateway/killswitch", nil)
	r.RemoteAddr = "198.51.100.7:1234"
	r.Header.Set("Authorization", "Bearer "+gwTok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("other gateway: %d", w.Code)
	}
}

// Every JSON endpoint bounds its request body: an oversized body is refused
// before the handler acts on it.
func TestJSONBodySizeLimits(t *testing.T) {
	e := killEnv(t)
	pad := func(n int) string { return strings.Repeat("x", n) }
	for _, tc := range []struct {
		path, auth, body string
		admin            bool
	}{
		{"/api/v1/fleet/report", "Bearer " + tok, `{"hostname":"h","lastError":"` + pad(MaxReportBytes) + `"}`, false},
		{"/api/v1/enroll", "", `{"token":"` + pad(4096) + `"}`, false},
		{"/api/v1/experiments/opus-5-5-canary/kill", "", `{"reason":"r","x":"` + pad(2048) + `"}`, true},
		{"/api/v1/experiments/opus-5-5-canary/unkill", "", `{"reason":"r","x":"` + pad(2048) + `"}`, true},
		{"/api/v1/toggles/github-mcp/kill", "", `{"reason":"r","x":"` + pad(2048) + `"}`, true},
		{"/api/v1/toggles/github-mcp/propose", "", `{"reason":"r","x":"` + pad(8192) + `"}`, true},
		{"/api/v1/requests", "", `{"kind":"mcp-server","item":"jira","justification":"j","x":"` + pad(8192) + `"}`, false},
		{"/api/v1/experiments/opus-5-5-canary/status", "", `{"status":"paused","x":"` + pad(1024) + `"}`, true},
	} {
		t.Run(tc.path, func(t *testing.T) {
			p := Principal{}
			switch {
			case tc.admin:
				p = admin
			case tc.auth == "" && tc.path != "/api/v1/enroll":
				p = dev
			}
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
			if p.ID != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: p.ID, Groups: p.Groups, Exp: e.now.Add(time.Hour).Unix()})})
			}
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			e.h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge && w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("oversized body: %d %s, want 400/413/422", w.Code, w.Body)
			}
		})
	}
	if recs, _, err := e.s.kills.Killed(); err != nil || len(recs) != 0 {
		t.Fatalf("oversized kill acted: %v %v", recs, err)
	}
	if n := len(e.s.cfg.Store.All()); n != 0 {
		t.Fatalf("oversized report stored: %d hosts", n)
	}
	if n := len(e.w.calls); n != 0 {
		t.Fatalf("oversized body reached the policy writer: %d calls", n)
	}
}

// Credentials (fleet, gateway, enrollment and device tokens, session cookies,
// failed guesses) never reach the log, and no API response other than the one
// that issues a credential carries it, even hashed.
func TestSecretsNeverLoggedOrReturned(t *testing.T) {
	var logs bytes.Buffer
	e := killEnv(t)
	e.s.cfg.Log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const guess = "guessed-token-LEAKCANARY"

	lt := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	ew := do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+lt+`"}`)
	m := devTokRe.FindStringSubmatch(ew.Body.String())
	if ew.Code != 200 || m == nil {
		t.Fatalf("enroll: %d %s", ew.Code, ew.Body)
	}
	dt := m[1]
	var devID string
	for _, d := range e.s.devices.list() {
		devID = d.ID
	}
	cookie := e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Add(time.Hour).Unix()})

	var bodies []string
	call := func(p Principal, method, url, auth, body string) {
		t.Helper()
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		if p.ID != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		}
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		bodies = append(bodies, url+" "+w.Body.String()+" "+strings.Join(w.Header().Values("Set-Cookie"), ";"))
	}
	call(Principal{}, "POST", "/api/v1/fleet/report", "Bearer "+dt, report("h1", "", "", false))
	call(Principal{}, "POST", "/api/v1/fleet/report", "Bearer "+tok, report("h2", "", "", false))
	call(Principal{}, "POST", "/api/v1/fleet/report", "Bearer "+guess, report("h3", "", "", false))
	call(Principal{}, "GET", "/api/v1/fleet/ring", "Bearer "+guess, "")
	call(Principal{}, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
	call(Principal{}, "GET", "/api/v1/gateway/killswitch", "Bearer "+guess, "")
	call(Principal{}, "POST", "/api/v1/enroll", "", `{"token":"`+lt+`"}`) // replay
	call(Principal{}, "POST", "/api/v1/enroll", "", `{"token":"`+guess+`"}`)
	call(admin, "POST", "/api/v1/experiments/opus-5-5-canary/kill", "", `{"reason":"r"}`)
	for _, u := range []string{"/api/v1/devices", "/api/v1/devices/" + devID, "/api/v1/audit", "/api/v1/fleet", "/api/v1/me",
		"/api/v1/policy", "/api/v1/capabilities", "/api/v1/killswitch", "/api/v1/requests", "/api/v1/catalog", "/api/v1/whoami?user=x"} {
		call(admin, "GET", u, "", "")
	}
	call(admin, "POST", "/api/v1/devices/"+devID+"/revoke", "", "")
	call(admin, "POST", "/auth/logout", "", "")

	secrets := map[string]string{
		"device token": dt, "device token hash": hashDeviceToken(dt), "enrollment token": lt, "gateway token": gwTok,
		"fleet token": tok, "failed guess": guess, "session cookie": cookie, "session key": string(e.s.cfg.SessionKey),
	}
	for name, v := range secrets {
		if strings.Contains(logs.String(), v) {
			t.Errorf("%s in logs", name)
		}
		for _, b := range bodies {
			if strings.Contains(b, v) {
				t.Errorf("%s in response %.60s", name, b)
			}
		}
	}
}

// An audit field with invalid UTF-8 (here a percent-encoded path segment)
// must not make the chain fail verification: the hash has to survive the
// JSON round trip, or one request turns every later check into a false alarm.
func TestAuditInvalidUTF8StaysVerifiable(t *testing.T) {
	for _, dir := range []string{"", t.TempDir()} {
		e := newEnv(t, func(c *Config) { c.DataDir = dir })
		if w := e.as(admin, "POST", "/api/v1/users/%FF%FEx/revoke-sessions", ""); w.Code != http.StatusNoContent {
			t.Fatalf("revoke: %d %s", w.Code, w.Body)
		}
		e.as(admin, "POST", "/api/v1/users/bob/revoke-sessions", "")
		got := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit", ""))
		if !got.Verified || got.Total != 2 {
			t.Fatalf("data dir %q: verified=%v total=%d: %s", dir, got.Verified, got.Total, got.VerifyError)
		}
	}
}

// Privileged actions fail closed when the audit append fails (HTTP 500): a
// kill stays applied, an unkill is reverted, enrollment hands out no device
// token, and a device revocation stays in force.
func TestPrivilegedActionsFailClosedOnAudit(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *Config) { c.DataDir, c.KillKey, c.GatewayToken = t.TempDir(), priv, gwTok })
	dt := enrollDevice(t, e, dev)
	if w := e.as(admin, "POST", "/api/v1/toggles/github-mcp/kill", `{"reason":"r"}`); w.Code != 200 {
		t.Fatalf("setup kill: %d", w.Code)
	}
	lt := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	_ = e.s.auditLog.f.Close() // every append now errors

	killed := func(key string) bool {
		recs, _, err := e.s.kills.Killed()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if r.Experiment == key {
				return true
			}
		}
		return false
	}
	if w := e.as(admin, "POST", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"r"}`); w.Code != 500 || !killed("opus-5-5-canary") {
		t.Fatalf("kill: %d, killed=%v; want 500 and the kill applied", w.Code, killed("opus-5-5-canary"))
	}
	if w := e.as(admin, "POST", "/api/v1/toggles/github-mcp/unkill", `{"reason":"r"}`); w.Code != 500 || !killed(toggleKillPrefix+"github-mcp") {
		t.Fatalf("unkill: %d; want 500 and the unkill reverted", w.Code)
	}
	if w := do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+lt+`"}`); w.Code != 500 || strings.Contains(w.Body.String(), "deviceToken") {
		t.Fatalf("enroll: %d %s; want 500 without a credential", w.Code, w.Body)
	}
	e.s.devices.mu.Lock()
	id := e.s.devices.byHash[hashDeviceToken(dt)].ID // the failed enrollment left an orphan (token never issued)
	e.s.devices.mu.Unlock()
	if w := e.as(admin, "POST", "/api/v1/devices/"+id+"/revoke", ""); w.Code != 500 {
		t.Fatalf("revoke: %d, want 500", w.Code)
	}
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 401 {
		t.Fatalf("revoked device still authenticates: %d", c)
	}
	if w := e.as(admin, "POST", "/api/v1/experiments/opus-5-5-canary/status", `{"status":"paused"}`); w.Code != 500 {
		t.Fatalf("experiment status: %d, want 500", w.Code)
	}
}

// The gateway kill list is served only with both the key and the token, and
// its signature is domain-separated (never a bare signature over the payload).
func TestGatewayKillswitchConfigAndDomain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key ed25519.PrivateKey
		tok string
	}{{priv, ""}, {nil, gwTok}, {nil, ""}} {
		e := newEnv(t, func(cfg *Config) { cfg.KillKey, cfg.GatewayToken = c.key, c.tok })
		if w := do(e.h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, ""); w.Code != 404 {
			t.Fatalf("key=%v token=%q: %d, want 404", c.key != nil, c.tok, w.Code)
		}
	}
	e := newEnv(t, func(cfg *Config) { cfg.KillKey, cfg.GatewayToken = priv, gwTok })
	w := do(e.h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
	env := decode[gateway.KillEnvelope](t, w)
	if _, err := gateway.VerifyKillList(pub, env, *e.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, env.Payload, env.Signature) {
		t.Fatal("kill-list signature is not domain-separated")
	}
}
