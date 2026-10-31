package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
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
	return newEnv(t, func(c *Config) { c.KillKey, c.GatewayToken = bundle.Ed25519Signer{Key: priv}, gwTok })
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
	gh := hashTok(good)
	_, kept, _ := e.s.kv.Get(context.Background(), kvEnroll, hex.EncodeToString(gh[:]))
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

// Failed-auth budgets are per endpoint class: garbage sent to the public
// token exchange and SCIM endpoints from an IP a gateway shares exhausts only
// those classes, never the gateway token (directory, posture, budget, kill
// list) or device endpoints. Otherwise anyone could cut a gateway off from its
// directory and force its fail mode.
func TestAuthLockoutIsPerEndpointClass(t *testing.T) {
	e := scimEnv(t, false, func(c *Config) {
		_, c.WorkloadKey, _ = ed25519.GenerateKey(rand.Reader)
		f := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, "workloads:\n  audience: halos\n  issuers: [{name: github, url: https://token.actions.githubusercontent.com}]\n"+
			"  rules: [{name: r, issuer: github, match: {repository_owner_id: \"42\"}, subject: 'workload:gh:{repository}'}]\n"...)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	dt := enrollDevice(t, e, dev)
	exchange := func() int {
		r := httptest.NewRequest("POST", "/api/v1/token/exchange", strings.NewReader(exchangeForm("a.b.c").Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < authFailBurst; i++ {
		if c := exchange(); c != http.StatusBadRequest {
			t.Fatalf("garbage exchange %d: %d", i, c)
		}
		if c := e.scimAs("Bearer wrong", "GET", "/scim/v2/Users", "").Code; c != http.StatusUnauthorized {
			t.Fatalf("bad SCIM token %d: %d", i, c)
		}
	}
	if c := exchange(); c != http.StatusTooManyRequests {
		t.Fatalf("exchange after burst: %d, want 429", c)
	}
	if c := e.scimAs("Bearer wrong", "GET", "/scim/v2/Users", "").Code; c != http.StatusTooManyRequests {
		t.Fatalf("SCIM after burst: %d, want 429", c)
	}
	if c := do(e.h, "GET", "/api/v1/gateway/directory?subject=dev@acme.example", "Bearer "+gwTok, "").Code; c != 200 {
		t.Fatalf("gateway directory from the same IP: %d, want 200 (separate budget)", c)
	}
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 200 {
		t.Fatalf("device auth from the same IP: %d, want 200 (separate budget)", c)
	}
}

// halo-server enforces the security validation itself on every policy load:
// a reload whose workload rule pins no tenant (or whose unit loosens the
// baseline) is refused, loudly and counted, and the last good policy keeps
// serving; with no good policy yet, nothing is served.
func TestPolicyLoadRefusesSecurityErrors(t *testing.T) {
	e := newWorkloadEnv(t, true)
	if org, _, err := e.s.pol.Get(); org == nil || err != nil {
		t.Fatalf("fixture: %v", err)
	}
	f := filepath.Join(e.dir, "halos.yaml")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(b), `match: {repository: "acme/*", ref: refs/heads/main}`, `match: {ref: refs/heads/main}`, 1)
	if bad == string(b) {
		t.Fatal("fixture changed")
	}
	if err := os.WriteFile(f, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	e.s.ReloadPolicy()
	org, _, err := e.s.pol.Get()
	if err == nil || !strings.Contains(err.Error(), "pins no tenant") {
		t.Fatalf("unpinned workload rule activated: err %v", err)
	}
	// The last good policy keeps serving, minus the rule the refused policy
	// changed: a modification is never applied, but the old rule is gone from
	// it, so it stops matching (TestRefusedPolicyStillRemovesWorkloadRules).
	if org == nil || org.Workloads == nil || org.Gateway == nil || ruleFor(org, "acme/app") != "" {
		t.Fatalf("last good policy not kept, or the changed rule still in effect: %+v", org)
	}
	var m bytes.Buffer
	e.s.WriteMetrics(&m)
	if !strings.Contains(m.String(), "halo_server_policy_refused_total 1\n") {
		t.Fatalf("refusal not counted:\n%s", m.String())
	}
	// A fresh server with only the bad policy serves none.
	s, err := New(Config{PolicyDir: e.dir, Token: tok, SessionKey: []byte(strings.Repeat("k", 32)), Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if org, _, err := s.pol.Get(); org != nil || err == nil {
		t.Fatalf("bad policy activated on a fresh server: %v", err)
	}
}

// With no policy loaded, unauthenticated endpoints answer a generic error:
// the load error quotes policy content (rule names, match values, paths),
// which an anonymous caller must not read. It is logged instead.
func TestPolicyLoadErrorNotLeaked(t *testing.T) {
	e := newWorkloadEnv(t, true)
	f := filepath.Join(e.dir, "halos.yaml")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	secret := "refs/heads/secret-release-train"
	bad := strings.Replace(string(b), `match: {repository: "acme/*", ref: refs/heads/main}`, `match: {ref: `+secret+`}`, 1)
	if err := os.WriteFile(f, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s, err := New(Config{PolicyDir: e.dir, Token: tok, SessionKey: []byte(strings.Repeat("k", 32)), WorkloadKey: key,
		Log: slog.New(slog.NewTextHandler(&logs, nil)), Portal: Portal{BaseURL: "https://halo.example"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	h := s.Handler()
	for _, c := range []struct{ method, path, body, ctype string }{
		{"GET", "/readyz", "", ""},
		{"GET", "/auth/login", "", ""},
		{"POST", "/api/v1/token/exchange", exchangeForm("a.b.c").Encode(), "application/x-www-form-urlencoded"},
		{"POST", "/api/v1/agents/egress", `{"agent":"x"}`, "application/json"},
	} {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		if c.ctype != "" {
			r.Header.Set("Content-Type", c.ctype)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d %s, want 503 (or 401 before the policy is read)", c.method, c.path, w.Code, w.Body)
		}
		for _, leak := range []string{secret, "pins no tenant", "main-branch", e.dir} {
			if strings.Contains(w.Body.String(), leak) {
				t.Errorf("%s %s leaks %q: %s", c.method, c.path, leak, w.Body)
			}
		}
	}
	if !strings.Contains(logs.String(), "pins no tenant") {
		t.Errorf("the load error is not logged:\n%s", logs.String())
	}
}

// An unrelated security error (a unit typo) refuses the policy, but cannot
// block the emergency removal of a compromised workload rule: the rules in
// effect become the last good rules still present, unchanged, in the refused
// policy. Its additions and modifications are not applied. Logged, counted,
// and seen by Server.Policy (the HA controller's path) as well as the API.
func TestRefusedPolicyStillRemovesWorkloadRules(t *testing.T) {
	e := newWorkloadEnv(t, true)
	f := filepath.Join(e.dir, "halos.yaml")
	write := func(rules string) {
		t.Helper()
		root := fmt.Sprintf(`org: acme-corp
workloads:
  audience: halos
  issuers:
    - {name: github, url: %q, tenantClaim: repository}
  rules:
%s`, e.iss.URL, rules)
		if err := os.WriteFile(f, []byte(root), 0o600); err != nil {
			t.Fatal(err)
		}
		e.s.ReloadPolicy()
	}
	const compromised = `    - {name: compromised, issuer: github, match: {repository: "acme/app"}, subject: "workload:gh:{repository}"}
`
	const kept = `    - {name: kept, issuer: github, match: {repository: "acme/tools"}, subject: "workload:gh:{repository}"}
`
	write(compromised + kept)
	if org, _, err := e.s.pol.Get(); err != nil || len(org.Workloads.Rules) != 2 {
		t.Fatalf("fixture: %v", err)
	}
	// The emergency change removes "compromised", adds "new" and widens
	// "kept"; an unrelated unit typo makes the whole policy fail validation.
	unit := filepath.Join(e.dir, "units", "payments", "checkout", "unit.yaml")
	ub, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, bytes.Replace(ub, []byte("parent: payments"), []byte("parent: paymnets"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	write(`    - {name: kept, issuer: github, match: {repository: "acme/*"}, subject: "workload:gh:{repository}"}
    - {name: new, issuer: github, match: {repository: "acme/new"}, subject: "workload:gh:{repository}"}
`)
	org, _, err := e.s.pol.Get()
	if err == nil || !strings.Contains(err.Error(), "units") {
		t.Fatalf("policy with a unit typo was not refused: %v", err)
	}
	if org == nil || org.Workloads == nil || ruleFor(org, "acme/app") != "" || ruleFor(org, "acme/tools") != "" || ruleFor(org, "acme/new") != "" {
		t.Fatalf("rules in effect %+v, want none matching: compromised removed, kept changed (not applied), new added (not applied)", org.Workloads)
	}
	// The exchange stops minting for the removed rule at once.
	if w := e.post(exchangeForm(e.mint(t)), ""); w.Code != http.StatusBadRequest {
		t.Fatalf("exchange for the removed rule: %d %s, want 400", w.Code, w.Body)
	}
	if hp, err := e.s.Policy(); err != nil || ruleFor(hp, "acme/app") != "" {
		t.Fatalf("Server.Policy (controller path) still has the removed rule: %+v %v", hp, err)
	}

	// Removing only "compromised" keeps "kept" unchanged in effect.
	write(compromised + kept)
	if org, _, err := e.s.pol.Get(); err == nil || ruleFor(org, "acme/app") != "compromised" || ruleFor(org, "acme/tools") != "kept" {
		t.Fatalf("still refused (unit typo), back to the last good rules: %+v %v", org.Workloads, err)
	}
	write(kept)
	org, _, _ = e.s.pol.Get()
	if ruleFor(org, "acme/app") != "" || ruleFor(org, "acme/tools") != "kept" {
		t.Fatalf("rules in effect %+v, want only kept", org.Workloads.Rules)
	}
	var m bytes.Buffer
	e.s.WriteMetrics(&m)
	for _, want := range []string{"halo_server_policy_tightened_total 2\n", "halo_server_policy_refused_total 3\n", "halo_server_workload_rules_skipped 0\n"} {
		if !strings.Contains(m.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, m.String())
		}
	}
}

// A user id compares the same way everywhere (canonicalUser): an IdP that
// sends "Boss@Acme.example" on one login and "boss@acme.example" on another
// cannot approve their own access request, and keeps their own requests,
// devices and whoami self view.
func TestUserIDsCompareCanonically(t *testing.T) {
	e := newEnv(t, nil)
	upper := Principal{ID: " Boss@ACME.example", Groups: admin.Groups}
	rq := decode[Request](t, e.as(upper, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"please"}`))
	if w := e.as(admin, "POST", "/api/v1/requests/"+rq.ID+"/approve", ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "your own request") {
		t.Fatalf("self-approval under another case: %d %s", w.Code, w.Body)
	}
	if c := e.as(admin, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"again"}`).Code; c != http.StatusConflict {
		t.Fatalf("duplicate pending request under another case: %d, want 409", c)
	}
	devUpper := Principal{ID: "DEV@acme.example"}
	rq = decode[Request](t, e.as(dev, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"please"}`))
	if mine := decode[[]Request](t, e.as(devUpper, "GET", "/api/v1/requests", "")); len(mine) != 1 || mine[0].ID != rq.ID {
		t.Fatalf("own requests under another case: %+v", mine)
	}
	if c := e.as(devUpper, "GET", "/api/v1/whoami?user=dev@acme.example", "").Code; c != 200 {
		t.Fatalf("whoami self under another case: %d", c)
	}
	enrollDevice(t, e, dev)
	if w := e.as(devUpper, "GET", "/api/v1/me/devices", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"id"`) {
		t.Fatalf("own devices under another case: %d %s", w.Code, w.Body)
	}
	if !sameUser("Alice@Corp.com ", "alice@corp.com") || sameUser("alice", "alice2") {
		t.Fatal("sameUser")
	}
}

// The gateway kill-list token is rate limited per IP on failure; a client
// that keeps guessing is refused, but a gateway presenting the valid token
// from the same (shared egress) IP is not locked out by someone else's noise.
func TestGatewayKillswitchRateLimited(t *testing.T) {
	_, h, _ := newKillServer(t, true)
	for i := 0; i < authFailBurst; i++ {
		if c := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer guess-0123456789abcdef", "").Code; c != 401 {
			t.Fatalf("guess %d: %d", i, c)
		}
	}
	if c := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer guess-0123456789abcdef", "").Code; c != http.StatusTooManyRequests {
		t.Fatalf("guess after burst: %d, want 429", c)
	}
	if c := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "").Code; c != 200 {
		t.Fatalf("valid gateway token from the blocked IP: %d, want 200", c)
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
	e := newEnv(t, func(c *Config) {
		c.DataDir, c.KillKey, c.GatewayToken = t.TempDir(), bundle.Ed25519Signer{Key: priv}, gwTok
	})
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
		key bundle.Signer
		tok string
	}{{bundle.Ed25519Signer{Key: priv}, ""}, {nil, gwTok}, {nil, ""}} {
		e := newEnv(t, func(cfg *Config) { cfg.KillKey, cfg.GatewayToken = c.key, c.tok })
		if w := do(e.h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, ""); w.Code != 404 {
			t.Fatalf("key=%v token=%q: %d, want 404", c.key != nil, c.tok, w.Code)
		}
	}
	e := newEnv(t, func(cfg *Config) { cfg.KillKey, cfg.GatewayToken = bundle.Ed25519Signer{Key: priv}, gwTok })
	w := do(e.h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
	env := decode[gateway.KillEnvelope](t, w)
	if _, err := gateway.VerifyKillList(context.Background(), bundle.Ed25519Verifier{Key: pub}, env, *e.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, env.Payload, env.Signature) {
		t.Fatal("kill-list signature is not domain-separated")
	}
}

// ruleFor is the workload rule a GitHub token for repository on main gets
// under org ("" = none).
func ruleFor(org *policy.Org, repository string) string {
	r, _, ok := org.Workloads.MatchWorkload("github", map[string]any{"repository": repository, "repository_owner": "acme", "ref": "refs/heads/main"})
	if !ok {
		return ""
	}
	return r.Name
}

// A refused policy that drops a narrow rule above a broader one leaves the
// narrow rule as a deny tombstone: its tokens do not fall through to the
// broader rule, so no token gains a grant over the last good policy.
func TestRefusedPolicyRemovalDoesNotWiden(t *testing.T) {
	e := newWorkloadEnv(t, true)
	f := filepath.Join(e.dir, "halos.yaml")
	write := func(rules string) {
		t.Helper()
		root := fmt.Sprintf(`org: acme-corp
workloads:
  audience: halos
  issuers:
    - {name: github, url: %q, tenantClaim: repository_owner}
  rules:
%s`, e.iss.URL, rules)
		if err := os.WriteFile(f, []byte(root), 0o600); err != nil {
			t.Fatal(err)
		}
		e.s.ReloadPolicy()
	}
	const narrow = `    - {name: untrusted-readonly, issuer: github, match: {repository_owner: acme, repository: "acme/untrusted"}, subject: "workload:gh:{repository}", groups: [readonly]}
`
	const broad = `    - {name: org-deploy, issuer: github, match: {repository_owner: acme}, subject: "workload:gh:{repository}", groups: [deploy]}
`
	write(narrow + broad)
	if org, _, err := e.s.pol.Get(); err != nil || ruleFor(org, "acme/untrusted") != "untrusted-readonly" || ruleFor(org, "acme/app") != "org-deploy" {
		t.Fatalf("fixture: %v", err)
	}
	unit := filepath.Join(e.dir, "units", "payments", "checkout", "unit.yaml")
	ub, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, bytes.Replace(ub, []byte("parent: payments"), []byte("parent: paymnets"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	write(broad) // refused (unit typo); drops the narrow rule
	org, _, err := e.s.pol.Get()
	if err == nil {
		t.Fatal("policy with a unit typo was not refused")
	}
	if got := ruleFor(org, "acme/untrusted"); got != "" {
		t.Fatalf("acme/untrusted fell through to %q after its narrow rule was removed, want no rule", got)
	}
	if got := ruleFor(org, "acme/app"); got != "org-deploy" {
		t.Fatalf("acme/app: %q, want org-deploy (unchanged)", got)
	}
	if w := e.post(exchangeForm(e.mint(t, "repository", "acme/untrusted")), ""); w.Code != http.StatusBadRequest {
		t.Fatalf("exchange for acme/untrusted: %d %s, want 400", w.Code, w.Body)
	}
}
