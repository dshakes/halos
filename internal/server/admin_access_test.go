package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/policy"
)

// Tests for ADR-0036: service-account tokens, break-glass, session policy.

func (e *env) bearer(tok, method, url, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// mintToken creates a token as admin and returns it with its info.
func (e *env) mintToken(t *testing.T, body string) (string, ServiceTokenInfo) {
	t.Helper()
	w := e.as(admin, "POST", "/api/v1/service-tokens", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", body, w.Code, w.Body)
	}
	out := decode[CreateServiceTokenResponse](t, w)
	return out.Token, out.ServiceToken
}

func auditBy(entries []AuditEntry, actor, action string) []AuditEntry {
	var out []AuditEntry
	for _, a := range entries {
		if a.Actor == actor && a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

func TestServiceTokenFormat(t *testing.T) {
	tok, id, err := newServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseServiceToken(tok)
	if !ok || got != id || len(tok) != len(ServiceTokenPrefix)+80 || !strings.HasPrefix(tok, "halo_sat_") {
		t.Fatalf("token %q id %q parsed %q %v", tok, id, got, ok)
	}
	for _, bad := range []string{"", "halo_sat_", tok[:len(tok)-1], tok + "0", strings.ToUpper(tok), "halo_sas_" + tok[9:], strings.Replace(tok, tok[20:21], "g", 1)} {
		if _, ok := parseServiceToken(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}

// TestServiceTokenLifecycle: create, use, role enforcement, audit
// attribution, timing-safe secret check, wrong prefix, expiry, revocation.
func TestServiceTokenLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	view, vi := e.mintToken(t, `{"name":"ci-fleet","role":"viewer","owner":"platform","description":"fleet dashboard","ttl":"48h"}`)
	adm, ai := e.mintToken(t, `{"name":"ops-bot","role":"admin"}`)
	if vi.Principal != "service-account:ci-fleet:"+vi.ID || vi.Role != "viewer" || vi.CreatedBy != admin.ID || !vi.ExpiresAt.Equal(e.now.Add(48*time.Hour)) {
		t.Fatalf("info: %+v", vi)
	}
	if !ai.ExpiresAt.Equal(e.now.Add(DefaultServiceTokenMaxTTL)) {
		t.Fatalf("default ttl must be the max: %s", ai.ExpiresAt)
	}
	// The secret is never listed.
	lw := e.as(admin, "GET", "/api/v1/service-tokens", "")
	if lw.Code != 200 || strings.Contains(lw.Body.String(), view[len(ServiceTokenPrefix)+16:]) || len(decode[ServiceTokensResponse](t, lw).Tokens) != 2 {
		t.Fatalf("list: %d %s", lw.Code, lw.Body)
	}
	tampered := view[:len(view)-1] + map[bool]string{true: "1", false: "0"}[view[len(view)-1] == '0'] // same id, wrong secret
	cases := []struct {
		name, tok, method, url, body string
		code                         int
	}{
		{"viewer reads fleet", view, "GET", "/api/v1/fleet", "", 200},
		{"viewer me", view, "GET", "/api/v1/me", "", 200},
		{"viewer cannot read audit", view, "GET", "/api/v1/audit", "", 403},
		{"viewer cannot revoke", view, "POST", "/api/v1/service-tokens/" + ai.ID + "/revoke", `{"reason":"x"}`, 403},
		{"admin token reads audit", adm, "GET", "/api/v1/audit", "", 200},
		{"admin token cannot mint", adm, "POST", "/api/v1/service-tokens", `{"name":"next","role":"viewer"}`, 403},
		{"wrong secret, same id", tampered, "GET", "/api/v1/fleet", "", 401},
		{"unknown id", ServiceTokenPrefix + strings.Repeat("0", 80), "GET", "/api/v1/fleet", "", 401},
		{"malformed", ServiceTokenPrefix + "nothex", "GET", "/api/v1/fleet", "", 401},
		{"wrong prefix is not a token: login required", "ghp_" + view[len(ServiceTokenPrefix):], "GET", "/api/v1/fleet", "", 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if w := e.bearer(c.tok, c.method, c.url, c.body); w.Code != c.code {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	if w := e.bearer("ghp_x", "GET", "/api/v1/fleet", ""); !strings.Contains(w.Body.String(), "login required") {
		t.Fatalf("a foreign bearer must fall through to the cookie: %s", w.Body)
	}
	if m := decode[Me](t, e.bearer(view, "GET", "/api/v1/me", "")); m.ID != vi.Principal || m.Kind != KindServiceAccount || m.Admin || len(m.Roles) != 1 || m.Roles[0] != "viewer" {
		t.Fatalf("me: %+v", m.Principal)
	}

	// Attribution: an action taken with the admin token is audited as its service account.
	if w := e.bearer(adm, "POST", "/api/v1/service-tokens/"+vi.ID+"/revoke", `{"reason":"rotated"}`); w.Code != 200 || !decode[ServiceTokenInfo](t, w).Revoked {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	all := e.auditActions(t)
	if len(auditBy(all, ai.Principal, "service-token.revoke")) != 1 || len(auditBy(all, ai.Principal, "service-token.use")) != 1 ||
		len(auditBy(all, vi.Principal, "service-token.use")) != 1 || len(auditBy(all, admin.ID, "service-token.create")) != 2 {
		t.Fatalf("audit attribution: %+v", all)
	}
	if d := auditBy(all, vi.Principal, "authz.deny"); len(d) == 0 {
		t.Fatal("a token's denied request must be audited as the token")
	}
	if w := e.bearer(view, "GET", "/api/v1/fleet", ""); w.Code != 401 {
		t.Fatalf("revoked token still works: %d", w.Code)
	}
	// Revocation sticks: a second revoke keeps the first record.
	if w := e.as(admin, "POST", "/api/v1/service-tokens/"+vi.ID+"/revoke", `{"reason":"again"}`); w.Code != 200 || decode[ServiceTokenInfo](t, w).RevokeReason != "rotated" {
		t.Fatalf("re-revoke: %d %s", w.Code, w.Body)
	}
	// Expiry: past expiresAt the admin token is refused, and it is not charged as a guess.
	*e.now = e.now.Add(DefaultServiceTokenMaxTTL)
	for range authFailBurst + 2 {
		if w := e.bearer(adm, "GET", "/api/v1/audit", ""); w.Code != 401 || !strings.Contains(w.Body.String(), "expired") {
			t.Fatalf("expired: %d %s", w.Code, w.Body)
		}
	}
}

func TestServiceTokenCreateValidation(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ServiceTokenMaxTTL = 30 * 24 * time.Hour })
	for _, c := range []struct {
		name, body string
		code       int
	}{
		{"ok", `{"name":"ok","role":"operator","ttl":"720h"}`, 201},
		{"over the max ttl", `{"name":"long","role":"viewer","ttl":"721h"}`, 400},
		{"under an hour", `{"name":"short","role":"viewer","ttl":"59m"}`, 400},
		{"bad ttl", `{"name":"x","role":"viewer","ttl":"forever"}`, 400},
		{"unknown role", `{"name":"x","role":"root"}`, 400},
		{"bad name", `{"name":"Bad Name","role":"viewer"}`, 400},
		{"control chars", `{"name":"x","role":"viewer","owner":"a\u0007b"}`, 400},
		{"unknown field", `{"name":"x","role":"viewer","scopes":["*"]}`, 201}, // tolerated, ignored
		{"trailing data", `{"name":"x","role":"viewer"}{}`, 400},
	} {
		t.Run(c.name, func(t *testing.T) {
			if w := e.as(admin, "POST", "/api/v1/service-tokens", c.body); w.Code != c.code {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	if w := e.as(dev, "POST", "/api/v1/service-tokens", `{"name":"x","role":"viewer"}`); w.Code != 403 {
		t.Fatalf("non-admin create: %d", w.Code)
	}
}

// TestRoleCeiling: a token's role never grants a permission its creator lacks.
func TestRoleCeiling(t *testing.T) {
	for _, c := range []struct {
		creator []string
		role    string
		ok      bool
	}{
		{[]string{RoleAdmin}, RoleAdmin, true},
		{[]string{RoleAdmin}, RoleAuditor, true},
		{[]string{RoleOperator}, RoleViewer, true},
		{[]string{RoleOperator}, RoleOperator, true},
		{[]string{RoleOperator}, RoleApprover, false},
		{[]string{RoleOperator}, RoleAdmin, false},
		{[]string{RoleViewer, RoleAuditor}, RoleAuditor, true},
		{[]string{RoleAuditor}, RoleViewer, false},
		{nil, RoleViewer, false},
		{[]string{RoleAdmin}, "root", false},
	} {
		if got := roleWithin(c.role, newPrincipal("u", nil, c.creator)); got != c.ok {
			t.Errorf("creator %v role %s: %v, want %v", c.creator, c.role, got, c.ok)
		}
	}
}

// TestServiceTokenFailedAuthLimit: guesses are rate limited per address on
// their own budget; a store error is a 503 and never a pass.
func TestServiceTokenFailedAuthLimit(t *testing.T) {
	e := newEnv(t, nil)
	good, _ := e.mintToken(t, `{"name":"bot","role":"viewer"}`)
	bad := ServiceTokenPrefix + strings.Repeat("ab", 40)
	for i := range authFailBurst {
		if w := e.bearer(bad, "GET", "/api/v1/fleet", ""); w.Code != 401 {
			t.Fatalf("guess %d: %d", i, w.Code)
		}
	}
	if w := e.bearer(bad, "GET", "/api/v1/fleet", ""); w.Code != 429 {
		t.Fatalf("after the burst: %d", w.Code)
	}
	if w := e.bearer(good, "GET", "/api/v1/fleet", ""); w.Code != 429 {
		t.Fatalf("a blocked address is blocked for every token: %d", w.Code)
	}
	// The console login budget is separate.
	if e.s.loginFails.blocked("192.0.2.1") {
		t.Fatal("token guesses charged the login budget")
	}

	e2 := newEnv(t, nil)
	tok, _ := e2.mintToken(t, `{"name":"bot","role":"viewer"}`)
	e2.s.tokens = brokenTokens{}
	if w := e2.bearer(tok, "GET", "/api/v1/fleet", ""); w.Code != 503 {
		t.Fatalf("store down: %d", w.Code)
	}
}

type brokenTokens struct{}

func (brokenTokens) PutServiceToken(context.Context, pgstore.ServiceToken, int, time.Time) error {
	return errBroken
}
func (brokenTokens) RevokeServiceToken(context.Context, string, []byte) (pgstore.ServiceToken, bool, error) {
	return pgstore.ServiceToken{}, false, errBroken
}
func (brokenTokens) ServiceToken(context.Context, string) (pgstore.ServiceToken, bool, error) {
	return pgstore.ServiceToken{}, false, errBroken
}
func (brokenTokens) ServiceTokens(context.Context) ([]pgstore.ServiceToken, error) {
	return nil, errBroken
}

var errBroken = fmt.Errorf("db down")

// TestServiceTokensPersistAndReplicate: tokens survive a restart (file log)
// and a revocation on one replica holds on another at once (shared backend).
func TestServiceTokensPersistAndReplicate(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir = dir })
	tok, info := e.mintToken(t, `{"name":"bot","role":"viewer"}`)
	_ = e.s.Close()
	e2 := newEnv(t, func(c *Config) { c.DataDir = dir })
	if w := e2.bearer(tok, "GET", "/api/v1/fleet", ""); w.Code != 200 {
		t.Fatalf("after restart: %d", w.Code)
	}
	if w := e2.as(admin, "POST", "/api/v1/service-tokens/"+info.ID+"/revoke", `{"reason":"x"}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	_ = e2.s.Close()
	e3 := newEnv(t, func(c *Config) { c.DataDir = dir })
	if w := e3.bearer(tok, "GET", "/api/v1/fleet", ""); w.Code != 401 {
		t.Fatalf("revocation lost on restart: %d", w.Code)
	}

	shared := newMemShared()
	a := newEnv(t, func(c *Config) { c.Backend = shared })
	b := newEnv(t, func(c *Config) { c.Backend = shared })
	tok, info = a.mintToken(t, `{"name":"bot","role":"viewer"}`)
	if w := b.bearer(tok, "GET", "/api/v1/fleet", ""); w.Code != 200 {
		t.Fatalf("other replica: %d", w.Code)
	}
	if w := a.as(admin, "POST", "/api/v1/service-tokens/"+info.ID+"/revoke", `{"reason":"x"}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := b.bearer(tok, "GET", "/api/v1/fleet", ""); w.Code != 401 {
		t.Fatalf("revoked on a, accepted on b: %d", w.Code)
	}
}

// TestServiceTokensPostgres: the same across real Postgres replicas, and
// `halo-server import` carries a data dir's tokens (revocations included).
func TestServiceTokensPostgres(t *testing.T) {
	db, schema := pgtest.OpenTest(t)
	db2, _ := pgtest.OpenTest(t, schema)
	a := newEnv(t, func(c *Config) { c.Backend = NewPGBackend(db) })
	*a.now = time.Now() // the database prunes on its own clock
	b := newEnv(t, func(c *Config) { c.Backend = NewPGBackend(db2) })
	*b.now = time.Now() // the database prunes on its own clock
	tok, info := a.mintToken(t, `{"name":"bot","role":"viewer"}`)
	if w := b.bearer(tok, "GET", "/api/v1/fleet", ""); w.Code != 200 {
		t.Fatalf("other replica: %d", w.Code)
	}
	if w := b.as(admin, "POST", "/api/v1/service-tokens/"+info.ID+"/revoke", `{"reason":"x"}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := a.bearer(tok, "GET", "/api/v1/fleet", ""); w.Code != 401 {
		t.Fatalf("revoked on b, accepted on a: %d", w.Code)
	}

	dir := t.TempDir()
	f := newEnv(t, func(c *Config) { c.DataDir = dir })
	*f.now = time.Now()
	live, _ := f.mintToken(t, `{"name":"live","role":"viewer"}`)
	dead, di := f.mintToken(t, `{"name":"dead","role":"viewer"}`)
	f.as(admin, "POST", "/api/v1/service-tokens/"+di.ID+"/revoke", `{"reason":"x"}`)
	_ = f.s.Close()
	idb, _ := pgtest.OpenTest(t)
	rep, err := ImportDataDir(context.Background(), dir, NewPGBackend(idb))
	if err != nil || rep.Copied["service-tokens"] != 2 {
		t.Fatalf("import: %+v %v", rep, err)
	}
	g := newEnv(t, func(c *Config) { c.Backend = NewPGBackend(idb) })
	*g.now = time.Now() // the database prunes on its own clock
	if w := g.bearer(live, "GET", "/api/v1/fleet", ""); w.Code != 200 {
		t.Fatalf("imported token: %d", w.Code)
	}
	if w := g.bearer(dead, "GET", "/api/v1/fleet", ""); w.Code != 401 {
		t.Fatalf("import revived a revoked token: %d", w.Code)
	}
}

// ---- break-glass ----

var (
	bgHashOnce sync.Once
	bgHash     string
)

const bgPassword = "correct horse battery staple 42"

func testBreakGlassHash(t *testing.T) string {
	t.Helper()
	bgHashOnce.Do(func() {
		h, err := HashBreakGlassPassword(bgPassword)
		if err != nil {
			panic(err)
		}
		bgHash = h
	})
	return bgHash
}

func (e *env) breakGlass(user, pass string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(BreakGlassLogin{User: user, Password: pass})
	r := httptest.NewRequest("POST", "/auth/breakglass", strings.NewReader(string(b)))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestBreakGlassHash(t *testing.T) {
	h := testBreakGlassHash(t)
	p, err := parseBreakGlassHash(h)
	if err != nil || !p.verify(bgPassword) || p.verify(bgPassword+"x") || p.iter != BreakGlassIterations {
		t.Fatalf("%s: %+v %v", h, p, err)
	}
	if _, err := HashBreakGlassPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	for _, bad := range []string{"", "bcrypt$x", "pbkdf2-sha256$1000$" + strings.SplitN(h, "$", 3)[2], strings.Replace(h, "pbkdf2-sha256", "pbkdf2-sha1", 1), h + "$x"} {
		if _, err := parseBreakGlassHash(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
	if _, err := New(Config{PolicyDir: t.TempDir(), Token: "t", SessionKey: []byte(strings.Repeat("k", 32)), BreakGlass: BreakGlass{Enabled: true}}); err == nil {
		t.Fatal("enabled without a hash accepted")
	}
}

func TestBreakGlass(t *testing.T) {
	h := testBreakGlassHash(t)
	t.Run("off by default", func(t *testing.T) {
		e := newEnv(t, nil)
		if w := e.breakGlass("breakglass", bgPassword); w.Code != 404 {
			t.Fatalf("%d", w.Code)
		}
	})
	t.Run("sealed: hash configured, not enabled", func(t *testing.T) {
		e := newEnv(t, func(c *Config) { c.BreakGlass = BreakGlass{Hash: h} })
		if w := e.breakGlass("breakglass", bgPassword); w.Code != 404 || cookieOf(w, sessionCookie) != nil {
			t.Fatalf("%d", w.Code)
		}
	})
	t.Run("enabled", func(t *testing.T) {
		e := newEnv(t, func(c *Config) { c.BreakGlass = BreakGlass{Enabled: true, Hash: h} })
		for _, bad := range [][2]string{{"breakglass", "wrong password, long enough"}, {"admin", bgPassword}} {
			if w := e.breakGlass(bad[0], bad[1]); w.Code != 401 || cookieOf(w, sessionCookie) != nil {
				t.Fatalf("bad credentials %v: %d", bad, w.Code)
			}
		}
		w := e.breakGlass("breakglass", bgPassword)
		sc := cookieOf(w, sessionCookie)
		if w.Code != 200 || sc == nil || sc.MaxAge != int(BreakGlassSessionTTL.Seconds()) {
			t.Fatalf("login: %d %+v", w.Code, sc)
		}
		req := func(method, url, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, url, strings.NewReader(body))
			r.AddCookie(sc)
			rw := httptest.NewRecorder()
			e.h.ServeHTTP(rw, r)
			return rw
		}
		if m := decode[Me](t, req("GET", "/api/v1/me", "")); m.ID != "breakglass:breakglass" || !m.Admin || m.Kind != KindBreakGlass {
			t.Fatalf("me: %+v", m.Principal)
		}
		if w := req("GET", "/api/v1/audit", ""); w.Code != 200 {
			t.Fatalf("admin read: %d", w.Code)
		}
		if w := req("POST", "/api/v1/service-tokens", `{"name":"x","role":"viewer"}`); w.Code != 403 {
			t.Fatalf("break-glass minted a token: %d", w.Code)
		}
		all := e.auditActions(t)
		login := auditBy(all, "breakglass:breakglass", "breakglass.login")
		if len(login) != 1 || login[0].Details["severity"] != "high" || len(auditBy(all, "breakglass:breakglass", "breakglass.login.failed")) != 2 ||
			len(auditBy(all, "breakglass:breakglass", "breakglass.request")) != 3 {
			t.Fatalf("audit: %+v", all)
		}
		if o := ocsfEvent(auditEvent{e: login[0]}); o.SeverityID != 4 || o.Severity != "High" {
			t.Fatalf("SIEM severity: %d %s", o.SeverityID, o.Severity)
		}
		// Fixed lifetime: no sliding, gone after 30 minutes however active.
		*e.now = e.now.Add(BreakGlassSessionTTL - time.Minute)
		if w := req("GET", "/api/v1/me", ""); w.Code != 200 || cookieOf(w, sessionCookie) != nil {
			t.Fatalf("near the end: %d (break-glass must not slide)", w.Code)
		}
		*e.now = e.now.Add(2 * time.Minute)
		if w := req("GET", "/api/v1/me", ""); w.Code != 401 {
			t.Fatalf("after 30m: %d", w.Code)
		}
	})
	t.Run("disabling or rotating ends sessions", func(t *testing.T) {
		e := newEnv(t, func(c *Config) { c.BreakGlass = BreakGlass{Enabled: true, Hash: h} })
		sc := cookieOf(e.breakGlass("breakglass", bgPassword), sessionCookie)
		me := func() int {
			r := httptest.NewRequest("GET", "/api/v1/me", nil)
			r.AddCookie(sc)
			w := httptest.NewRecorder()
			e.h.ServeHTTP(w, r)
			return w.Code
		}
		if me() != 200 {
			t.Fatal("login")
		}
		e.s.bg.print = "rotated0"
		if me() != 401 {
			t.Fatal("rotated hash still accepted the old session")
		}
		e.s.bg.print, _ = parseBreakGlassPrint(h)
		e.s.cfg.BreakGlass.Enabled = false
		if me() != 401 {
			t.Fatal("disabled break-glass still accepted its session")
		}
	})
	t.Run("audit down: refused", func(t *testing.T) {
		e := newEnv(t, func(c *Config) { c.BreakGlass, c.DataDir = BreakGlass{Enabled: true, Hash: h}, t.TempDir() })
		_ = e.s.auditLog.f.Close() // every append now errors
		if w := e.breakGlass("breakglass", bgPassword); w.Code != 500 || cookieOf(w, sessionCookie) != nil {
			t.Fatalf("unrecorded break-glass login: %d", w.Code)
		}
	})
}

func parseBreakGlassPrint(h string) (string, error) {
	p, err := parseBreakGlassHash(h)
	return p.print, err
}

// ---- session policy ----

func TestSessionPolicyNormalize(t *testing.T) {
	for _, c := range []struct {
		in       SessionPolicy
		ttl, idl time.Duration
		err      bool
	}{
		{SessionPolicy{}, DefaultSessionTTL, DefaultSessionIdle, false},
		{SessionPolicy{TTL: 30 * time.Minute}, 30 * time.Minute, 30 * time.Minute, false},
		{SessionPolicy{Idle: -1}, DefaultSessionTTL, 0, false},
		{SessionPolicy{TTL: 8 * time.Hour, Idle: 15 * time.Minute}, 8 * time.Hour, 15 * time.Minute, false},
		{SessionPolicy{TTL: time.Minute}, 0, 0, true},
		{SessionPolicy{TTL: 8 * 24 * time.Hour}, 0, 0, true},
		{SessionPolicy{Idle: 30 * time.Second}, 0, 0, true},
		{SessionPolicy{TTL: time.Hour, Idle: 2 * time.Hour}, 0, 0, true},
	} {
		got, err := c.in.normalize()
		if (err != nil) != c.err || (!c.err && (got.TTL != c.ttl || got.Idle != c.idl)) {
			t.Errorf("%+v: %+v %v", c.in, got, err)
		}
	}
}

// TestSessionIdleAndAbsoluteTimeout drives a real OIDC login on a fake clock.
func TestSessionIdleAndAbsoluteTimeout(t *testing.T) {
	o := newOIDCEnv(t, "[platform-admins]", func(c *Config) { c.Session = SessionPolicy{TTL: 4 * time.Hour, Idle: time.Hour} })
	o.iss.SetLogin(map[string]any{"email": "boss@acme.example", "email_verified": true, "groups": []any{"platform-admins"}})
	login := func() *http.Cookie {
		w := o.callback(o.login(t))
		c := cookieOf(w, sessionCookie)
		if w.Code != 302 || c == nil || c.MaxAge != int((4*time.Hour).Seconds()) {
			t.Fatalf("login: %d %+v", w.Code, c)
		}
		return c
	}
	get := func(c *http.Cookie) (int, *http.Cookie) {
		r := httptest.NewRequest("GET", "/api/v1/me", nil)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		o.h.ServeHTTP(w, r)
		return w.Code, cookieOf(w, sessionCookie)
	}
	start := *o.now
	at := func(d time.Duration) { *o.now = start.Add(d) }

	c := login()
	at(5 * time.Minute) // under slideEvery (6m): no re-issue
	if code, re := get(c); code != 200 || re != nil {
		t.Fatalf("early: %d %v", code, re)
	}
	at(61 * time.Minute) // idle past 1h since login: out
	if code, _ := get(c); code != 401 {
		t.Fatalf("idle: %d", code)
	}

	at(0)
	c = login()
	cur := c
	for i := 1; i <= 4; i++ { // a request every 50 minutes keeps it alive
		at(time.Duration(i) * 50 * time.Minute)
		code, re := get(cur)
		if code != 200 || re == nil {
			t.Fatalf("slide %d: %d %v", i, code, re)
		}
		if left := start.Add(4 * time.Hour).Sub(*o.now); re.MaxAge != int(left.Seconds()) {
			t.Fatalf("re-issued cookie extends the absolute lifetime: %d vs %s", re.MaxAge, left)
		}
		cur = re
		if i == 2 {
			if code, _ := get(c); code != 401 {
				t.Fatalf("the original cookie, idle 100m, still works: %d", code)
			}
		}
	}
	// 250 minutes: past the 4h absolute TTL however active.
	at(250 * time.Minute)
	if code, _ := get(cur); code != 401 {
		t.Fatalf("absolute: %d", code)
	}
}

func TestSessionIdleOff(t *testing.T) {
	o := newOIDCEnv(t, "[platform-admins]", func(c *Config) { c.Session = SessionPolicy{Idle: -1} })
	o.iss.SetLogin(map[string]any{"email": "boss@acme.example", "email_verified": true})
	c := cookieOf(o.callback(o.login(t)), sessionCookie)
	*o.now = o.now.Add(11 * time.Hour)
	if code, _ := o.me(t, c); code != 200 {
		t.Fatalf("idle off: %d", code)
	}
	*o.now = o.now.Add(2 * time.Hour)
	if code, _ := o.me(t, c); code != 401 {
		t.Fatalf("12h absolute default: %d", code)
	}
}

// ---- OIDC: Entra overage, acr/amr ----

// fakeGraph serves POST /me/getMemberObjects for any bearer token.
func fakeGraph(t *testing.T, code int, groups ...string) (*httptest.Server, *[]string) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1.0/me/getMemberObjects" {
			http.NotFound(w, r)
			return
		}
		seen = append(seen, r.Header.Get("Authorization"))
		if code != 200 {
			http.Error(w, `{"error":{"code":"Authorization_RequestDenied"}}`, code)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": groups})
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func overageClaims() map[string]any {
	return map[string]any{"email": "boss@acme.example", "email_verified": true,
		"_claim_names": map[string]any{"groups": "src1"}, "_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.windows.net/x/users/y/getMemberObjects"}}}
}

func TestEntraGroupsOverage(t *testing.T) {
	for _, c := range []struct {
		name, identity string
		claims         map[string]any
		graphCode      int
		code           int
		admin          bool
		reason         string
	}{
		{"deny by default", "", overageClaims(), 200, 403, false, "groups_overage"},
		{"explicit deny", "\n  groupsOverage: deny", overageClaims(), 200, 403, false, "groups_overage"},
		{"hasgroups also counts", "", map[string]any{"email": "boss@acme.example", "email_verified": true, "hasgroups": true}, 200, 403, false, "groups_overage"},
		{"graph resolves", "\n  groupsOverage: graph", overageClaims(), 200, 302, true, ""},
		{"graph error: refused, never no-roles", "\n  groupsOverage: graph", overageClaims(), 403, 503, false, "groups_graph"},
		{"no overage: token groups", "\n  groupsOverage: graph", map[string]any{"email": "boss@acme.example", "email_verified": true, "groups": []any{"platform-admins"}}, 500, 302, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			graph, seen := fakeGraph(t, c.graphCode, "11111111-aaaa", "platform-admins")
			o := newOIDCEnv(t, "[platform-admins]"+c.identity, func(cfg *Config) { cfg.EntraGraphURL = graph.URL + "/v1.0" })
			o.iss.SetLogin(c.claims)
			sc, u := o.login(t)
			w := o.callback(sc, u)
			if w.Code != c.code {
				t.Fatalf("callback: %d %s", w.Code, w.Body)
			}
			if c.code != 302 {
				if cookieOf(w, sessionCookie) != nil {
					t.Fatal("session issued")
				}
				d := auditBy(o.auditActions(t), "boss@acme.example", "login.denied")
				if len(d) != 1 || d[0].Details["reason"] != c.reason {
					t.Fatalf("denial audit: %+v", d)
				}
				if c.reason == "groups_overage" && !strings.Contains(w.Body.String(), "groupsOverage") {
					t.Fatalf("unclear error: %s", w.Body)
				}
				return
			}
			code, m := o.me(t, cookieOf(w, sessionCookie))
			if code != 200 || m.Admin != c.admin {
				t.Fatalf("me: %d %+v", code, m.Principal)
			}
			if _, ok := c.claims["_claim_names"]; ok && (len(*seen) != 1 || !strings.HasPrefix((*seen)[0], "Bearer ") || len((*seen)[0]) < 10) {
				t.Fatalf("graph not called with the access token: %v", *seen)
			}
		})
	}
}

func TestGraphScopesRequested(t *testing.T) {
	o := newOIDCEnv(t, "[platform-admins]\n  groupsOverage: graph")
	w := httptest.NewRecorder()
	o.h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "GroupMember.Read.All") {
		t.Fatalf("graph scope not requested: %s", loc)
	}
}

func TestRequireAcrAmr(t *testing.T) {
	for _, c := range []struct {
		name, identity string
		claims         map[string]any
		code           int
	}{
		{"amr mfa present", "\n  requireAmr: [mfa]", map[string]any{"amr": []any{"pwd", "mfa"}}, 302},
		{"amr pwd only", "\n  requireAmr: [mfa]", map[string]any{"amr": []any{"pwd"}}, 403},
		{"amr absent", "\n  requireAmr: [mfa]", map[string]any{}, 403},
		{"amr any of", "\n  requireAmr: [hwk, mfa]", map[string]any{"amr": []any{"hwk"}}, 302},
		{"acr match", "\n  requireAcr: [urn:okta:loa:2fa:any]", map[string]any{"acr": "urn:okta:loa:2fa:any"}, 302},
		{"acr mismatch", "\n  requireAcr: [urn:okta:loa:2fa:any]", map[string]any{"acr": "urn:okta:loa:1fa:any"}, 403},
		{"both, acr fails", "\n  requireAcr: [phr]\n  requireAmr: [mfa]", map[string]any{"acr": "1", "amr": []any{"mfa"}}, 403},
		{"none required", "", map[string]any{}, 302},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := newOIDCEnv(t, "[platform-admins]"+c.identity)
			claims := map[string]any{"email": "boss@acme.example", "email_verified": true}
			for k, v := range c.claims {
				claims[k] = v
			}
			o.iss.SetLogin(claims)
			sc, u := o.login(t)
			w := o.callback(sc, u)
			if w.Code != c.code {
				t.Fatalf("callback: %d %s", w.Code, w.Body)
			}
			if c.code == 403 {
				if !strings.Contains(w.Body.String(), "sign in again") || len(auditBy(o.auditActions(t), "boss@acme.example", "login.denied")) != 1 {
					t.Fatalf("denial: %s", w.Body)
				}
				if o.s.loginFails.blocked("192.0.2.1") {
					t.Fatal("policy denial charged the failed-login budget")
				}
			}
		})
	}
	o := newOIDCEnv(t, "[platform-admins]\n  requireAcr: [urn:okta:loa:2fa:any]")
	w := httptest.NewRecorder()
	o.h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "acr_values=urn%3Aokta%3Aloa%3A2fa%3Aany") {
		t.Fatalf("acr_values not sent: %s", loc)
	}
}

func TestReservedSubjectRefused(t *testing.T) {
	o2 := newOIDCEnv(t, "[platform-admins]\n  userClaim: sub")
	o2.iss.SetLogin(map[string]any{"sub": "breakglass:breakglass"})
	if w := o2.callback(o2.login(t)); w.Code != 403 || cookieOf(w, sessionCookie) != nil {
		t.Fatalf("reserved id logged in: %d %s", w.Code, w.Body)
	}
	o2.iss.SetLogin(map[string]any{"sub": "service-account:ops-bot:0123456789abcdef"})
	if w := o2.callback(o2.login(t)); w.Code != 403 {
		t.Fatalf("reserved id logged in: %d %s", w.Code, w.Body)
	}
}

func TestIdentityPolicyValidation(t *testing.T) {
	for _, c := range []struct {
		id   policy.Identity
		errs int
	}{
		{policy.Identity{GroupsOverage: "graph", RequireAmr: []string{"mfa"}, RequireAcr: []string{"phr"}}, 0},
		{policy.Identity{GroupsOverage: "ignore"}, 1},
		{policy.Identity{RequireAmr: []string{"mfa", "mfa"}}, 1},
		{policy.Identity{RequireAcr: []string{"two words"}}, 1},
	} {
		org := &policy.Org{Identity: c.id}
		n := 0
		for _, i := range policy.SecurityIssues(org) {
			if strings.HasPrefix(i.Path, "identity") {
				n++
			}
		}
		if n != c.errs {
			t.Errorf("%+v: %d identity security issues, want %d", c.id, n, c.errs)
		}
	}
}
