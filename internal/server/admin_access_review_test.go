package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Security review fixes for ADR-0036 (M1, L1-L3, atomic token cap).

const needPerson = "needs a person"

// TestSelfApprovalViaOwnToken (M1, the reviewer's proof): a human refused as
// their own approver must not approve through a token they minted, nor file
// a request through one; every refusal is audited.
func TestSelfApprovalViaOwnToken(t *testing.T) {
	e := newEnv(t, nil)
	rq := decode[Request](t, e.as(admin, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"me"}`))
	if c := e.as(admin, "POST", "/api/v1/requests/"+rq.ID+"/approve", "").Code; c != http.StatusForbidden {
		t.Fatalf("self approve as human: %d", c)
	}
	tok, info := e.mintToken(t, `{"name":"sod-bypass","role":"approver"}`)
	for _, verb := range []string{"approve", "deny"} {
		if w := e.bearer(tok, "POST", "/api/v1/requests/"+rq.ID+"/"+verb, ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), needPerson) {
			t.Fatalf("%s own request via own token: %d %s", verb, w.Code, w.Body)
		}
	}
	if w := e.bearer(tok, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"x"}`); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), needPerson) {
		t.Fatalf("token files request: %d %s", w.Code, w.Body)
	}
	if got := e.s.reqs.byID[rq.ID]; got.Status != StatusPending {
		t.Fatalf("request decided: %s", got.Status)
	}
	var denies int
	for _, a := range auditBy(e.auditActions(t), info.Principal, "authz.deny") {
		if a.Details["need"] == "human" && a.Details["onBehalfOf"] == admin.ID {
			denies++
		}
	}
	if denies != 3 {
		t.Fatalf("audited human-only denials: %d", denies)
	}
}

func TestBreakGlassCannotDecide(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t)} })
	rq := decode[Request](t, e.as(dev, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"x"}`))
	sc := cookieOf(e.breakGlass("breakglass", bgPassword), sessionCookie)
	r := httptest.NewRequest("POST", "/api/v1/requests/"+rq.ID+"/approve", nil)
	r.AddCookie(sc)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), needPerson) {
		t.Fatalf("break-glass approved a request: %d %s", w.Code, w.Body)
	}
}

func TestRolloutApprovalNeedsHuman(t *testing.T) {
	e := govEnv(t)
	tok, _ := e.mintToken(t, `{"name":"rollout-bot","role":"approver"}`)
	if w := e.bearer(tok, "POST", "/api/v1/rollouts/claude-code-2.1.300/approve", `{"ticket":"CHG7"}`); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), needPerson) {
		t.Fatalf("token approved a rollout step: %d %s", w.Code, w.Body)
	}
}

// TestPrincipalIsOnBehalfOf: separation-of-duties identity covers the creator.
func TestPrincipalIsOnBehalfOf(t *testing.T) {
	p := Principal{ID: "service-account:bot:0123456789abcdef", OnBehalfOf: "Boss@Acme.example"}
	for user, want := range map[string]bool{"boss@acme.example": true, "service-account:bot:0123456789abcdef": true, "other@acme.example": false} {
		if p.is(user) != want {
			t.Errorf("is(%q) = %v", user, !want)
		}
	}
	if (Principal{ID: "a@b"}).is("") {
		t.Error("empty OnBehalfOf matched the empty user")
	}
}

// TestReservedSubjectCase (L1): the reservation is checked on the canonical id.
func TestReservedSubjectCase(t *testing.T) {
	for id, want := range map[string]bool{
		"breakglass:breakglass": true, "BreakGlass:breakglass": true, "BREAKGLASS:x": true,
		"Service-Account:bot:1": true, "service-account:x": true, " breakglass:x": true,
		"boss@acme.example": false, "breakglassfan@acme.example": false,
	} {
		if reservedSubject(id) != want {
			t.Errorf("reservedSubject(%q) = %v, want %v", id, !want, want)
		}
	}
	o := newOIDCEnv(t, "[platform-admins]\n  userClaim: sub")
	for _, sub := range []string{"BreakGlass:breakglass", "SERVICE-ACCOUNT:ops-bot:0123456789abcdef"} {
		o.iss.SetLogin(map[string]any{"sub": sub})
		if w := o.callback(o.login(t)); w.Code != 403 || cookieOf(w, sessionCookie) != nil {
			t.Fatalf("reserved id %q logged in: %d %s", sub, w.Code, w.Body)
		}
	}
}

// TestDelegationBoundedByIdle (L2): an agent credential from a session lives
// no longer than the session's idle window, and neither does its child.
func TestDelegationBoundedByIdle(t *testing.T) {
	e, _ := delegationEnv(t, false)
	now := *e.now
	sess := e.s.seal(cookiePayload{Sub: alice.ID, Groups: alice.Groups, Iat: now.Add(-2 * time.Hour).UnixNano(), Seen: now.Add(-55 * time.Minute).Unix(), Exp: now.Add(8 * time.Hour).Unix()})
	resp, c := e.delegate(t, delegForm(sess, tokenTypeSession, "planner", paramActorHarness, "claude-code"))
	if resp.ExpiresIn > 300 || c.Expiry > now.Add(5*time.Minute).Unix() {
		t.Fatalf("delegated past the idle deadline: expires_in %d", resp.ExpiresIn)
	}
	_, c2 := e.delegate(t, delegForm(resp.AccessToken, tokenTypeJWT, "reviewer"))
	if c2.Expiry > c.Expiry {
		t.Fatalf("child outlives its idle-bounded parent: %d > %d", c2.Expiry, c.Expiry)
	}
	idle := e.s.seal(cookiePayload{Sub: alice.ID, Groups: alice.Groups, Iat: now.Add(-2 * time.Hour).UnixNano(), Seen: now.Add(-61 * time.Minute).Unix(), Exp: now.Add(8 * time.Hour).Unix()})
	if w := e.exchange(delegForm(idle, tokenTypeSession, "planner", paramActorHarness, "claude-code")); w.Code == http.StatusOK {
		t.Fatalf("idle session delegated: %s", w.Body)
	}
}

func (e *env) breakGlassFrom(ip, user, pass string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(BreakGlassLogin{User: user, Password: pass})
	r := httptest.NewRequest("POST", "/auth/breakglass", strings.NewReader(string(b)))
	r.RemoteAddr = ip + ":5555"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// TestBreakGlassAllowedCIDRs (L3): outside the allowed ranges break-glass
// looks sealed, and an existing session is refused there.
func TestBreakGlassAllowedCIDRs(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t), AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	})
	if w := e.breakGlassFrom("192.0.2.7", "breakglass", bgPassword); w.Code != http.StatusNotFound {
		t.Fatalf("outside the CIDRs: %d", w.Code)
	}
	w := e.breakGlassFrom("10.1.2.3", "breakglass", bgPassword)
	sc := cookieOf(w, sessionCookie)
	if w.Code != 200 || sc == nil {
		t.Fatalf("inside: %d", w.Code)
	}
	for ip, code := range map[string]int{"10.9.9.9": 200, "192.0.2.7": 401} {
		r := httptest.NewRequest("GET", "/api/v1/me", nil)
		r.RemoteAddr = ip + ":1"
		r.AddCookie(sc)
		rw := httptest.NewRecorder()
		e.h.ServeHTTP(rw, r)
		if rw.Code != code {
			t.Fatalf("session from %s: %d, want %d", ip, rw.Code, code)
		}
	}
}

// TestBreakGlassGlobalLockout (L3): failures spread over many addresses lock
// break-glass for everyone, the lockout is audited at high severity, and it
// lifts after the window.
func TestBreakGlassGlobalLockout(t *testing.T) {
	old := breakGlassGlobalFails
	breakGlassGlobalFails = 3
	t.Cleanup(func() { breakGlassGlobalFails = old })
	e := newEnv(t, func(c *Config) { c.BreakGlass = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t)} })
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if w := e.breakGlassFrom(ip, "breakglass", "wrong but long enough password"); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := e.breakGlassFrom("203.0.113.9", "breakglass", bgPassword); w.Code != http.StatusTooManyRequests || cookieOf(w, sessionCookie) != nil {
		t.Fatalf("locked: correct password from a fresh address: %d", w.Code)
	}
	lock := auditBy(e.auditActions(t), "breakglass:breakglass", "breakglass.lockout")
	if len(lock) != 1 || lock[0].Details["severity"] != "high" {
		t.Fatalf("lockout audit: %+v", lock)
	}
	*e.now = e.now.Add(breakGlassLockWindow + time.Second)
	if w := e.breakGlassFrom("203.0.113.9", "breakglass", bgPassword); w.Code != 200 {
		t.Fatalf("after the window: %d", w.Code)
	}
}

// TestBreakGlassStrictAudit (L3): a state-changing break-glass request whose
// audit entry cannot be written is refused before it acts.
func TestBreakGlassStrictAudit(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.BreakGlass, c.DataDir = BreakGlass{Enabled: true, Hash: testBreakGlassHash(t)}, t.TempDir()
	})
	sc := cookieOf(e.breakGlass("breakglass", bgPassword), sessionCookie)
	_ = e.s.auditLog.f.Close() // every append now errors
	do := func(method, url, body string) int {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		r.AddCookie(sc)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do("POST", "/api/v1/freeze", `{"frozen":true,"reason":"SEV1"}`); c != http.StatusServiceUnavailable {
		t.Fatalf("unaudited break-glass change: %d", c)
	}
	if inc, err := e.s.IncidentFreeze(); err != nil || inc != nil {
		t.Fatalf("freeze applied without an audit record: %+v %v", inc, err)
	}
	if c := do("GET", "/api/v1/me", ""); c != 200 {
		t.Fatalf("reads stay available: %d", c)
	}
}

// TestServiceTokenCapAtomic: concurrent creations never exceed the cap.
func TestServiceTokenCapAtomic(t *testing.T) {
	old := maxActiveServiceTokens
	maxActiveServiceTokens = 5
	t.Cleanup(func() { maxActiveServiceTokens = old })
	e := newEnv(t, nil)
	var wg sync.WaitGroup
	var created, refused atomic.Int32
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := e.as(admin, "POST", "/api/v1/service-tokens", `{"name":"bot-`+string(rune('a'+i%26))+`","role":"viewer"}`)
			switch w.Code {
			case http.StatusCreated:
				created.Add(1)
			case http.StatusConflict:
				refused.Add(1)
			default:
				t.Errorf("%d %s", w.Code, w.Body)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 5 || refused.Load() != 35 {
		t.Fatalf("created %d, refused %d (cap 5)", created.Load(), refused.Load())
	}
}
