package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Regression tests for the ADR-0024 security review (2026-10-21).

func (e *env) egressFrom(ip, tok, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/agents/egress", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.RemoteAddr = ip + ":4444"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *env) exchangeFrom(ip string, f url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/token/exchange", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ip + ":4444"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func lastAuditOf(t *testing.T, e *env, action string) AuditEntry {
	t.Helper()
	ents := e.auditActions(t)
	for i := len(ents) - 1; i >= 0; i-- {
		if ents[i].Action == action {
			return ents[i]
		}
	}
	t.Fatalf("no %s audit entry", action)
	return AuditEntry{}
}

// TestEgressRevokedRoot (M3): revoking the human root's sessions kills the
// egress decisions of its agents, as it kills their exchanges, and the
// refusal is audited.
func TestEgressRevokedRoot(t *testing.T) {
	e, _ := delegationEnv(t, false)
	resp, c := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "reviewer"))
	if w := e.egress(resp.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusOK {
		t.Fatalf("before revoke: %d %s", w.Code, w.Body)
	}
	*e.now = e.now.Add(2 * time.Second)
	if err := e.s.revoked.revoke(alice.ID, *e.now); err != nil {
		t.Fatal(err)
	}
	w := e.egress(resp.AccessToken, `{"agent":"billing"}`)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"allow":true`) {
		t.Fatalf("revoked root's agent got an egress decision: %d %s", w.Code, w.Body)
	}
	if a := lastAuditOf(t, e, "agent.egress.deny"); a.Actor != alice.ID || a.Details["jti"] != c.ID || !strings.Contains(a.Details["reason"], "revoked") {
		t.Fatalf("refusal audit: %+v", a)
	}
}

// TestAgentLimiter (M4): delegation and egress have their own failure
// budget, separate from CI token exchange; policy refusals of an
// authenticated caller never spend it; forged tokens do; an expired agent
// credential on egress does not.
func TestAgentLimiter(t *testing.T) {
	e, _ := delegationEnv(t, false)
	sess := e.session(alice)
	const ip = "198.51.100.7"
	// Many policy refusals from one IP: the next legitimate exchange works.
	for range authFailBurst + 5 {
		if w := e.exchangeFrom(ip, delegForm(sess, tokenTypeSession, "rogue")); w.Code != http.StatusBadRequest {
			t.Fatalf("policy refusal: %d %s", w.Code, w.Body)
		}
	}
	if w := e.exchangeFrom(ip, delegForm(sess, tokenTypeSession, "reviewer")); w.Code != http.StatusOK {
		t.Fatalf("policy refusals locked out an authenticated caller: %d %s", w.Code, w.Body)
	}
	// An expired agent credential on egress: 401 every time, never a lockout.
	expired, _ := e.delegate(t, delegForm(sess, tokenTypeSession, "reviewer", paramExpiresIn, "60"))
	fresh, _ := e.delegate(t, delegForm(sess, tokenTypeSession, "reviewer"))
	*e.now = e.now.Add(2 * time.Minute)
	for range authFailBurst + 5 {
		if w := e.egressFrom(ip, expired.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusUnauthorized {
			t.Fatalf("expired credential: %d %s", w.Code, w.Body)
		}
	}
	if w := e.egressFrom(ip, fresh.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusOK {
		t.Fatalf("expired credentials locked the IP out: %d %s", w.Code, w.Body)
	}
	// Forged credentials spend the agent budget, not the CI exchange's.
	for range authFailBurst {
		e.exchangeFrom(ip, delegForm(sess+"x", tokenTypeSession, "reviewer"))
	}
	if !e.s.agentFails.blocked(ip) || e.s.exchangeFails.blocked(ip) {
		t.Fatalf("buckets: agent blocked=%v ci blocked=%v", e.s.agentFails.blocked(ip), e.s.exchangeFails.blocked(ip))
	}
	if w := e.egressFrom(ip, fresh.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked IP at egress: %d", w.Code)
	}
	const ip2 = "198.51.100.8"
	for range authFailBurst {
		e.egressFrom(ip2, "garbage.garbage.garbage", `{"agent":"billing"}`)
	}
	if !e.s.agentFails.blocked(ip2) {
		t.Fatal("garbage egress bearers did not count")
	}
}

// TestDelegationAuditsRefusedParents (L1): refusing a verified parent (its
// root revoked) and an unresolvable policy are audited as
// agent.token.denied with the root and the parent's jti.
func TestDelegationAuditsRefusedParents(t *testing.T) {
	e, _ := delegationEnv(t, false)
	parent, pc := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "planner", paramActorHarness, "claude-code"))

	org, _, _ := e.s.pol.Get()
	saved := map[string]string{}
	for _, r := range org.Rings {
		saved[r.Name], r.Profile = r.Profile, "no-such-profile"
	}
	if w := e.exchange(delegForm(parent.AccessToken, tokenTypeJWT, "reviewer")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unresolvable policy: %d %s", w.Code, w.Body)
	}
	if a := lastAuditOf(t, e, "agent.token.denied"); a.Actor != alice.ID || a.Details["parentJti"] != pc.ID || !strings.Contains(a.Details["reason"], "cannot be resolved") {
		t.Fatalf("scope error audit: %+v", a)
	}
	for _, r := range org.Rings {
		r.Profile = saved[r.Name]
	}

	*e.now = e.now.Add(2 * time.Second)
	if err := e.s.revoked.revoke(alice.ID, *e.now); err != nil {
		t.Fatal(err)
	}
	if w := e.exchange(delegForm(parent.AccessToken, tokenTypeJWT, "reviewer")); w.Code != http.StatusBadRequest {
		t.Fatalf("revoked root: %d %s", w.Code, w.Body)
	}
	if a := lastAuditOf(t, e, "agent.token.denied"); a.Actor != alice.ID || a.Details["parentJti"] != pc.ID || !strings.Contains(a.Details["reason"], "revoked") {
		t.Fatalf("revoked-root audit: %+v", a)
	}
}

// TestDelegationAuditsDeprovisionedParent (L1): a deprovisioned root's
// verified parent is refused, audited with the root and the jti.
func TestDelegationAuditsDeprovisionedParent(t *testing.T) {
	e, _ := delegationEnv(t, true)
	e.createSCIMUser(t, alice.ID, true)
	parent, pc := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "planner", paramActorHarness, "claude-code"))
	u, _, _ := e.s.scim.store.Lookup(alice.ID)
	u.Active = false
	if err := e.s.scim.store.PutUser(u); err != nil {
		t.Fatal(err)
	}
	if w := e.exchange(delegForm(parent.AccessToken, tokenTypeJWT, "reviewer")); w.Code != http.StatusBadRequest {
		t.Fatalf("deprovisioned root: %d %s", w.Code, w.Body)
	}
	if a := lastAuditOf(t, e, "agent.token.denied"); a.Actor != alice.ID || a.Details["parentJti"] != pc.ID || !strings.Contains(a.Details["reason"], "deactivated") {
		t.Fatalf("deprovisioned-root audit: %+v", a)
	}
}

// TestEgressAllowIsAuditStrict (L1): no allow without its audit record; a
// refusal is still answered when the audit log is down, and counted.
func TestEgressAllowIsAuditStrict(t *testing.T) {
	e, _ := delegationEnv(t, false, func(c *Config) { c.DataDir = t.TempDir() })
	resp, _ := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "reviewer"))
	_ = e.s.auditLog.f.Close() // every append now errors
	if w := e.egress(resp.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), `"allow":true`) {
		t.Fatalf("allow without an audit record: %d %s", w.Code, w.Body)
	}
	if w := e.egress(resp.AccessToken, `{"agent":"elsewhere"}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"allow":false`) {
		t.Fatalf("refusal: %d %s", w.Code, w.Body)
	}
	var m strings.Builder
	e.s.WriteMetrics(&m)
	if !strings.Contains(m.String(), "halo_server_audit_append_errors_total 2\n") {
		t.Fatalf("audit failures not counted:\n%s", m.String())
	}
}

// TestDelegationActorLabels (L2): harness and session are labels limited to
// [A-Za-z0-9._:-]; a value that would forge structure in the audit chain
// detail or a terminal is refused before anything is audited.
func TestDelegationActorLabels(t *testing.T) {
	e, _ := delegationEnv(t, false)
	before := len(e.auditActions(t))
	for name, kv := range map[string][]string{
		"chain forgery in harness": {paramActorHarness, "claude-code/x)>admin(codex"},
		"newline in session":       {paramActorSession, "s1\nagent.token.exchange"},
		"escape in session":        {paramActorSession, "\x1b[2J"},
		"session too long":         {paramActorSession, strings.Repeat("a", 257)},
	} {
		w := e.exchange(delegForm(e.session(alice), tokenTypeSession, "reviewer", kv...))
		if code, _ := oauthErrOf(w); w.Code != http.StatusBadRequest || code != "invalid_request" {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if n := len(e.auditActions(t)); n != before {
		t.Fatalf("refused labels reached the audit log: %d entries", n-before)
	}
	_, c := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "reviewer", paramActorHarness, "claude-code", paramActorSession, "a1b2:c3.d4_e5-f6"))
	if c.Act.Session != "a1b2:c3.d4_e5-f6" {
		t.Fatalf("valid labels: %+v", c.Act)
	}
}

// TestDelegationExpiresInOverflow (L7): a huge expires_in is a 400 and
// audited, never a wrapped negative lifetime and a 500.
func TestDelegationExpiresInOverflow(t *testing.T) {
	e, _ := delegationEnv(t, false)
	for _, v := range []string{"9223372037", "9223372036854775807", "99999999999999999999"} {
		w := e.exchange(delegForm(e.session(alice), tokenTypeSession, "reviewer", paramExpiresIn, v))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expires_in=%s: %d %s", v, w.Code, w.Body)
		}
		if a := lastAuditOf(t, e, "agent.token.denied"); !strings.Contains(a.Details["reason"], "expires_in") {
			t.Fatalf("expires_in=%s audit: %+v", v, a)
		}
	}
}
