package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

const agentsYAML = `agents:
  maxTTLSeconds: 900
  allowedModels: [sonnet, haiku]
  deniedTools: [Bash]
  actors:
    - {name: planner, harnesses: [claude-code]}
    - {name: reviewer}
    - {name: tester}
    - {name: haiku-only, models: [haiku]}
    - {name: platform-only, groups: [platform-admins]}
  remote:
    - name: billing
      cardURL: https://agents.billing.example/.well-known/agent-card.json
      digest: sha256:` + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + `
      skills: [lookup-invoice]
      rings: [ring3-ga]
    - name: payments-bot
      cardURL: https://pay.example/.well-known/agent-card.json
      digest: sha256:` + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" + `
      units: [payments]
`

// delegationEnv is newEnv (acme-corp, fixed clock) with halos.yaml agents and
// a workload key; scim turns the SCIM directory on (authoritative).
func delegationEnv(t *testing.T, scim bool) (*env, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(c *Config) {
		c.WorkloadKey = priv
		f := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, append(b, []byte(agentsYAML)...), 0o600); err != nil {
			t.Fatal(err)
		}
		org, err := policy.Load(c.PolicyDir)
		if err != nil {
			t.Fatal(err)
		}
		if issues := org.Validate(); policy.HasErrors(issues) {
			t.Fatalf("fixture invalid: %v", issues)
		}
	}
	if scim {
		return scimEnv(t, true, mutate), priv
	}
	return newEnv(t, mutate), priv
}

var alice = Principal{ID: "alice@acme.example", Groups: []string{"eng"}}

func (e *env) session(p Principal) string {
	return e.s.seal(cookiePayload{Sub: p.ID, Groups: p.Groups, Iat: e.now.Add(-time.Minute).UnixNano(), Exp: e.now.Add(time.Hour).Unix()})
}

func delegForm(subject, typ, agent string, kv ...string) url.Values {
	f := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {subject}, "subject_token_type": {typ}, paramActorID: {agent}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Set(kv[i], kv[i+1])
	}
	return f
}

var delegIP = 0

func (e *env) exchange(f url.Values) *httptest.ResponseRecorder {
	delegIP++ // a fresh client IP each time: negative cases must not trip the limiter for each other
	r := httptest.NewRequest("POST", "/api/v1/token/exchange", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113." + strconv.Itoa(delegIP%250+1) + ":4444"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *env) delegate(t *testing.T, f url.Values) (TokenExchangeResponse, identity.DelegatedClaims) {
	t.Helper()
	w := e.exchange(f)
	if w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	var resp TokenExchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	c, err := identity.VerifyDelegatedToken(e.s.workloadPub(), resp.AccessToken, *e.now)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	return resp, c
}

func oauthErrOf(w *httptest.ResponseRecorder) (string, string) {
	var m map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m["error"], m["error_description"]
}

// TestDelegationFromSession: a human session becomes an agent credential with
// the human as subject, the act chain, the policy's model scope and the
// TTL cap, and the exchange is audited with the full chain.
func TestDelegationFromSession(t *testing.T) {
	e, _ := delegationEnv(t, false)
	resp, c := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "planner", paramActorHarness, "claude-code", paramActorSession, "s-1"))
	if c.Subject != alice.ID || c.RootKind != "" || !slices.Equal(c.Groups, alice.Groups) {
		t.Fatalf("root: %+v", c)
	}
	if ch := c.Chain(); len(ch) != 1 || ch[0] != (policy.Actor{Agent: "planner", Harness: "claude-code", Session: "s-1"}) {
		t.Fatalf("chain: %+v", ch)
	}
	if !slices.Equal(c.Models, []string{"sonnet", "haiku"}) || resp.ExpiresIn != 900 || c.Expiry-c.IssuedAt != 900 {
		t.Fatalf("scope/ttl: models=%v ttl=%d", c.Models, resp.ExpiresIn)
	}
	if !slices.Equal(resp.Actors, []string{"planner"}) || resp.Subject != alice.ID {
		t.Fatalf("response: %+v", resp)
	}
	ents := e.auditActions(t)
	last := ents[len(ents)-1]
	if last.Action != "agent.token.exchange" || last.Actor != alice.ID || last.Target != "planner" ||
		last.Details["chain"] != "planner(claude-code/s-1)" || last.Details["via"] != "session" || last.Details["jti"] != c.ID {
		t.Fatalf("audit: %+v", last)
	}
	if strings.Contains(strings.Join(slices.Collect(mapValues(last.Details)), " "), resp.AccessToken) {
		t.Fatal("audit holds the token")
	}
}

func mapValues(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for _, v := range m {
			if !yield(v) {
				return
			}
		}
	}
}

// TestDelegationChainDepthAndCycles: a delegate can delegate again up to the
// default depth 2; depth 3 and a repeated agent (a cycle) are refused and audited.
func TestDelegationChainDepthAndCycles(t *testing.T) {
	e, _ := delegationEnv(t, false)
	first, _ := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "planner", paramActorHarness, "claude-code"))
	second, c2 := e.delegate(t, delegForm(first.AccessToken, tokenTypeJWT, "reviewer", paramActorHarness, "codex"))
	if got := c2.Chain(); len(got) != 2 || got[0].Agent != "planner" || got[1].Agent != "reviewer" || c2.Act.Subject != "agent:reviewer" || c2.Act.Act.Subject != "agent:planner" {
		t.Fatalf("RFC 8693 nesting: current actor on top: %+v", c2.Act)
	}
	if c2.Subject != alice.ID || c2.Parent == "" {
		t.Fatalf("root or parent lost: %+v", c2)
	}
	for name, f := range map[string]url.Values{
		"depth 3": delegForm(second.AccessToken, tokenTypeJWT, "tester"),
		"cycle":   delegForm(first.AccessToken, tokenTypeJWT, "planner", paramActorHarness, "claude-code"),
	} {
		w := e.exchange(f)
		if code, desc := oauthErrOf(w); w.Code != http.StatusBadRequest || code != "invalid_grant" {
			t.Errorf("%s: %d %s %s", name, w.Code, code, desc)
		}
	}
	denied := 0
	for _, a := range e.auditActions(t) {
		if a.Action == "agent.token.denied" {
			denied++
			if !strings.Contains(a.Details["chain"], "planner(claude-code/)>") {
				t.Errorf("denial audit lacks the chain: %+v", a.Details)
			}
		}
	}
	if denied != 2 {
		t.Fatalf("denials audited: %d", denied)
	}
}

// TestDelegationScopeEscalation: a child can never gain groups, models or
// lifetime, and an agent outside policy, a wrong harness or a root outside the
// agent's groups is refused.
func TestDelegationScopeEscalation(t *testing.T) {
	e, _ := delegationEnv(t, false)
	sess := e.session(alice)
	haikuOnly, _ := e.delegate(t, delegForm(sess, tokenTypeSession, "reviewer", "scope", "model:haiku"))
	for _, tc := range []struct {
		name string
		form url.Values
		code string
	}{
		{"extra group", delegForm(sess, tokenTypeSession, "reviewer", "scope", "group:eng group:platform-admins"), "invalid_scope"},
		{"swapped group", delegForm(sess, tokenTypeSession, "reviewer", "scope", "group:platform-admins"), "invalid_scope"},
		{"narrowed groups", delegForm(e.session(Principal{ID: "bob@acme.example", Groups: []string{"eng", "payments-eng"}}), tokenTypeSession, "reviewer", "scope", "group:eng"), "invalid_scope"},
		{"model outside policy", delegForm(sess, tokenTypeSession, "reviewer", "scope", "model:opus"), "invalid_scope"},
		{"model outside parent", delegForm(haikuOnly.AccessToken, tokenTypeJWT, "tester", "scope", "model:sonnet"), "invalid_scope"},
		{"model outside actor", delegForm(sess, tokenTypeSession, "haiku-only", "scope", "model:sonnet"), "invalid_scope"},
		{"unknown scope token", delegForm(sess, tokenTypeSession, "reviewer", "scope", "admin"), "invalid_scope"},
		{"ttl beyond policy", delegForm(sess, tokenTypeSession, "reviewer", paramExpiresIn, "901"), "invalid_scope"},
		{"agent not in policy", delegForm(sess, tokenTypeSession, "rogue"), "invalid_grant"},
		{"wrong harness", delegForm(sess, tokenTypeSession, "planner", paramActorHarness, "codex"), "invalid_grant"},
		{"root outside agent groups", delegForm(sess, tokenTypeSession, "platform-only"), "invalid_grant"},
		{"no actor", delegForm(sess, tokenTypeSession, ""), "invalid_request"},
		{"bad expires_in", delegForm(sess, tokenTypeSession, "reviewer", paramExpiresIn, "-5"), "invalid_request"},
	} {
		w := e.exchange(tc.form)
		if code, desc := oauthErrOf(w); w.Code != http.StatusBadRequest || code != tc.code {
			t.Errorf("%s: %d %s (%s), want %s", tc.name, w.Code, code, desc, tc.code)
		}
	}
	// The child of a haiku-only parent inherits haiku, never the policy's wider list.
	_, c := e.delegate(t, delegForm(haikuOnly.AccessToken, tokenTypeJWT, "tester"))
	if !slices.Equal(c.Models, []string{"haiku"}) {
		t.Fatalf("child widened the parent's models: %v", c.Models)
	}
}

// TestDelegationTTLBoundedByParent: a child never outlives its parent; asking
// for longer is refused, the default is clamped.
func TestDelegationTTLBoundedByParent(t *testing.T) {
	e, _ := delegationEnv(t, false)
	parent, pc := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "planner", paramActorHarness, "claude-code", paramExpiresIn, "300"))
	*e.now = e.now.Add(100 * time.Second)
	w := e.exchange(delegForm(parent.AccessToken, tokenTypeJWT, "reviewer", paramExpiresIn, "250"))
	if code, _ := oauthErrOf(w); code != "invalid_scope" {
		t.Fatalf("child TTL past the parent's: %d %s", w.Code, w.Body)
	}
	_, c := e.delegate(t, delegForm(parent.AccessToken, tokenTypeJWT, "reviewer"))
	if c.Expiry > pc.Expiry || c.Expiry-c.IssuedAt != 200 {
		t.Fatalf("child exp %d, parent exp %d", c.Expiry, pc.Expiry)
	}
}

// TestDelegationRefusesForgedAndDeadParents: an altered act chain, a token
// signed by another key, a revoked session and a deprovisioned root all fail.
func TestDelegationRefusesForgedAndDeadParents(t *testing.T) {
	e, _ := delegationEnv(t, true)
	id := e.createSCIMUser(t, alice.ID, true)
	parent, pc := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "planner", paramActorHarness, "claude-code"))

	forged := pc
	forged.Act = identity.ActFromChain([]policy.Actor{{Agent: "reviewer"}})
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	byOther, err := identity.SignDelegatedToken(other, forged)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(parent.AccessToken, ".")
	swapped, _ := identity.SignDelegatedToken(other, forged)
	spliced := parts[0] + "." + strings.Split(swapped, ".")[1] + "." + parts[2] // our header and signature, a rewritten act
	for name, tok := range map[string]string{"other key": byOther, "spliced act": spliced} {
		if w := e.exchange(delegForm(tok, tokenTypeJWT, "reviewer")); w.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", name, w.Code, w.Body)
		}
	}

	// Deactivated in the directory: the chain dies with its root, even where
	// the session revocation that SCIM deprovisioning also writes has not
	// reached this replica (the store is written directly here).
	u, _, _ := e.s.scim.store.Lookup(alice.ID)
	u.Active = false
	if err := e.s.scim.store.PutUser(u); err != nil {
		t.Fatal(err)
	}
	if w := e.exchange(delegForm(parent.AccessToken, tokenTypeJWT, "reviewer")); w.Code != http.StatusBadRequest {
		t.Fatalf("inactive root's agent delegated: %d %s", w.Code, w.Body)
	}
	u.Active = true
	if err := e.s.scim.store.PutUser(u); err != nil {
		t.Fatal(err)
	}
	// Deprovisioned through SCIM: the chain dies with its root.
	if w := e.scim("PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"active","value":false}]}`); w.Code != http.StatusOK {
		t.Fatalf("deactivate: %d %s", w.Code, w.Body)
	}
	if w := e.exchange(delegForm(parent.AccessToken, tokenTypeJWT, "reviewer")); w.Code != http.StatusBadRequest {
		t.Fatalf("deprovisioned root's agent delegated: %d %s", w.Code, w.Body)
	}
}

func TestDelegationRevokedSession(t *testing.T) {
	e, _ := delegationEnv(t, false)
	parent, _ := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "planner", paramActorHarness, "claude-code"))
	*e.now = e.now.Add(2 * time.Second)
	if err := e.s.revoked.revoke(alice.ID, *e.now); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]url.Values{
		"session":   delegForm(e.session(alice), tokenTypeSession, "reviewer"),
		"its agent": delegForm(parent.AccessToken, tokenTypeJWT, "reviewer"),
	} {
		if w := e.exchange(f); w.Code != http.StatusBadRequest {
			t.Errorf("%s after revoke-sessions: %d %s", name, w.Code, w.Body)
		}
	}
}

func TestDelegationFromWorkload(t *testing.T) {
	e, priv := delegationEnv(t, false)
	now := *e.now
	wl, err := identity.SignWorkloadToken(priv, identity.WorkloadClaims{Issuer: identity.WorkloadIssuer, Subject: "workload:gh:acme/app", Audience: identity.WorkloadAudience,
		Groups: []string{"ai-platform"}, Kind: policy.SubjectWorkload, Rule: "main", IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(10 * time.Minute).Unix(), ID: "wl-1"})
	if err != nil {
		t.Fatal(err)
	}
	resp, c := e.delegate(t, delegForm(wl, tokenTypeJWT, "reviewer"))
	if c.RootKind != policy.SubjectWorkload || c.Subject != "workload:gh:acme/app" || c.Parent != "wl-1" || resp.ExpiresIn != 600 {
		t.Fatalf("workload root: %+v ttl %d", c, resp.ExpiresIn)
	}
	if resp.Ring != "ring0-harness-team" {
		t.Fatalf("ring is the root's: %q", resp.Ring)
	}
}

func TestDelegationDisabled(t *testing.T) {
	e := newEnv(t, func(c *Config) { _, c.WorkloadKey, _ = ed25519.GenerateKey(rand.Reader) })
	if w := e.exchange(delegForm(e.session(alice), tokenTypeSession, "planner")); w.Code != http.StatusNotFound {
		t.Fatalf("no agents policy: %d %s", w.Code, w.Body)
	}
}

func (e *env) egress(tok string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/agents/egress", strings.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// TestAgentEgressDecision: the remote-agent allowlist by ring, unit and
// skill, decided for the verified root, never for a header or a body field.
func TestAgentEgressDecision(t *testing.T) {
	e, _ := delegationEnv(t, true)
	e.createSCIMUser(t, alice.ID, true)
	e.createSCIMGroup(t, "payments-eng", e.createSCIMUser(t, "pat@acme.example", true))
	tokFor := func(p Principal) string {
		resp, _ := e.delegate(t, delegForm(e.session(p), tokenTypeSession, "reviewer"))
		return resp.AccessToken
	}
	al, pat := tokFor(alice), tokFor(Principal{ID: "pat@acme.example"})
	for _, tc := range []struct {
		name, tok, body string
		allow           bool
	}{
		{"ring member, allowed skill", al, `{"agent":"billing","skill":"lookup-invoice"}`, true},
		{"by card origin", al, `{"url":"https://agents.billing.example/a2a/v1"}`, true},
		{"skill not allowed", al, `{"agent":"billing","skill":"refund"}`, false},
		{"unknown agent", al, `{"agent":"elsewhere"}`, false},
		{"unknown origin", al, `{"url":"https://evil.example/a2a"}`, false},
		{"unit-only agent, not in unit", al, `{"agent":"payments-bot"}`, false},
		{"unit-only agent, unit member", pat, `{"agent":"payments-bot"}`, true},
	} {
		w := e.egress(tc.tok, tc.body)
		var d policy.RemoteDecision
		if err := json.Unmarshal(w.Body.Bytes(), &d); w.Code != http.StatusOK || err != nil || d.Allow != tc.allow {
			t.Errorf("%s: %d %s", tc.name, w.Code, w.Body)
		}
	}
	if w := e.egress("", `{"agent":"billing"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("no credential: %d", w.Code)
	}
	if w := e.egress(e.session(alice), `{"agent":"billing"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("session cookie as bearer: %d", w.Code)
	}
	var allow, deny int
	for _, a := range e.auditActions(t) {
		switch a.Action {
		case "agent.egress.allow":
			allow++
		case "agent.egress.deny":
			deny++
		}
	}
	if allow != 3 || deny != 4 {
		t.Fatalf("audit allow=%d deny=%d", allow, deny)
	}
}
