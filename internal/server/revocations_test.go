package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Per-credential revocation (ADR-0026).

func (e *env) revoke(t *testing.T, body string) Revocation {
	t.Helper()
	w := e.as(admin, "POST", "/api/v1/revocations", body)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke %s: %d %s", body, w.Code, w.Body)
	}
	return decode[Revocation](t, w)
}

func (e *env) workloadToken(t *testing.T, priv ed25519.PrivateKey, jti string) string {
	t.Helper()
	now := *e.now
	tok, err := identity.SignWorkloadToken(priv, identity.WorkloadClaims{Issuer: identity.WorkloadIssuer, Subject: "workload:gh:acme/app", Audience: identity.WorkloadAudience,
		Groups: []string{"ai-platform"}, Kind: policy.SubjectWorkload, Rule: "main", IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(10 * time.Minute).Unix(), ID: jti})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestRevocationAPI: admin only, reason required, exactly one target,
// validated; listed with who and why; audited; a failed audit is a 500 and
// the revocation still holds.
func TestRevocationAPI(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.DataDir = t.TempDir() })
	for _, c := range []struct {
		name, body string
		who        Principal
		want       int
	}{
		{"developer", `{"jti":"abc","reason":"x"}`, dev, http.StatusForbidden},
		{"no reason", `{"jti":"abc","reason":"  "}`, admin, http.StatusBadRequest},
		{"both", `{"jti":"abc","subject":"agent:planner","reason":"x"}`, admin, http.StatusBadRequest},
		{"neither", `{"reason":"x"}`, admin, http.StatusBadRequest},
		{"bad jti", `{"jti":"a b","reason":"x"}`, admin, http.StatusBadRequest},
		{"bad agent", `{"subject":"agent:Not_A_Name!","reason":"x"}`, admin, http.StatusBadRequest},
		{"control character", `{"subject":"bob\u0007@acme.example","reason":"x"}`, admin, http.StatusBadRequest},
		{"unknown field", `{"jti":"abc","reason":"x","extra":1}`, admin, http.StatusOK}, // tolerated, like other admin bodies
	} {
		if w := e.as(c.who, "POST", "/api/v1/revocations", c.body); w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, w.Code, w.Body, c.want)
		}
	}
	r := e.revoke(t, `{"subject":"agent:planner","reason":"prompt-injected in run 42"}`)
	if r.Subject != "agent:planner" || r.RevokedBefore == nil || !r.RevokedBefore.Equal(e.now.Add(revocationSkew).Truncate(time.Second)) || r.By != admin.ID {
		t.Fatalf("subject revocation: %+v", r)
	}
	if a := lastAuditOf(t, e, "credential.revoke"); a.Actor != admin.ID || a.Target != "agent:planner" || a.Details["reason"] != "prompt-injected in run 42" || a.Details["kind"] != "subject" {
		t.Fatalf("audit: %+v", a)
	}
	if w := e.as(dev, "GET", "/api/v1/revocations", ""); w.Code != http.StatusForbidden {
		t.Fatalf("developer listing: %d", w.Code)
	}
	list := decode[RevocationsResponse](t, e.as(admin, "GET", "/api/v1/revocations", "")).Revocations
	if len(list) != 2 || list[0].JTI != "abc" || list[1].Subject != "agent:planner" || list[1].Reason != "prompt-injected in run 42" {
		t.Fatalf("list: %+v", list)
	}
	_ = e.s.auditLog.f.Close()
	if w := e.as(admin, "POST", "/api/v1/revocations", `{"jti":"def","reason":"x"}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("revocation without its audit record: %d", w.Code)
	}
	if list := decode[RevocationsResponse](t, e.as(admin, "GET", "/api/v1/revocations", "")).Revocations; !slices.ContainsFunc(list, func(r Revocation) bool { return r.JTI == "def" }) {
		t.Fatal("a failed audit undid the revocation")
	}
	// A restart keeps them (file backend); expired rows are dropped.
	_ = e.s.Close()
	rl, err := openRevocationLog(storage.Dir(e.s.cfg.DataDir), func() time.Time { return *e.now })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rl.close() }()
	if got, _ := rl.Revocations(context.Background()); len(got) != 3 {
		t.Fatalf("revocations after restart: %+v", got)
	}
	rl.now = func() time.Time { return e.now.Add(revocationSkew + revocationLife + time.Second) }
	if got, _ := rl.Revocations(context.Background()); len(got) != 0 {
		t.Fatalf("expired revocations served: %+v", got)
	}
}

// TestRevokedJTIKillsLineage: revoking a credential's jti kills it, every
// credential exchanged from it (children and grandchildren, through
// anc_jti), at the exchange and at egress; others are untouched.
func TestRevokedJTIKillsLineage(t *testing.T) {
	e, priv := delegationEnv(t, false)
	wl := e.workloadToken(t, priv, "wl-1")
	a, ac := e.delegate(t, delegForm(wl, tokenTypeJWT, "reviewer"))
	b, bc := e.delegate(t, delegForm(a.AccessToken, tokenTypeJWT, "tester"))
	if bc.Parent != ac.ID || !slices.Equal(bc.Ancestors, []string{"wl-1"}) || ac.Parent != "wl-1" || ac.Ancestors != nil {
		t.Fatalf("lineage: a=%s/%v b=%s/%v", ac.Parent, ac.Ancestors, bc.Parent, bc.Ancestors)
	}
	other, _ := e.delegate(t, delegForm(e.workloadToken(t, priv, "wl-2"), tokenTypeJWT, "reviewer"))
	for _, tok := range []string{a.AccessToken, b.AccessToken, other.AccessToken} {
		if w := e.egress(tok, `{"agent":"billing"}`); w.Code != http.StatusOK {
			t.Fatalf("before revocation: %d %s", w.Code, w.Body)
		}
	}
	e.revoke(t, `{"jti":"wl-1","reason":"token printed in a CI log"}`)
	for name, tok := range map[string]string{"child": a.AccessToken, "grandchild": b.AccessToken} {
		if w := e.egress(tok, `{"agent":"billing"}`); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "revoked") {
			t.Errorf("%s of a revoked credential at egress: %d %s", name, w.Code, w.Body)
		}
	}
	if a := lastAuditOf(t, e, "agent.egress.deny"); !strings.Contains(a.Details["reason"], "wl-1") {
		t.Fatalf("egress refusal audit: %+v", a)
	}
	if w := e.exchange(delegForm(wl, tokenTypeJWT, "reviewer")); w.Code != http.StatusBadRequest {
		t.Fatalf("exchange from a revoked credential: %d %s", w.Code, w.Body)
	}
	if a := lastAuditOf(t, e, "agent.token.denied"); !strings.Contains(a.Details["reason"], "revoked") || a.Details["parentJti"] != "wl-1" {
		t.Fatalf("exchange refusal audit: %+v", a)
	}
	if w := e.exchange(delegForm(a.AccessToken, tokenTypeJWT, "tester")); w.Code != http.StatusBadRequest {
		t.Fatalf("exchange from a revoked credential's child: %d %s", w.Code, w.Body)
	}
	if w := e.egress(other.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusOK {
		t.Fatalf("an unrelated credential: %d %s", w.Code, w.Body)
	}
}

// TestRevokedSubjectEpoch: an agent's epoch kills every credential issued at
// or before it with that agent anywhere in the chain; no new credential for
// it is minted until the (skew-padded) epoch has passed; a workload epoch
// kills chains rooted in it; a human root's revocation ends their sessions
// and their agents, and a fresh login delegates at once.
func TestRevokedSubjectEpoch(t *testing.T) {
	e, priv := delegationEnv(t, false)
	sess := e.session(alice)
	p, _ := e.delegate(t, delegForm(sess, tokenTypeSession, "planner", paramActorHarness, "claude-code"))
	pr, _ := e.delegate(t, delegForm(p.AccessToken, tokenTypeJWT, "reviewer"))
	direct, _ := e.delegate(t, delegForm(sess, tokenTypeSession, "reviewer"))

	e.revoke(t, `{"subject":"agent:planner","reason":"compromised"}`)
	for name, tok := range map[string]string{"planner": p.AccessToken, "planner>reviewer": pr.AccessToken} {
		if w := e.egress(tok, `{"agent":"billing"}`); w.Code != http.StatusForbidden {
			t.Errorf("%s after the planner epoch: %d %s", name, w.Code, w.Body)
		}
	}
	if w := e.egress(direct.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusOK {
		t.Fatalf("a chain without planner: %d %s", w.Code, w.Body)
	}
	if w := e.exchange(delegForm(sess, tokenTypeSession, "planner", paramActorHarness, "claude-code")); w.Code != http.StatusBadRequest {
		t.Fatalf("new planner credential within the epoch pad: %d %s", w.Code, w.Body)
	}
	*e.now = e.now.Add(revocationSkew + time.Second)
	fresh, _ := e.delegate(t, delegForm(sess, tokenTypeSession, "planner", paramActorHarness, "claude-code"))
	if w := e.egress(fresh.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusOK {
		t.Fatalf("planner credential minted after the epoch: %d %s", w.Code, w.Body)
	}

	wa, _ := e.delegate(t, delegForm(e.workloadToken(t, priv, "wl-9"), tokenTypeJWT, "reviewer"))
	e.revoke(t, `{"subject":"workload:gh:acme/app","reason":"repo compromised"}`)
	if w := e.egress(wa.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusForbidden {
		t.Fatalf("workload-rooted chain after the workload epoch: %d %s", w.Code, w.Body)
	}

	*e.now = e.now.Add(time.Second)
	before, _ := e.delegate(t, delegForm(e.session(alice), tokenTypeSession, "reviewer"))
	e.revoke(t, `{"subject":"Alice@ACME.example","reason":"left the company"}`)
	if w := e.egress(before.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusForbidden {
		t.Fatalf("human root's agent after revocation: %d %s", w.Code, w.Body)
	}
	if w := e.sessionAt(alice, e.now.Add(-time.Second), "GET", "/api/v1/me"); w.Code != http.StatusUnauthorized {
		t.Fatalf("human root's session after revocation: %d", w.Code)
	}
	iat, ok := e.s.revoked.issueAt(alice.ID, *e.now) // what the OIDC callback stamps on a new login
	if !ok {
		t.Fatal("issueAt")
	}
	login := e.s.seal(cookiePayload{Sub: alice.ID, Groups: alice.Groups, Iat: iat, Exp: e.now.Add(time.Hour).Unix()})
	after, _ := e.delegate(t, delegForm(login, tokenTypeSession, "reviewer"))
	if w := e.egress(after.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusOK {
		t.Fatalf("a fresh login after the revocation: %d %s", w.Code, w.Body)
	}
}

// TestGatewayRevocationList: the directory endpoint serves the list to the
// directory token (SCIM not required), and it kills what halo-server kills.
func TestGatewayRevocationList(t *testing.T) {
	e, priv := delegationEnv(t, false, func(c *Config) { c.GatewayDirectoryToken = gwTok })
	_, ac := e.delegate(t, delegForm(e.workloadToken(t, priv, "wl-1"), tokenTypeJWT, "reviewer"))
	e.revoke(t, `{"jti":"wl-1","reason":"x"}`)
	if w := do(e.h, "GET", "/api/v1/gateway/directory?revocations=1", "Bearer wrong", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong gateway token: %d", w.Code)
	}
	if w := do(e.h, "GET", "/api/v1/gateway/directory?subject=x", "Bearer "+gwTok, ""); w.Code != http.StatusNotFound {
		t.Fatalf("subject lookup without SCIM: %d", w.Code)
	}
	l := decode[gateway.RevocationList](t, do(e.h, "GET", "/api/v1/gateway/directory?revocations=1", "Bearer "+gwTok, ""))
	sub := ac.AsSubject()
	if err := l.Check(&sub); !errors.Is(err, gateway.ErrCredentialRevoked) {
		t.Fatalf("gateway list does not kill the child: %v (%+v)", err, l)
	}
}

// TestRevocationReachesGatewayWithinBound: through the real endpoint, a
// gateway's DirectoryClient refuses a revoked credential once its list is
// RevocationTTL old (the stated bound), and not before.
func TestRevocationReachesGatewayWithinBound(t *testing.T) {
	e, priv := delegationEnv(t, false, func(c *Config) { c.GatewayDirectoryToken = gwTok })
	srv := httptest.NewServer(e.h)
	t.Cleanup(srv.Close)
	dc, err := gateway.NewDirectoryClient(srv.URL+"/api/v1/gateway/directory", gwTok, 0, 0, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	clock := *e.now
	dc.Now = func() time.Time { return clock }
	_, c := e.delegate(t, delegForm(e.workloadToken(t, priv, "wl-1"), tokenTypeJWT, "reviewer"))
	sub := c.AsSubject()
	ctx := context.Background()
	if _, err := dc.Resolve(ctx, &sub); err != nil {
		t.Fatalf("before revocation: %v", err)
	}
	e.revoke(t, `{"jti":"`+c.ID+`","reason":"x"}`)
	clock = clock.Add(gateway.DefaultRevocationTTL - time.Second)
	if _, err := dc.Resolve(ctx, &sub); err != nil {
		t.Fatalf("within the bound the cached list serves: %v", err)
	}
	clock = clock.Add(time.Second)
	if _, err := dc.Resolve(ctx, &sub); !errors.Is(err, gateway.ErrCredentialRevoked) {
		t.Fatalf("at the bound (%s): %v, want revoked", gateway.DefaultRevocationTTL, err)
	}
}

func TestRevocationsAcrossReplicasInMemory(t *testing.T) { testRevocationReplicas(t, newMemShared()) }

func TestRevocationsAcrossReplicasPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	testRevocationReplicas(t, NewPGBackend(db))
}

// testRevocationReplicas: a revocation made on one replica holds on the
// other at once (shared store, no cache), and both serve it to gateways.
func testRevocationReplicas(t *testing.T, b Backend) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *env {
		kills, err := controller.NewKillStore(context.Background(), b)
		if err != nil {
			t.Fatal(err)
		}
		e, _ := delegationEnv(t, false, func(c *Config) { c.Backend, c.KillStore, c.WorkloadKey, c.GatewayDirectoryToken = b, kills, key, gwTok })
		*e.now = time.Now().UTC() // shared expiries are judged on the database clock
		return e
	}
	a, c := mk(), mk()
	resp, _ := a.delegate(t, delegForm(a.workloadToken(t, key, "wl-r1"), tokenTypeJWT, "reviewer"))
	if w := c.egress(resp.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusOK {
		t.Fatalf("before: %d %s", w.Code, w.Body)
	}
	a.revoke(t, `{"jti":"wl-r1","reason":"x"}`)
	if w := c.egress(resp.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusForbidden {
		t.Fatalf("revoked on a, accepted by c: %d %s", w.Code, w.Body)
	}
	l := decode[gateway.RevocationList](t, do(c.h, "GET", "/api/v1/gateway/directory?revocations=1", "Bearer "+gwTok, ""))
	if _, ok := l.JTIs["wl-r1"]; !ok {
		t.Fatalf("c's gateway list: %+v", l)
	}
	if list := decode[RevocationsResponse](t, c.as(admin, "GET", "/api/v1/revocations", "")).Revocations; len(list) != 1 || list[0].By != admin.ID {
		t.Fatalf("c's admin list: %+v", list)
	}
}

// TestRevocationsFailClosed: when the revocation store cannot be read, a
// workload or agent credential is refused (503), never passed.
func TestRevocationsFailClosed(t *testing.T) {
	e, priv := delegationEnv(t, false)
	resp, _ := e.delegate(t, delegForm(e.workloadToken(t, priv, "wl-1"), tokenTypeJWT, "reviewer"))
	e.s.revs = brokenRevocations{}
	if w := e.egress(resp.AccessToken, `{"agent":"billing"}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("egress with the store down: %d %s", w.Code, w.Body)
	}
	if w := e.exchange(delegForm(resp.AccessToken, tokenTypeJWT, "tester")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("exchange with the store down: %d %s", w.Code, w.Body)
	}
	if w := e.exchange(delegForm(e.session(alice), tokenTypeSession, "reviewer")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint with the store down: %d %s", w.Code, w.Body)
	}
}

type brokenRevocations struct{ revocationStore }

func (brokenRevocations) RevocationsFor(context.Context, []string, []string) ([]pgstore.Revocation, error) {
	return nil, errors.New("connection refused")
}
