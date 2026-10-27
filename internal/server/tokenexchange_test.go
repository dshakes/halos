package server

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
)

type wlEnv struct {
	s    *Server
	h    http.Handler
	iss  *identitytest.Issuer
	isrv *httptest.Server
	pub  ed25519.PublicKey
	dir  string
	seq  int
	ring string
}

// newWorkloadEnv: acme-corp with a workloads section trusting a local OIDC
// issuer (a stand-in for token.actions.githubusercontent.com).
func newWorkloadEnv(t *testing.T, withKey bool) *wlEnv {
	t.Helper()
	iss, err := identitytest.NewIssuer("k1")
	if err != nil {
		t.Fatal(err)
	}
	isrv := iss.Serve()
	t.Cleanup(isrv.Close)
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../../examples/acme-corp")); err != nil {
		t.Fatal(err)
	}
	root := fmt.Sprintf(`org: acme-corp
workloads:
  audience: halos
  issuers:
    - {name: github, url: %q, tenantClaim: repository}
  rules:
    - name: main-branch
      issuer: github
      match: {repository: "acme/*", ref: refs/heads/main}
      subject: "workload:gh:{repository}"
      groups: [ai-platform]
      maxTTLSeconds: 600
`, iss.URL) + exampleSupplyChain(t)
	if err := os.WriteFile(filepath.Join(dir, "halos.yaml"), []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	org, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if issues := org.Validate(); policy.HasErrors(issues) {
		t.Fatalf("fixture invalid: %v", issues)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{PolicyDir: dir, Token: tok, SessionKey: []byte(strings.Repeat("k", 32)),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if withKey {
		cfg.WorkloadKey = priv
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	e := &wlEnv{s: s, h: s.Handler(), iss: iss, isrv: isrv, pub: pub, dir: dir}
	if r := org.ResolveRing(policy.Subject{ID: "workload:gh:acme/app", Groups: []string{"ai-platform"}}); r != nil {
		e.ring = r.Name
	}
	return e
}

// post exchanges subject from a fresh client IP (so negative cases do not
// trip the failed-attempt limiter for each other) unless ip is given.
func (e *wlEnv) post(form url.Values, ip string) *httptest.ResponseRecorder {
	if ip == "" {
		e.seq++
		ip = fmt.Sprintf("198.51.100.%d", e.seq)
	}
	r := httptest.NewRequest("POST", "/api/v1/token/exchange", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ip + ":5555"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func exchangeForm(subject string) url.Values {
	return url.Values{"grant_type": {grantTokenExchange}, "subject_token": {subject}, "subject_token_type": {tokenTypeJWT}}
}

func (e *wlEnv) ghClaims(kv ...any) map[string]any {
	now := time.Now()
	c := map[string]any{"aud": "halos", "sub": "repo:acme/app:ref:refs/heads/main", "repository": "acme/app",
		"repository_owner": "acme", "ref": "refs/heads/main", "jti": fmt.Sprintf("jti-%d", now.UnixNano()), "iat": now.Unix()}
	for i := 0; i+1 < len(kv); i += 2 {
		c[kv[i].(string)] = kv[i+1]
	}
	return c
}

func (e *wlEnv) mint(t *testing.T, kv ...any) string {
	t.Helper()
	tok, err := e.iss.Mint(e.ghClaims(kv...))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func oauthError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m["error"]
}

func TestTokenExchangeMintsGatewayCredential(t *testing.T) {
	e := newWorkloadEnv(t, true)
	ci := e.mint(t)
	w := e.post(exchangeForm(ci), "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp TokenExchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Subject != "workload:gh:acme/app" || resp.Rule != "main-branch" || resp.ExpiresIn != 600 || resp.TokenType != "Bearer" ||
		resp.IssuedTokenType != tokenTypeJWT || resp.Ring == "" || resp.Ring != e.ring || resp.GatewayURL == "" {
		t.Fatalf("response %+v (want ring %q)", resp, e.ring)
	}

	// The proxy's verifier (identity.New with the public key) accepts it as a
	// workload principal, and rejects it once expired.
	der, _ := x509.MarshalPKIXPublicKey(e.pub)
	v, err := identity.New(identity.Options{Mode: identity.ModeJWT, Issuer: e.iss.URL, Audience: "gw",
		WorkloadKeys: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	sub, err := v.Verify(req)
	if err != nil || sub.ID != resp.Subject || sub.Kind != policy.SubjectWorkload || len(sub.Groups) != 1 || sub.Groups[0] != "ai-platform" {
		t.Fatalf("proxy verifier: %+v %v", sub, err)
	}
	wv := v.(*identity.WorkloadJWT)
	wv.Now = func() time.Time { return time.Now().Add(601 * time.Second) }
	if _, err := v.Verify(req); err == nil {
		t.Fatal("expired workload credential accepted")
	}

	// Audited with the matched claims; neither token is ever written.
	entries, err := e.s.auditLog.all()
	if err != nil || len(entries) == 0 {
		t.Fatalf("audit: %v %d", err, len(entries))
	}
	last := entries[len(entries)-1]
	if last.Action != "workload.token.exchange" || last.Actor != resp.Subject || last.Target != "main-branch" ||
		last.Details["claim.repository"] != "acme/app" || last.Details["claim.ref"] != "refs/heads/main" || last.Details["ciSubject"] == "" {
		t.Fatalf("audit entry %+v", last)
	}
	raw, _ := json.Marshal(entries)
	for _, secret := range []string{ci, resp.AccessToken, strings.Split(ci, ".")[2], strings.Split(resp.AccessToken, ".")[2]} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("audit log contains a token")
		}
	}
}

// TestTokenExchangeRejectsBadSubjectTokens covers the JWT verification
// negatives: issuer, audience, time claims, algorithm and key confusion,
// replay, and claims no rule matches.
func TestTokenExchangeRejectsBadSubjectTokens(t *testing.T) {
	e := newWorkloadEnv(t, true)
	other, err := identitytest.NewIssuer("k1")
	if err != nil {
		t.Fatal(err)
	}
	osrv := other.Serve()
	defer osrv.Close()
	now := time.Now()
	rs256 := func(k *rsa.PrivateKey) func([]byte) ([]byte, error) {
		return func(in []byte) ([]byte, error) {
			d := sha256.Sum256(in)
			return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		}
	}
	signed := func(hdr map[string]any, claims map[string]any, s func([]byte) ([]byte, error)) string {
		t.Helper()
		claims["iss"], claims["exp"] = e.iss.URL, now.Add(time.Hour).Unix()
		tok, err := identitytest.Sign(hdr, claims, s)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&e.iss.Key.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	hs256 := func(in []byte) ([]byte, error) {
		m := hmac.New(sha256.New, pubPEM)
		m.Write(in)
		return m.Sum(nil), nil
	}
	foreignTok, _ := other.Mint(e.ghClaims())

	for _, tc := range []struct {
		name, tok string
	}{
		{"untrusted issuer", foreignTok},
		{"iss spoofed to ours, foreign key and kid", signed(map[string]any{"alg": "RS256", "kid": "k1"}, e.ghClaims(), rs256(other.Key))},
		{"wrong audience", e.mint(t, "aud", "someone-else")},
		{"audience array without ours", e.mint(t, "aud", []string{"a", "b"})},
		{"expired", e.mint(t, "exp", now.Add(-time.Minute).Unix())},
		{"nbf in the future", e.mint(t, "nbf", now.Add(time.Hour).Unix())},
		{"iat in the future", e.mint(t, "iat", now.Add(time.Hour).Unix(), "exp", now.Add(2*time.Hour).Unix())},
		{"iat missing", e.mint(t, "iat", nil)},
		{"alg none", signed(map[string]any{"alg": "none", "kid": "k1"}, e.ghClaims(), nil)},
		{"HS256 keyed with the issuer's public key", signed(map[string]any{"alg": "HS256", "kid": "k1"}, e.ghClaims(), hs256)},
		{"unknown kid", signed(map[string]any{"alg": "RS256", "kid": "rotated"}, e.ghClaims(), rs256(other.Key))},
		{"not a JWT", "abc"},
		{"claim mismatch: other owner", e.mint(t, "repository", "evil/app")},
		{"claim mismatch: branch", e.mint(t, "ref", "refs/heads/feature")},
		{"claim mismatch: glob does not cross /", e.mint(t, "repository", "acme/x/app")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := e.post(exchangeForm(tc.tok), "")
			if w.Code != http.StatusBadRequest || oauthError(t, w) != "invalid_grant" {
				t.Fatalf("status %d %s, want 400 invalid_grant", w.Code, w.Body)
			}
		})
	}

	// Replay: a jti is exchanged once; a token without jti once by its hash.
	for name, tok := range map[string]string{"jti": e.mint(t), "no jti": e.mint(t, "jti", nil)} {
		if w := e.post(exchangeForm(tok), ""); w.Code != http.StatusOK {
			t.Fatalf("%s first exchange: %d %s", name, w.Code, w.Body)
		}
		w := e.post(exchangeForm(tok), "")
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "replay") {
			t.Fatalf("%s replay: %d %s", name, w.Code, w.Body)
		}
	}
	entries, _ := e.s.auditLog.all()
	denied := 0
	for _, a := range entries {
		if a.Action == "workload.token.denied" {
			denied++
		}
	}
	if denied != 5 { // 3 claim mismatches + 2 replays; unverified tokens are logged, not audited
		t.Fatalf("denied audit entries = %d, want 5", denied)
	}
}

func TestTokenExchangeRequestShape(t *testing.T) {
	e := newWorkloadEnv(t, true)
	good := exchangeForm("x.y.z")
	with := func(k, v string) url.Values {
		f := url.Values{}
		for kk, vv := range good {
			f[kk] = vv
		}
		if v == "" {
			f.Del(k)
		} else {
			f.Set(k, v)
		}
		return f
	}
	for _, tc := range []struct {
		name string
		form url.Values
		want string
	}{
		{"wrong grant", with("grant_type", "client_credentials"), "unsupported_grant_type"},
		{"no subject token", with("subject_token", ""), "invalid_request"},
		{"saml subject", with("subject_token_type", "urn:ietf:params:oauth:token-type:saml2"), "invalid_request"},
		{"refresh token requested", with("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"), "invalid_request"},
		{"other audience", with("audience", "https://api.anthropic.com"), "invalid_target"},
		{"delegation", with("actor_token", "a.b.c"), "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := e.post(tc.form, ""); w.Code != http.StatusBadRequest || oauthError(t, w) != tc.want {
				t.Fatalf("got %d %s, want %s", w.Code, w.Body, tc.want)
			}
		})
	}
	// JSON is not the RFC 8693 encoding.
	r := httptest.NewRequest("POST", "/api/v1/token/exchange", strings.NewReader(`{"grant_type":"`+grantTokenExchange+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("json body: %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token endpoint response is cacheable")
	}

	// Repeated failures from one address are throttled.
	var last int
	for range authFailBurst + 2 {
		last = e.post(exchangeForm("bad.bad.bad"), "203.0.113.7").Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: %d, want 429", authFailBurst+2, last)
	}
}

func TestTokenExchangeDisabledWithoutKey(t *testing.T) {
	e := newWorkloadEnv(t, false)
	if w := e.post(exchangeForm(e.mint(t)), ""); w.Code != http.StatusNotFound {
		t.Fatalf("no --workload-key-file: %d %s", w.Code, w.Body)
	}
}

// An unreachable issuer is an outage, not a bad credential: 503, and CI
// clients behind one address are not locked out for it.
func TestTokenExchangeIssuerDownIsNotPenalized(t *testing.T) {
	e := newWorkloadEnv(t, true)
	tok := e.mint(t)
	e.isrv.Close()
	for range authFailBurst + 2 {
		if w := e.post(exchangeForm(tok), "203.0.113.9"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("issuer down: %d %s, want 503", w.Code, w.Body)
		}
	}
}

func TestReplayCacheBounded(t *testing.T) {
	x := workloadExchange{seen: map[string]time.Time{}}
	now := time.Now()
	for i := range maxReplayEntries {
		x.seen[fmt.Sprint(i)] = now.Add(time.Minute)
	}
	if err := x.remember("new", now.Add(time.Minute), now); err != errReplayFull {
		t.Fatalf("full of live entries: %v", err)
	}
	if err := x.remember("new", now.Add(time.Minute), now.Add(2*time.Minute)); err != nil {
		t.Fatalf("expired entries are pruned: %v", err)
	}
	if len(x.seen) != 1 {
		t.Fatalf("pruned to %d", len(x.seen))
	}
}

// halo_server_workload_rules_skipped is a gauge of the rules in effect that
// pin no tenant, set once per policy load: failed exchanges do not inflate it.
func TestWorkloadRulesSkippedIsPerLoad(t *testing.T) {
	e := newWorkloadEnv(t, true)
	org, _, err := e.s.pol.Get()
	if err != nil {
		t.Fatal(err)
	}
	// A policy that skipped validation (unreachable after SecurityIssues; the
	// gauge is defence in depth): one rule pins no tenant.
	cp, wl := *org, *org.Workloads
	wl.Rules = append(slices.Clone(wl.Rules), policy.WorkloadRule{Name: "any-main", Issuer: "github", Match: map[string]string{"ref": "refs/heads/main"}, Subject: "workload:gh:{repository}"})
	cp.Workloads = &wl
	e.s.pol.mu.Lock()
	e.s.pol.org = &cp
	e.s.pol.activate()
	e.s.pol.mu.Unlock()
	for i := 0; i < 3; i++ {
		if w := e.post(exchangeForm(e.mint(t, "repository", "evil/x")), ""); w.Code != http.StatusBadRequest {
			t.Fatalf("exchange %d: %d %s", i, w.Code, w.Body)
		}
	}
	var m bytes.Buffer
	e.s.WriteMetrics(&m)
	if !strings.Contains(m.String(), "# TYPE halo_server_workload_rules_skipped gauge\nhalo_server_workload_rules_skipped 1\n") {
		t.Fatalf("want the gauge at 1 after 3 failed exchanges:\n%s", m.String())
	}
}

// Shared CI egress (GitHub-hosted runners, NAT) puts many tenants behind one
// IP, so the exchange's failed-attempt budget counts only subject tokens that
// are malformed or not signed by a trusted issuer. Tokens a neighbour can
// mint (signed, but matching no rule, expired, for another audience) cost
// nothing; a signed token passes even once the IP is blocked, verified from
// cached keys only (a blocked IP never makes halo-server fetch the JWKS);
// replay protection still holds. The same holds for delegation exchanges.
func TestExchangeLimiterCountsOnlyForgeries(t *testing.T) {
	e := newWorkloadEnv(t, true)
	pf := filepath.Join(e.dir, "halos.yaml")
	pb, err := os.ReadFile(pf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, append(pb, agentsYAML...), 0o600); err != nil {
		t.Fatal(err)
	}
	e.s.ReloadPolicy()
	if org, _, err := e.s.pol.Get(); err != nil || org.Agents == nil {
		t.Fatalf("fixture with agents: %v", err)
	}
	var jwksFetches atomic.Int64
	inner := e.isrv.Config.Handler
	e.isrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			jwksFetches.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	const ip = "203.0.113.7"
	// A neighbour's signed tokens that match no rule or fail claim checks.
	for i := 0; i < authFailBurst+2; i++ {
		for _, kv := range [][]any{{"repository", "evil/x"}, {"exp", time.Now().Add(-time.Hour).Unix()}, {"aud", "other"}} {
			if w := e.post(exchangeForm(e.mint(t, kv...)), ip); w.Code != http.StatusBadRequest {
				t.Fatalf("signed but unusable token %v: %d %s, want 400", kv, w.Code, w.Body)
			}
		}
	}
	if w := e.post(exchangeForm(e.mint(t)), ip); w.Code != http.StatusOK {
		t.Fatalf("victim after a neighbour's signed-but-unmatched tokens: %d %s, want 200 (not counted)", w.Code, w.Body)
	}
	// Forgeries count, and block the IP.
	for i := 0; i < authFailBurst; i++ {
		if w := e.post(exchangeForm("a.b.c"), ip); w.Code != http.StatusBadRequest {
			t.Fatalf("garbage %d: %d", i, w.Code)
		}
	}
	if w := e.post(exchangeForm("a.b.c"), ip); w.Code != http.StatusTooManyRequests {
		t.Fatalf("garbage after the burst: %d, want 429", w.Code)
	}
	// A signed token still passes from the blocked IP.
	ci := e.mint(t)
	w := e.post(exchangeForm(ci), ip)
	if w.Code != http.StatusOK {
		t.Fatalf("signed token from the blocked IP: %d %s, want 200", w.Code, w.Body)
	}
	var resp TokenExchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if w := e.post(exchangeForm(ci), ip); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "replay") {
		t.Fatalf("replay from the blocked IP: %d %s, want 400 replay", w.Code, w.Body)
	}
	// A token signed by a key the issuer never published: from the blocked
	// IP it is refused from cache, without a JWKS fetch.
	rogue, err := identitytest.NewIssuer("rogue")
	if err != nil {
		t.Fatal(err)
	}
	rogue.URL = e.iss.URL
	forged, err := rogue.Mint(e.ghClaims())
	if err != nil {
		t.Fatal(err)
	}
	before := jwksFetches.Load()
	if w := e.post(exchangeForm(forged), ip); w.Code != http.StatusTooManyRequests {
		t.Fatalf("forged token from the blocked IP: %d, want 429", w.Code)
	}
	if n := jwksFetches.Load(); n != before {
		t.Fatalf("a blocked IP made halo-server fetch the JWKS (%d fetches)", n-before)
	}
	if w := e.post(exchangeForm(forged), ""); w.Code != http.StatusBadRequest || jwksFetches.Load() == before {
		t.Fatalf("forged token from a fresh IP: %d, fetches %d, want 400 after a JWKS refetch", w.Code, jwksFetches.Load()-before)
	}

	// Delegation has its own budget (agentFails): CI failures that blocked
	// ip do not block agent delegation from it, and the reverse.
	garbage := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {"x"}, "subject_token_type": {tokenTypeSession}, "actor_id": {"planner"}}
	if w := e.post(garbage, ip); w.Code != http.StatusBadRequest {
		t.Fatalf("garbage delegation from the CI-blocked IP: %d, want 400 (agentFails, not exchangeFails)", w.Code)
	}
	const ip2 = "203.0.113.8"
	for i := 0; i < authFailBurst-1; i++ {
		if w := e.post(garbage, ip2); w.Code != http.StatusBadRequest {
			t.Fatalf("garbage delegation %d: %d", i, w.Code)
		}
	}
	// Signed but unusable parents (an expired workload credential) do not count.
	expired, err := identity.SignWorkloadToken(e.s.cfg.WorkloadKey, identity.WorkloadClaims{Issuer: identity.WorkloadIssuer, Subject: "workload:gh:acme/app",
		Audience: identity.WorkloadAudience, Kind: policy.SubjectWorkload, IssuedAt: time.Now().Add(-2 * time.Hour).Unix(), NotBefore: time.Now().Add(-2 * time.Hour).Unix(),
		Expiry: time.Now().Add(-time.Hour).Unix(), ID: "old"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < authFailBurst; i++ {
		if w := e.post(url.Values{"grant_type": {grantTokenExchange}, "subject_token": {expired}, "subject_token_type": {tokenTypeJWT}, "actor_id": {"planner"}}, ip2); w.Code != http.StatusBadRequest {
			t.Fatalf("expired signed parent %d: %d %s", i, w.Code, w.Body)
		}
	}
	if w := e.post(garbage, ip2); w.Code != http.StatusBadRequest {
		t.Fatalf("last garbage delegation before the burst: %d, want 400 (expired parents were counted)", w.Code)
	}
	if w := e.post(garbage, ip2); w.Code != http.StatusTooManyRequests {
		t.Fatalf("garbage delegation after the burst: %d, want 429", w.Code)
	}
	// A Halos credential still passes from the agent-blocked IP (it then
	// fails on the agent policy, not on the limiter).
	del := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {resp.AccessToken}, "subject_token_type": {tokenTypeJWT}, "actor_id": {"planner"}}
	if w := e.post(del, ip2); w.Code == http.StatusTooManyRequests {
		t.Fatalf("delegation with a valid credential from the agent-blocked IP: %d %s", w.Code, w.Body)
	}
	// Agent failures do not block the CI exchange.
	if w := e.post(exchangeForm(e.mint(t)), ip2); w.Code != http.StatusOK {
		t.Fatalf("CI exchange from the agent-blocked IP: %d %s, want 200", w.Code, w.Body)
	}
}

// Tokens anyone can mint from a shared CI issuer (another repository, a
// branch no rule names) never take a replay-cache slot, so they cannot fill
// the cache and refuse every tenant; their denials are audited at most once
// per issuer+IP per minute, the rest counted. Replay protection still holds
// for tokens a rule matches.
func TestUnmatchedWorkloadTokensSkipReplayCacheAndCoalesceAudit(t *testing.T) {
	e := newWorkloadEnv(t, true)
	const ip, n = "203.0.113.20", 5
	for i := 0; i < n; i++ {
		if w := e.post(exchangeForm(e.mint(t, "repository", fmt.Sprintf("evil/x%d", i))), ip); w.Code != http.StatusBadRequest {
			t.Fatalf("unmatched token %d: %d %s", i, w.Code, w.Body)
		}
	}
	e.s.wl.mu.Lock()
	cached := len(e.s.wl.seen)
	e.s.wl.mu.Unlock()
	if cached != 0 {
		t.Fatalf("replay cache holds %d unmatched tokens, want 0", cached)
	}
	countDenied := func() int {
		entries, _ := e.s.auditLog.all()
		c := 0
		for _, a := range entries {
			if a.Action == "workload.token.denied" {
				c++
			}
		}
		return c
	}
	if got := countDenied(); got != 1 {
		t.Fatalf("denied audit entries from one issuer+IP = %d, want 1 (coalesced)", got)
	}
	var m bytes.Buffer
	e.s.WriteMetrics(&m)
	if want := fmt.Sprintf("halo_server_workload_denied_audit_suppressed_total %d\n", n-1); !strings.Contains(m.String(), want) {
		t.Fatalf("metrics missing %q", want)
	}
	// Another IP gets its own audit entry.
	if w := e.post(exchangeForm(e.mint(t, "repository", "evil/y")), ""); w.Code != http.StatusBadRequest || countDenied() != 2 {
		t.Fatalf("other IP: %d, denied entries %d, want 2", w.Code, countDenied())
	}
	// A matching token is remembered and its replay refused.
	ok := e.mint(t)
	if w := e.post(exchangeForm(ok), ip); w.Code != http.StatusOK {
		t.Fatalf("matching token: %d %s", w.Code, w.Body)
	}
	if w := e.post(exchangeForm(ok), ip); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "replay") {
		t.Fatalf("replay: %d %s", w.Code, w.Body)
	}
}

func TestAuditDeniedBounded(t *testing.T) {
	var x workloadExchange
	now := time.Now()
	x.denied = map[string]time.Time{}
	for i := range maxDeniedAuditKeys {
		x.denied[fmt.Sprint(i)] = now
	}
	if x.auditDenied("new", now) {
		t.Fatal("full of live keys: audited")
	}
	if !x.auditDenied("new", now.Add(deniedAuditWindow)) || len(x.denied) != 1 {
		t.Fatalf("stale keys not pruned: %d", len(x.denied))
	}
	if x.deniedSuppressed.Load() != 1 {
		t.Fatalf("suppressed = %d", x.deniedSuppressed.Load())
	}
}
