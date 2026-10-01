package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
)

const testAud = "halo-gateway"

// seen is what the fake upstream observed.
type seen struct {
	mu      sync.Mutex
	hits    int
	header  http.Header
	body    string
	path    string
	rawPath string
}

func (s *seen) record(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits++
	s.header, s.body, s.path, s.rawPath = r.Header.Clone(), string(b), r.URL.Path, r.URL.EscapedPath()
}

func (s *seen) get() (int, http.Header, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits, s.header, s.body, s.rawPath
}

func recordingServer(t *testing.T) (*httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

type env struct {
	iss    *identitytest.Issuer
	proxy  *httptest.Server
	p      *Proxy
	policy string
	cfg    Config
}

// testEnv wires: OIDC issuer, a policy whose "sonnet" alias routes to the
// fake upstream (model real-model), ga/ring0 rings, and a halo-proxy in front.
func testEnv(t *testing.T, upstream *httptest.Server, mod func(*Config, *policy.Org)) *env {
	t.Helper()
	iss, err := identitytest.NewIssuer("k1")
	if err != nil {
		t.Fatal(err)
	}
	isrv := iss.Serve()
	t.Cleanup(isrv.Close)

	rt := func(up, m string) policy.ModelRoute { return policy.ModelRoute{Upstream: up, Model: m} }
	org := &policy.Org{
		Name:     "acme",
		Identity: policy.Identity{Issuer: iss.URL, Audience: testAud},
		Gateway: &policy.Gateway{
			Models:    map[string]policy.ModelRoute{"sonnet": rt("up", "real-model")},
			Upstreams: map[string]policy.Upstream{"up": {URL: upstream.URL, Kind: "anthropic"}},
		},
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "ring0"}, Order: 0, Membership: policy.Membership{Groups: []string{"ai-platform"}}},
			{Meta: policy.Meta{Name: "ga"}, Order: 1, Membership: policy.Membership{Default: true}},
		},
	}
	cfg := defaults()
	if mod != nil {
		mod(&cfg, org)
	}
	e := &env{iss: iss, cfg: cfg}
	e.policy = filepath.Join(t.TempDir(), "policy.json")
	e.writePolicy(t, org)
	e.cfg.Policy = e.policy
	p, err := newProxy(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.p, e.proxy = p, httptest.NewServer(p)
	t.Cleanup(e.proxy.Close)
	return e
}

func (e *env) writePolicy(t *testing.T, org *policy.Org) {
	t.Helper()
	b, err := policy.Compile(org)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.policy, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *env) token(t *testing.T, user string, groups ...string) string {
	t.Helper()
	tok, err := e.iss.Mint(map[string]any{"aud": testAud, "email": user, "groups": groups})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *env) post(t *testing.T, path, tok, body string, hdr map[string]string) *http.Response {
	t.Helper()
	return e.postReader(t, path, tok, strings.NewReader(body), hdr)
}

func (e *env) postReader(t *testing.T, path, tok string, body io.Reader, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", e.proxy.URL+path, body)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

const msgBody = `{"model":"sonnet","messages":[{"role":"user","content":"hi"}],"stream":false}`

func TestInvalidJWTRejected(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, nil)
	expired, _ := e.iss.Mint(map[string]any{"aud": testAud, "email": "a@x", "exp": time.Now().Add(-time.Hour).Unix()})
	for name, tok := range map[string]string{"none": "", "garbage": "abc.def.ghi", "expired": expired} {
		t.Run(name, func(t *testing.T) {
			resp := e.post(t, "/v1/messages", tok, msgBody, nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d want 401", resp.StatusCode)
			}
		})
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatalf("rejected requests reached upstream (%d hits)", hits)
	}
}

func TestAllowAnonymousFallsBackToDefaultRouting(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, _ *policy.Org) { c.Identity.AllowAnonymous = true })
	resp := e.post(t, "/v1/messages", "opaque-api-key", msgBody, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, h, _, _ := s.get(); h.Get("x-halo-ring") != "unknown" {
		t.Fatalf("x-halo-ring=%q want unknown", h.Get("x-halo-ring"))
	}
}

func TestSpoofedHeadersStrippedRewriteAndAuth(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, nil)
	tok := e.token(t, "alice@acme.com", "ai-platform")
	resp := e.post(t, "/v1/messages", tok, msgBody, map[string]string{
		"x-halo-ring": "ga", "x-halo-release": "sha256:evil", "x-halo-variant": "control", "X-Halo-Custom": "1",
		"x-api-key": "client-key",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	hits, h, body, _ := s.get()
	if hits != 1 {
		t.Fatalf("hits=%d", hits)
	}
	if h.Get("x-halo-ring") != "ring0" { // from the JWT groups, not the spoofed header
		t.Errorf("x-halo-ring=%q want ring0", h.Get("x-halo-ring"))
	}
	if h.Get("x-halo-custom") != "" || h.Get("x-halo-release") != "" || h.Get("x-halo-variant") != "" {
		t.Errorf("spoofed x-halo-* leaked: %v", h)
	}
	if h.Get("Authorization") != "" || h.Get("x-api-key") != "" {
		t.Errorf("client credentials forwarded with forwardAuth=false: %v", h)
	}
	var b map[string]any
	if err := json.Unmarshal([]byte(body), &b); err != nil || b["model"] != "real-model" {
		t.Errorf("model not rewritten: %s (%v)", body, err)
	}
	if h.Get("Content-Length") != "" && h.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Errorf("content-length %q != body %d", h.Get("Content-Length"), len(body))
	}
}

func TestBedrockPathRewrite(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		o.Gateway.Models["sonnet"] = policy.ModelRoute{Upstream: "up", Model: "arn:aws:bedrock:us-east-1:1:inference-profile/us.anthropic.x"}
	})
	tok := e.token(t, "bob@acme.com")
	resp := e.post(t, "/model/sonnet/invoke", tok, `{"messages":[]}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, _, _, raw := s.get()
	if want := "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fus.anthropic.x/invoke"; raw != want {
		t.Fatalf("path %q want %q", raw, want)
	}
}

func TestOversizeIs413(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, _ *policy.Org) { c.MaxBodyBytes = 100 })
	tok := e.token(t, "alice@acme.com")
	big := `{"model":"sonnet","messages":[{"role":"user","content":"` + strings.Repeat("x", 500) + `"}]}`

	if resp := e.post(t, "/v1/messages", tok, big, nil); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("content-length body: status %d want 413", resp.StatusCode)
	}
	// Unknown length (chunked) must be caught while reading, not skipped.
	if resp := e.postReader(t, "/v1/messages", tok, io.MultiReader(strings.NewReader(big)), nil); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked body: status %d want 413", resp.StatusCode)
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatalf("oversize request reached upstream")
	}
}

func TestStreamingFlushedIncrementally(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select { // upstream has NOT finished until the test says so
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: second\n\n")
	}))
	defer up.Close()
	e := testEnv(t, up, nil)
	tok := e.token(t, "alice@acme.com")

	resp := e.post(t, "/v1/messages", tok, msgBody, nil)
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- l
	}()
	select {
	case l := <-line:
		if l != "data: first\n" {
			t.Fatalf("first chunk %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first SSE chunk not delivered before upstream finished: response is being buffered")
	}
	close(release)
}

func TestNextHopForwardAuth(t *testing.T) {
	policyUp, policySeen := recordingServer(t)
	for _, forward := range []bool{true, false} {
		next, nextSeen := recordingServer(t)
		e := testEnv(t, policyUp, func(c *Config, _ *policy.Org) { c.NextHop = next.URL; c.ForwardAuth = forward })
		tok := e.token(t, "alice@acme.com", "ai-platform")
		if resp := e.post(t, "/v1/messages", tok, msgBody, nil); resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		hits, h, body, _ := nextSeen.get()
		if hits != 1 {
			t.Fatalf("forward=%v: next hop hits=%d", forward, hits)
		}
		if got := h.Get("Authorization"); (got == "Bearer "+tok) != forward || (!forward && got != "") {
			t.Errorf("forwardAuth=%v but Authorization=%q", forward, got)
		}
		if h.Get("x-halo-ring") != "ring0" || !strings.Contains(body, `"real-model"`) {
			t.Errorf("next hop should still get stamped+rewritten request: ring=%q body=%s", h.Get("x-halo-ring"), body)
		}
	}
	if hits, _, _, _ := policySeen.get(); hits != 0 {
		t.Fatalf("policy upstream bypassed next-hop (%d hits)", hits)
	}
}

func TestShadowMirrorFiredForFirstTurn(t *testing.T) {
	up, _ := recordingServer(t)
	jobs := make(chan map[string]any, 4)
	tokens := make(chan string, 4)
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var j map[string]any
		_ = json.NewDecoder(r.Body).Decode(&j)
		tokens <- r.Header.Get("X-Halo-Shadow-Token")
		jobs <- j
	}))
	defer shadowSrv.Close()
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.Shadow.URL, c.Shadow.Token = shadowSrv.URL, "tok"
		rt := policy.ModelRoute{Upstream: "up", Model: "candidate-model"}
		o.Experiments = []*policy.Experiment{{
			Meta: policy.Meta{Name: "sonnet-shadow"}, Type: policy.ExperimentShadow, Axis: policy.AxisTraffic,
			Status: "running", Rings: []string{"ga"}, SampleRate: 1,
			Variants: []policy.Variant{{Name: "control", Control: true}, {Name: "cand", Routes: map[string]policy.ModelRoute{"sonnet": rt}}},
		}}
	})
	tok := e.token(t, "carol@acme.com")

	// Multi-turn: not eligible.
	multi := `{"model":"sonnet","messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"c"}]}`
	e.post(t, "/v1/messages", tok, multi, map[string]string{"x-claude-code-session-id": "s-multi"})
	// First turn: mirrored.
	e.post(t, "/v1/messages", tok, msgBody, map[string]string{"x-claude-code-session-id": "s1", "anthropic-version": "2023-06-01"})

	select {
	case j := <-jobs:
		if j["experiment"] != "sonnet-shadow" || j["session_id"] != "s1" || j["ring"] != "ga" {
			t.Fatalf("unexpected job %v", j)
		}
		if j["variant"] != "cand" || j["method"] != "POST" || j["path"] != "/v1/messages" {
			t.Fatalf("job %v", j)
		}
		for _, k := range []string{"control", "candidate", "upstream", "model"} {
			if _, ok := j[k]; ok {
				t.Fatalf("job must not name upstreams/models (%q): %v", k, j)
			}
		}
		if hs := j["headers"].(map[string]any); hs["anthropic-version"] != "2023-06-01" || len(hs) != 1 {
			t.Fatalf("only allowlisted headers may be replayed, got %v", hs)
		}
		if strings.Contains(mustJSON(j), tok) {
			t.Fatal("client credential leaked into shadow job")
		}
		if <-tokens != "tok" {
			t.Fatal("missing shadow token")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shadow job not sent for eligible first turn")
	}
	select {
	case j := <-jobs:
		t.Fatalf("multi-turn request was mirrored: %v", j)
	case <-time.After(300 * time.Millisecond):
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// awaitHandlers serves e through a wrapper and returns a func that blocks until the
// next n requests have fully returned from ServeHTTP. Metrics are recorded in a
// deferred block that runs after a streamed response has reached the client, so
// tests that read metrics wait on this instead of racing it (or sleeping).
func (e *env) awaitHandlers(t *testing.T, n int) (wait func()) {
	t.Helper()
	var wg sync.WaitGroup
	var left atomic.Int64
	left.Store(int64(n))
	wg.Add(n)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if left.Add(-1) >= 0 {
			defer wg.Done()
		}
		e.p.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	e.proxy = srv
	return wg.Wait
}

func TestHealthAndMetrics(t *testing.T) {
	up, _ := recordingServer(t)
	e := testEnv(t, up, nil)
	wait := e.awaitHandlers(t, 2)
	tok := e.token(t, "alice@acme.com", "ai-platform")
	e.post(t, "/v1/messages", tok, msgBody, nil)
	e.post(t, "/v1/messages", "", msgBody, nil) // 401
	wait()

	admin := httptest.NewServer(e.p.AdminHandler())
	defer admin.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(admin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatalf("healthz %d", code)
	}
	code, m := get("/metrics")
	if code != 200 {
		t.Fatalf("metrics %d", code)
	}
	for _, want := range []string{
		`halo_proxy_requests_total{ring="ring0",variant="",status="200"} 1`,
		`halo_proxy_requests_total{ring="none",variant="",status="401"} 1`,
		`halo_proxy_upstream_ttfb_seconds_bucket{le="+Inf"} 1`,
		`halo_proxy_request_duration_seconds_count 2`,
		`halo_proxy_auth_failures_total 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q\n%s", want, m)
		}
	}
	for _, path := range []string{"/healthz", "/metrics"} {
		if resp, err := http.Get(e.proxy.URL + path); err != nil || resp.StatusCode == http.StatusOK {
			t.Fatalf("public listener must not serve %s: %v %v", path, resp, err)
		} else {
			_ = resp.Body.Close()
		}
	}
}

func TestHealthzFailsWithoutPolicy(t *testing.T) {
	p, err := newProxy(func() Config { c := defaults(); c.Policy = filepath.Join(t.TempDir(), "missing.json"); return c }(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz=%d want 503", rec.Code)
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(msgBody)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no policy and no next-hop: %d want 503", rec.Code)
	}
}

func TestPolicyHotReload(t *testing.T) {
	up, s := recordingServer(t)
	var org *policy.Org
	e := testEnv(t, up, func(_ *Config, o *policy.Org) { org = o })
	tok := e.token(t, "alice@acme.com")
	e.post(t, "/v1/messages", tok, msgBody, nil)
	if _, _, body, _ := s.get(); !strings.Contains(body, `"real-model"`) {
		t.Fatalf("before reload: %s", body)
	}
	org.Gateway.Models["sonnet"] = policy.ModelRoute{Upstream: "up", Model: "reloaded-model"}
	time.Sleep(1100 * time.Millisecond) // snapshot stat interval is 1s
	e.writePolicy(t, org)
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.post(t, "/v1/messages", tok, msgBody, nil)
		if _, _, body, _ := s.get(); strings.Contains(body, `"reloaded-model"`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("policy change not picked up")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestUpstreamHeadersInjected(t *testing.T) {
	t.Setenv("TEST_PROVIDER_KEY", "sk-secret")
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, _ *policy.Org) {
		c.UpstreamHeaders = map[string]map[string]string{"up": {"x-api-key": "${TEST_PROVIDER_KEY}"}}
	})
	e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), msgBody, map[string]string{"x-api-key": "client"})
	if _, h, _, _ := s.get(); h.Get("x-api-key") != "sk-secret" {
		t.Fatalf("x-api-key=%q", h.Get("x-api-key"))
	}
}

func TestLoadConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "c.yaml")
	os.WriteFile(f, []byte("policy: /y/policy.json\nlisten: ':1111'\nmaxBodyBytes: 5\nidentity:\n  mode: none\n  trustedProxyCIDRs: [10.0.0.0/8]\n"), 0o600)
	env := map[string]string{"HALO_PROXY_LISTEN": ":2222", "HALO_PROXY_HALO_SHADOW_TOKEN": "t"}
	cfg, err := loadConfig([]string{"--config", f, "--max-body-bytes", "9"}, func(k string) string { return env[k] }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy != "/y/policy.json" || cfg.Listen != ":2222" || cfg.MaxBodyBytes != 9 || cfg.Shadow.Token != "t" ||
		cfg.Identity.Mode != "none" || len(cfg.Identity.TrustedProxyCIDRs) != 1 {
		t.Fatalf("%+v", cfg)
	}
	for name, args := range map[string][]string{
		"no policy":        {},
		"bad next hop":     {"--policy", "p", "--next-hop", "kong:8000"},
		"unknown flag":     {"--policy", "p", "--nope"},
		"non-positive max": {"--policy", "p", "--max-body-bytes", "0"},
	} {
		if _, err := loadConfig(args, func(string) string { return "" }, io.Discard); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	os.WriteFile(f, []byte("bogus: 1\n"), 0o600)
	if _, err := loadConfig([]string{"--config", f}, func(string) string { return "" }, io.Discard); err == nil {
		t.Error("unknown YAML field must be rejected")
	}
}

func TestModelAllowlistFailsClosed(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, nil)
	tok := e.token(t, "alice@acme.com")
	for _, tc := range []struct {
		name, path, body string
		status           int
		errType          string
	}{
		{"unknown model", "/v1/messages", `{"model":"claude-opus-4","messages":[]}`, 400, "invalid_request_error"},
		{"upstream id not alias", "/v1/messages", `{"model":"real-model","messages":[]}`, 400, "invalid_request_error"},
		{"unparseable body", "/v1/messages", `not json`, 400, "invalid_request_error"},
		{"batches", "/v1/messages/batches", `{"requests":[]}`, 400, "invalid_request_error"},
		{"unknown subpath", "/v1/messages/foo", msgBody, 404, "not_found_error"},
		{"escaped path", "/v1/%6Dessages", msgBody, 404, "not_found_error"},
		{"responses unknown", "/v1/responses", `{"model":"gpt-x","input":"hi"}`, 400, "invalid_request_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := e.post(t, tc.path, tok, tc.body, nil)
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status || !strings.Contains(string(b), tc.errType) {
				t.Fatalf("status %d body %s; want %d %s", resp.StatusCode, b, tc.status, tc.errType)
			}
		})
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatalf("rejected requests reached upstream (%d)", hits)
	}
	// count_tokens is routed and rewritten like messages.
	if resp := e.post(t, "/v1/messages/count_tokens", tok, msgBody, nil); resp.StatusCode != 200 {
		t.Fatalf("count_tokens %d", resp.StatusCode)
	}
	hits, _, body, raw := s.get()
	if hits != 1 || raw != "/v1/messages/count_tokens" || !strings.Contains(body, `"real-model"`) {
		t.Fatalf("hits=%d path=%s body=%s", hits, raw, body)
	}
}

func TestIdentityHeadersNeverForwarded(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.Identity = IdentityConfig{Mode: "trusted_header", IdentityHeader: "x-acme-user", GroupsHeader: "x-acme-groups", TrustedProxyCIDRs: []string{"127.0.0.0/8", "::1/128"}}
	})
	resp := e.post(t, "/v1/messages", "", msgBody, map[string]string{"x-acme-user": "alice", "x-acme-groups": "ai-platform"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, h, _, _ := s.get()
	if h.Get("x-halo-ring") != "ring0" {
		t.Fatalf("subject not derived from trusted headers: ring=%q", h.Get("x-halo-ring"))
	}
	if h.Get("x-acme-user") != "" || h.Get("x-acme-groups") != "" {
		t.Fatalf("identity headers forwarded upstream: %v", h)
	}

	// Duplicate identity header => 400, never reaches upstream.
	req, _ := http.NewRequest("POST", e.proxy.URL+"/v1/messages", strings.NewReader(msgBody))
	req.Header.Add("x-acme-user", "alice")
	req.Header.Add("x-acme-user", "mallory")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate identity header: %d want 400", r2.StatusCode)
	}
	if hits, _, _, _ := s.get(); hits != 1 {
		t.Fatalf("hits=%d", hits)
	}
}

// A non-routed, allowlisted path (model listing) has no policy upstream, so it
// goes to defaultUpstream: identity is still verified, client credentials and
// x-halo-* are stripped, and cohort headers are the gateway's own.
func TestDefaultUpstreamFallbackForNonRoutedPaths(t *testing.T) {
	def, defSeen := recordingServer(t)
	routed, routedSeen := recordingServer(t)
	e := testEnv(t, routed, func(c *Config, _ *policy.Org) { c.DefaultUpstream = def.URL })
	get := func(path, tok string, hdr map[string]string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.proxy.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	tok := e.token(t, "alice@acme.com", "ai-platform")
	resp := get("/v1/models", tok, map[string]string{
		"x-api-key": "client-key", "x-goog-api-key": "k", "x-halo-ring": "ga", "x-halo-variant": "evil", "X-Halo-Custom": "1"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	hits, h, _, raw := defSeen.get()
	if hits != 1 || raw != "/v1/models" || routedSeen.hitCount() != 0 {
		t.Fatalf("default upstream hits %d path %q, policy upstream hits %d", hits, raw, routedSeen.hitCount())
	}
	for _, k := range []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key", "X-Halo-Variant", "X-Halo-Custom"} {
		if h.Get(k) != "" {
			t.Errorf("%s reached the default upstream: %q", k, h.Get(k))
		}
	}
	if h.Get("x-halo-ring") != "ring0" { // from the verified groups claim, not the client's "ga"
		t.Errorf("x-halo-ring=%q, want ring0", h.Get("x-halo-ring"))
	}

	// Identity is verified on this path too, and nothing else is passed through.
	before := defSeen.hitCount()
	if r := get("/v1/models", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated: status %d, want 401", r.StatusCode)
	}
	if r := get("/v1/admin/keys", tok, nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("non-allowlisted path: status %d, want 404", r.StatusCode)
	}
	if defSeen.hitCount() != before {
		t.Fatal("a refused request reached the default upstream")
	}
}
