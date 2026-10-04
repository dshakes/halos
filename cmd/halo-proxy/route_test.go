package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/dshakes/halos/internal/policy"
)

// upstream is a fake provider that counts hits and records the last request.
func upstream(t *testing.T, h http.HandlerFunc) (*httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.record(r.Clone(r.Context()))
		s.mu.Lock()
		s.body = string(b)
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

func respond(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func (s *seen) hitCount() int { n, _, _, _ := s.get(); return n }

type fakeTokens struct{ tok string }

func (f fakeTokens) Token(context.Context) (string, error) { return f.tok, nil }

const opusBody = `{"model":"opus","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`

// routeEnv serves alias "opus" with the given targets over named upstreams.
func routeEnv(t *testing.T, ups map[string]policy.Upstream, targets []policy.RouteTarget, cfg func(*Config)) *env {
	t.Helper()
	return testEnv(t, httptest.NewServer(http.NotFoundHandler()), func(c *Config, o *policy.Org) {
		for n, u := range ups {
			o.Gateway.Upstreams[n] = u
		}
		o.Gateway.Models["opus"] = policy.ModelRoute{Targets: targets}
		c.UpstreamHeaders = map[string]map[string]string{"p": {"x-api-key": "key-p"}, "s": {"x-api-key": "key-s"}}
		if cfg != nil {
			cfg(c)
		}
	})
}

func anthropic(url string) policy.Upstream { return policy.Upstream{URL: url, Kind: "anthropic"} }

func primarySecondary(p, s *httptest.Server) (map[string]policy.Upstream, []policy.RouteTarget) {
	return map[string]policy.Upstream{"p": anthropic(p.URL), "s": anthropic(s.URL)},
		[]policy.RouteTarget{{Upstream: "p", Model: "m-primary"}, {Upstream: "s", Model: "m-secondary", Priority: 1}}
}

func TestFailoverBeforeFirstByte(t *testing.T) {
	slow := func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	for name, mode := range map[string]struct {
		handler http.HandlerFunc
		closed  bool // primary is not listening at all
	}{
		"5xx":             {handler: respond(503, `{"error":"overloaded"}`)},
		"429":             {handler: respond(429, `{"error":"rate"}`)},
		"connect refused": {handler: respond(200, ""), closed: true},
		"header timeout":  {handler: slow},
	} {
		t.Run(name, func(t *testing.T) {
			pSrv, pSeen := upstream(t, mode.handler)
			sSrv, sSeen := upstream(t, respond(200, `{"from":"secondary"}`))
			ups, targets := primarySecondary(pSrv, sSrv)
			e := routeEnv(t, ups, targets, func(c *Config) { c.UpstreamHeaderTimeout = 150 * time.Millisecond })
			if mode.closed {
				pSrv.Close() // after routeEnv: a server it starts could otherwise reuse the freed port
			}
			resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || !strings.Contains(string(b), "secondary") {
				t.Fatalf("status %d body %s", resp.StatusCode, b)
			}
			if want := map[bool]int{true: 0, false: 1}[mode.closed]; pSeen.hitCount() != want || sSeen.hitCount() != 1 {
				t.Fatalf("hits primary=%d secondary=%d", pSeen.hitCount(), sSeen.hitCount())
			}
			_, h, body, _ := sSeen.get()
			if !strings.Contains(body, `"model":"m-secondary"`) {
				t.Errorf("secondary got body %s", body)
			}
			if h.Get("x-api-key") != "key-s" {
				t.Errorf("secondary x-api-key=%q: the primary's upstream header must not carry over", h.Get("x-api-key"))
			}
			rec := httptest.NewRecorder()
			e.p.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
			if !strings.Contains(rec.Body.String(), `halo_proxy_upstream_attempts_total{provider="anthropic",outcome="failed"} 1`) {
				t.Errorf("failed attempt not counted:\n%s", rec.Body)
			}
		})
	}
}

func TestNoRetryAfterStreamingStarted(t *testing.T) {
	pSrv, pSeen := upstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		panic(http.ErrAbortHandler) // upstream dies mid-stream
	})
	sSrv, sSeen := upstream(t, respond(200, `{"from":"secondary"}`))
	ups, targets := primarySecondary(pSrv, sSrv)
	e := routeEnv(t, ups, targets, nil)
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
	b, err := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "data: one") {
		t.Fatalf("client should have received the first chunk, got %q (%v)", b, err)
	}
	if err == nil {
		t.Error("the client must see the truncated stream as an error, not a clean end")
	}
	if pSeen.hitCount() != 1 || sSeen.hitCount() != 0 {
		t.Fatalf("retried after the first byte: primary=%d secondary=%d", pSeen.hitCount(), sSeen.hitCount())
	}
}

func TestLastFailureReturnedWhenAllTargetsFail(t *testing.T) {
	pSrv, _ := upstream(t, respond(503, `{"who":"primary"}`))
	sSrv, _ := upstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		respond(429, `{"who":"secondary"}`)(w, nil)
	})
	ups, targets := primarySecondary(pSrv, sSrv)
	e := routeEnv(t, ups, targets, nil)
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "7" || !strings.Contains(string(b), "secondary") {
		t.Fatalf("status %d retry-after %q body %s", resp.StatusCode, resp.Header.Get("Retry-After"), b)
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	pSrv, pSeen := upstream(t, respond(400, `{"error":"bad request"}`))
	sSrv, sSeen := upstream(t, respond(200, `{}`))
	ups, targets := primarySecondary(pSrv, sSrv)
	e := routeEnv(t, ups, targets, nil)
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
	if resp.StatusCode != 400 || pSeen.hitCount() != 1 || sSeen.hitCount() != 0 {
		t.Fatalf("status %d primary=%d secondary=%d", resp.StatusCode, pSeen.hitCount(), sSeen.hitCount())
	}
}

func TestMaxAttemptsBoundsRetries(t *testing.T) {
	var servers [3]*seen
	ups := map[string]policy.Upstream{}
	var targets []policy.RouteTarget
	for i := range servers {
		srv, s := upstream(t, respond(502, `{}`))
		servers[i] = s
		n := fmt.Sprint("u", i)
		ups[n] = anthropic(srv.URL)
		targets = append(targets, policy.RouteTarget{Upstream: n, Model: "m", Priority: i})
	}
	e := routeEnv(t, ups, targets, func(c *Config) { c.Route.MaxAttempts = 2 })
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
	if resp.StatusCode != 502 || servers[0].hitCount() != 1 || servers[1].hitCount() != 1 || servers[2].hitCount() != 0 {
		t.Fatalf("status %d hits %d/%d/%d", resp.StatusCode, servers[0].hitCount(), servers[1].hitCount(), servers[2].hitCount())
	}
}

func TestCircuitBreakerSkipsFailingTarget(t *testing.T) {
	pSrv, pSeen := upstream(t, respond(500, `{}`))
	sSrv, sSeen := upstream(t, respond(200, `{"ok":1}`))
	ups, targets := primarySecondary(pSrv, sSrv)
	e := routeEnv(t, ups, targets, func(c *Config) { c.Route.BreakerFailures, c.Route.BreakerCooldown = 2, time.Hour })
	tok := e.token(t, "alice@acme.com")
	for range 4 {
		if resp := e.post(t, "/v1/messages", tok, opusBody, nil); resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if pSeen.hitCount() != 2 || sSeen.hitCount() != 4 {
		t.Fatalf("breaker should open after 2 failures: primary=%d secondary=%d", pSeen.hitCount(), sSeen.hitCount())
	}
	rec := httptest.NewRecorder()
	e.p.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `outcome="circuit_open"} 2`) {
		t.Errorf("circuit_open not counted:\n%s", rec.Body)
	}
}

func TestAllCircuitsOpenIs503(t *testing.T) {
	pSrv, _ := upstream(t, respond(500, `{}`))
	sSrv, _ := upstream(t, respond(500, `{}`))
	ups, targets := primarySecondary(pSrv, sSrv)
	e := routeEnv(t, ups, targets, func(c *Config) { c.Route.BreakerFailures, c.Route.BreakerCooldown = 1, time.Hour })
	tok := e.token(t, "alice@acme.com")
	e.post(t, "/v1/messages", tok, opusBody, nil) // trips both
	if resp := e.post(t, "/v1/messages", tok, opusBody, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
}

func TestWeightedSplitIsStickyPerSession(t *testing.T) {
	aSrv, aSeen := upstream(t, respond(200, `{}`))
	bSrv, bSeen := upstream(t, respond(200, `{}`))
	e := routeEnv(t, map[string]policy.Upstream{"a": anthropic(aSrv.URL), "b": anthropic(bSrv.URL)},
		[]policy.RouteTarget{{Upstream: "a", Model: "m1", Weight: 90}, {Upstream: "b", Model: "m2", Weight: 10}}, nil)
	tok := e.token(t, "alice@acme.com")
	hdr := func(s string) map[string]string { return map[string]string{"x-claude-code-session-id": s} }
	// Known answers for alias opus (bucket of route/opus/0): s1 -> 1645 -> a, s9 -> 9176 -> b.
	for range 3 {
		e.post(t, "/v1/messages", tok, opusBody, hdr("s1"))
	}
	if aSeen.hitCount() != 3 || bSeen.hitCount() != 0 {
		t.Fatalf("s1 should stay on a: a=%d b=%d", aSeen.hitCount(), bSeen.hitCount())
	}
	for range 3 {
		e.post(t, "/v1/messages", tok, opusBody, hdr("s9"))
	}
	if aSeen.hitCount() != 3 || bSeen.hitCount() != 3 {
		t.Fatalf("s9 should stay on b: a=%d b=%d", aSeen.hitCount(), bSeen.hitCount())
	}
	if _, _, body, _ := bSeen.get(); !strings.Contains(body, `"model":"m2"`) {
		t.Errorf("b got %s", body)
	}
}

func TestVertexRoute(t *testing.T) {
	srv, s := upstream(t, respond(200, `{"ok":true}`))
	ups := map[string]policy.Upstream{"v": {URL: srv.URL, Kind: "vertex", Project: "proj", Region: "us-east5"}}
	e := routeEnv(t, ups, []policy.RouteTarget{{Upstream: "v", Model: "claude-opus-4-1@20250805"}}, func(c *Config) {
		c.UpstreamHosts, c.AllowInsecureUpstreams = []string{"127.0.0.1"}, true
		c.ForwardAuth = true // even then, the client's credentials must not reach Vertex
	})
	e.p.vertexTS = fakeTokens{"ya29.fake"}
	const base = "/v1/projects/proj/locations/us-east5/publishers/anthropic/models/claude-opus-4-1@20250805"

	resp := e.post(t, "/v1/messages?beta=true", e.token(t, "alice@acme.com"), opusBody, map[string]string{"x-api-key": "client", "anthropic-version": "2023-06-01"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, h, body, raw := s.get()
	if raw != base+":rawPredict" {
		t.Errorf("path %q", raw)
	}
	if h.Get("Authorization") != "Bearer ya29.fake" || h.Get("x-api-key") != "" || h.Get("anthropic-version") != "" {
		t.Errorf("auth headers: %v", h)
	}
	if strings.Contains(body, `"model"`) || !strings.Contains(body, `"anthropic_version":"vertex-2023-10-16"`) {
		t.Errorf("body %s", body)
	}

	e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), strings.Replace(opusBody, `"max_tokens"`, `"stream":true,"max_tokens"`, 1), nil)
	if _, _, _, raw = s.get(); raw != base+":streamRawPredict" {
		t.Errorf("stream path %q", raw)
	}
}

func TestOpenAIAndAzureAuth(t *testing.T) {
	srv, s := upstream(t, respond(200, `{}`))
	ups := map[string]policy.Upstream{
		"az":  {URL: srv.URL, Kind: "azure-openai", Credential: &policy.Credential{Env: "AZ_KEY"}},
		"oai": {URL: srv.URL, Kind: "openai", Credential: &policy.Credential{Env: "OAI_KEY"}},
	}
	e := routeEnv(t, ups, []policy.RouteTarget{{Upstream: "az", Model: "deploy-1"}}, func(c *Config) {
		c.UpstreamHosts, c.AllowInsecureUpstreams = []string{"127.0.0.1"}, true
	})
	e.p.getenv = func(k string) string { return map[string]string{"AZ_KEY": "azure-secret", "OAI_KEY": "oai-secret"}[k] }
	org, _ := e.p.snap.Get()
	org.Gateway.Models["gpt"] = policy.ModelRoute{Targets: []policy.RouteTarget{{Upstream: "az", Model: "deploy-1"}}}
	org.Gateway.Models["gpt-oai"] = policy.ModelRoute{Targets: []policy.RouteTarget{{Upstream: "oai", Model: "gpt-5"}}}
	e.writePolicy(t, org)
	tok := e.token(t, "alice@acme.com")
	req := func(alias string) {
		resp := e.post(t, "/v1/responses", tok, fmt.Sprintf(`{"model":%q,"input":"hi"}`, alias), map[string]string{"x-api-key": "client", "api-key": "client"})
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", alias, resp.StatusCode)
		}
	}
	waitPolicy(t, e, "gpt")

	req("gpt")
	_, h, body, raw := s.get()
	if raw != "/openai/v1/responses" || h.Get("api-key") != "azure-secret" || h.Get("Authorization") != "" || h.Get("x-api-key") != "" || !strings.Contains(body, `"model":"deploy-1"`) {
		t.Errorf("azure: path %q headers %v body %s", raw, h, body)
	}
	req("gpt-oai")
	_, h, body, raw = s.get()
	if raw != "/v1/responses" || h.Get("Authorization") != "Bearer oai-secret" || h.Get("api-key") != "" || h.Get("x-api-key") != "" || !strings.Contains(body, `"model":"gpt-5"`) {
		t.Errorf("openai: path %q headers %v body %s", raw, h, body)
	}

	e.p.getenv = func(string) string { return "" } // secret gone: fail, never forward unauthenticated
	hits := s.hitCount()
	if resp := e.post(t, "/v1/responses", tok, `{"model":"gpt","input":"hi"}`, nil); resp.StatusCode != http.StatusBadGateway || s.hitCount() != hits {
		t.Fatalf("missing secret: status %d, extra hits %d", resp.StatusCode, s.hitCount()-hits)
	}
}

// waitPolicy blocks until the proxy's snapshot serves alias (policy files are polled).
func waitPolicy(t *testing.T, e *env, alias string) {
	t.Helper()
	for range 100 {
		if org, _ := e.p.snap.Get(); org != nil && len(org.Gateway.Models[alias].Candidates()) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("policy never served alias %q", alias)
}

func TestCredentialedHostAllowlist(t *testing.T) {
	srv, s := upstream(t, respond(200, `{}`))
	ups := map[string]policy.Upstream{"v": {URL: srv.URL, Kind: "vertex", Project: "p", Region: "global"}}
	targets := []policy.RouteTarget{{Upstream: "v", Model: "m"}}
	for name, cfg := range map[string]func(*Config){
		"host not allowed":   func(c *Config) { c.AllowInsecureUpstreams = true },
		"http not permitted": func(c *Config) { c.UpstreamHosts = []string{"127.0.0.1"} },
	} {
		t.Run(name, func(t *testing.T) {
			e := routeEnv(t, ups, targets, cfg)
			e.p.vertexTS = fakeTokens{"must-not-leak"}
			resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status %d, want 502", resp.StatusCode)
			}
		})
	}
	if s.hitCount() != 0 {
		t.Fatal("a credentialed request reached a disallowed host")
	}

	t.Run("disallowed target is skipped, next one serves", func(t *testing.T) {
		okSrv, okSeen := upstream(t, respond(200, `{"from":"anthropic"}`))
		ups := map[string]policy.Upstream{"v": ups["v"], "s": anthropic(okSrv.URL)}
		e := routeEnv(t, ups, []policy.RouteTarget{{Upstream: "v", Model: "m"}, {Upstream: "s", Model: "m2", Priority: 1}}, nil)
		e.p.vertexTS = fakeTokens{"must-not-leak"}
		resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
		if resp.StatusCode != 200 || okSeen.hitCount() != 1 || s.hitCount() != 0 {
			t.Fatalf("status %d hits ok=%d vertex=%d", resp.StatusCode, okSeen.hitCount(), s.hitCount())
		}
	})
}

func TestRoutedRequestsStripSpoofedHaloHeaders(t *testing.T) {
	srv, s := upstream(t, respond(200, `{}`))
	ups := map[string]policy.Upstream{"p": anthropic(srv.URL)}
	e := routeEnv(t, ups, []policy.RouteTarget{{Upstream: "p", Model: "m"}, {Upstream: "p", Model: "m2", Priority: 1}}, nil)
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com", "ai-platform"), opusBody, map[string]string{
		"x-halo-ring": "ga", "x-halo-release": "sha256:evil", "x-halo-variant": "control", "X-Halo-Custom": "1", "x-halo-provider": "evil",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, h, _, _ := s.get()
	if h.Get("x-halo-ring") != "ring0" || h.Get("x-halo-release") == "sha256:evil" || h.Get("x-halo-variant") != "" || h.Get("X-Halo-Custom") != "" || h.Get("x-halo-provider") != "" {
		t.Fatalf("spoofed headers leaked or cohort taken from client: %v", h)
	}
}

// bedrock frames, as AWS sends them for invoke-with-response-stream.
func esFrame(event string) []byte {
	pl, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(event))})
	var h bytes.Buffer
	for _, kv := range [][2]string{{":event-type", "chunk"}, {":message-type", "event"}} {
		h.WriteByte(byte(len(kv[0])))
		h.WriteString(kv[0])
		h.WriteByte(7)
		binary.Write(&h, binary.BigEndian, uint16(len(kv[1])))
		h.WriteString(kv[1])
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(16+h.Len()+len(pl)))
	binary.Write(&b, binary.BigEndian, uint32(h.Len()))
	binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(b.Bytes()))
	b.Write(h.Bytes())
	b.Write(pl)
	binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(b.Bytes()))
	return b.Bytes()
}

func TestAnthropicClientToBedrockStreamsSSE(t *testing.T) {
	srv, s := upstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.Write(esFrame(`{"type":"message_start"}`))
		w.Write(esFrame(`{"type":"message_stop"}`))
	})
	e := routeEnv(t, map[string]policy.Upstream{"b": {URL: srv.URL, Kind: "bedrock", Region: "us-west-2"}},
		[]policy.RouteTarget{{Upstream: "b", Model: "us.anthropic.claude-opus-4-1:0"}}, func(c *Config) { c.SignHosts = []string{"127.0.0.1"} })
	e.p.sigv4.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"}, nil
	})
	resp := e.post(t, "/v1/messages?beta=true", e.token(t, "alice@acme.com"), strings.Replace(opusBody, `"max_tokens"`, `"stream":true,"max_tokens"`, 1), nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" ||
		!strings.Contains(string(b), "event: message_start\ndata: {\"type\":\"message_start\"}\n\n") || !strings.Contains(string(b), "event: message_stop") {
		t.Fatalf("status %d ct %q body %q", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
	_, h, body, raw := s.get()
	if raw != "/model/us.anthropic.claude-opus-4-1%3A0/invoke-with-response-stream" || !strings.HasPrefix(h.Get("Authorization"), "AWS4-HMAC-SHA256") ||
		strings.Contains(body, `"model"`) || strings.Contains(body, `"stream"`) || !strings.Contains(body, "bedrock-2023-05-31") {
		t.Errorf("bedrock request: path %q auth %q body %s", raw, h.Get("Authorization"), body)
	}
}

func TestBedrockPrimaryFailsOverToAnthropicDirect(t *testing.T) {
	bSrv, bSeen := upstream(t, respond(200, `{}`))
	aSrv, aSeen := upstream(t, respond(200, `{"from":"anthropic-direct"}`))
	var calls atomic.Int32
	e := routeEnv(t, map[string]policy.Upstream{"p": {URL: bSrv.URL, Kind: "bedrock", Region: "us-west-2"}, "s": anthropic(aSrv.URL)},
		[]policy.RouteTarget{{Upstream: "p", Model: "us.anthropic.x"}, {Upstream: "s", Model: "claude-opus-4-1", Priority: 1}},
		func(c *Config) { c.SignHosts = []string{"127.0.0.1"} })
	e.p.sigv4.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		calls.Add(1)
		return aws.Credentials{}, errors.New("no AWS credentials")
	})
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "anthropic-direct") || bSeen.hitCount() != 0 || aSeen.hitCount() != 1 || calls.Load() == 0 {
		t.Fatalf("status %d body %s bedrock=%d anthropic=%d", resp.StatusCode, b, bSeen.hitCount(), aSeen.hitCount())
	}
}

// Every client credential header must be gone on every upstream kind; only the
// gateway's own credential (if any) may arrive.
func TestClientCredentialHeadersStrippedOnEveryKind(t *testing.T) {
	creds := map[string]string{"Authorization": "", "X-Api-Key": "c1", "Api-Key": "c2", "X-Goog-Api-Key": "c3", "Proxy-Authorization": "c4"}
	for _, tc := range []struct {
		name, path, body string
		up               func(url string) policy.Upstream
		wantOnly         string // the one credential header the gateway itself may send
		wantValue        string
	}{
		{"anthropic", "/v1/messages", opusBody, func(u string) policy.Upstream { return anthropic(u) }, "", ""},
		{"vertex", "/v1/messages", opusBody, func(u string) policy.Upstream {
			return policy.Upstream{URL: u, Kind: "vertex", Project: "p", Region: "global"}
		}, "Authorization", "Bearer gw-token"},
		{"bedrock", "/v1/messages", opusBody, func(u string) policy.Upstream {
			return policy.Upstream{URL: u, Kind: "bedrock", Region: "us-west-2"}
		}, "Authorization", "AWS4"},
		{"azure-openai", "/v1/responses", `{"model":"opus","input":"hi"}`, func(u string) policy.Upstream {
			return policy.Upstream{URL: u, Kind: "azure-openai", Credential: &policy.Credential{Env: "K"}}
		}, "Api-Key", "gw-secret"},
		{"openai", "/v1/responses", `{"model":"opus","input":"hi"}`, func(u string) policy.Upstream {
			return policy.Upstream{URL: u, Kind: "openai", Credential: &policy.Credential{Env: "K"}}
		}, "Authorization", "Bearer gw-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, s := upstream(t, respond(200, `{}`))
			e := routeEnv(t, map[string]policy.Upstream{"u": tc.up(srv.URL)}, []policy.RouteTarget{{Upstream: "u", Model: "m"}}, func(c *Config) {
				c.UpstreamHosts, c.AllowInsecureUpstreams, c.SignHosts, c.UpstreamHeaders = []string{"127.0.0.1"}, true, []string{"127.0.0.1"}, nil
			})
			e.p.vertexTS = fakeTokens{"gw-token"}
			e.p.getenv = func(string) string { return "gw-secret" }
			e.p.sigv4.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"}, nil
			})
			hdr := map[string]string{}
			for k, v := range creds {
				if v != "" {
					hdr[k] = v
				}
			}
			resp := e.post(t, tc.path, e.token(t, "alice@acme.com"), tc.body, hdr)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			_, h, _, _ := s.get()
			for k := range creds {
				v := h.Get(k)
				if k == tc.wantOnly {
					if v != tc.wantValue && (tc.wantValue != "AWS4" || !strings.HasPrefix(v, "AWS4-HMAC-SHA256 ")) {
						t.Errorf("%s=%q: want only the gateway's own credential %q", k, v, tc.wantValue)
					}
					continue
				}
				if v != "" {
					t.Errorf("client credential header %s reached %s upstream: %q", k, tc.name, v)
				}
			}
		})
	}

	t.Run("legacy single route", func(t *testing.T) {
		srv, s := upstream(t, respond(200, `{}`))
		e := testEnv(t, srv, func(c *Config, _ *policy.Org) { c.UpstreamHeaders = nil })
		hdr := map[string]string{"X-Api-Key": "c1", "Api-Key": "c2", "X-Goog-Api-Key": "c3", "Proxy-Authorization": "c4"}
		e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), msgBody, hdr)
		_, h, _, _ := s.get()
		for _, k := range []string{"Authorization", "X-Api-Key", "Api-Key", "X-Goog-Api-Key", "Proxy-Authorization"} {
			if h.Get(k) != "" {
				t.Errorf("%s reached the upstream: %q", k, h.Get(k))
			}
		}
	})
}
