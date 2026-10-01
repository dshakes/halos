package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

const geminiBody = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`

func geminiEnv(t *testing.T, up policy.Upstream, mod func(*Config)) *env {
	t.Helper()
	return testEnv(t, httptest.NewServer(http.NotFoundHandler()), func(c *Config, o *policy.Org) {
		o.Gateway.Upstreams["g"] = up
		o.Gateway.Models["gemini-default"] = policy.ModelRoute{Upstream: "g", Model: "gemini-2.5-pro"}
		c.UpstreamHeaders = nil
		if mod != nil {
			mod(c)
		}
	})
}

func gemPost(t *testing.T, e *env, path, key, body string, hdr map[string]string) *http.Response {
	t.Helper()
	h := map[string]string{}
	if key != "" {
		h["x-goog-api-key"] = key
	}
	for k, v := range hdr {
		h[k] = v
	}
	return e.post(t, path, "", body, h)
}

func TestGeminiWireRoutingIdentityAndSSE(t *testing.T) {
	srv, s := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"candidates\":[]}\n\n")
	})
	e := geminiEnv(t, policy.Upstream{URL: srv.URL, Kind: "gemini"}, nil)
	jwt := e.token(t, "alice@acme.com", "ai-platform")

	resp := gemPost(t, e, "/v1beta/models/gemini-default:streamGenerateContent?alt=sse&key=leak", jwt, geminiBody,
		map[string]string{"x-halo-ring": "ga", "Proxy-Authorization": "p", "x-gemini-api-privileged-user-id": "install-123"})
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.HasPrefix(string(b), "data: ") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status %d ct %q body %q", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
	_, h, _, raw := s.get()
	if raw != "/v1beta/models/gemini-2.5-pro:streamGenerateContent" {
		t.Errorf("alias not rewritten: %q", raw)
	}
	for _, k := range []string{"x-goog-api-key", "Authorization", "Proxy-Authorization", "x-gemini-api-privileged-user-id"} {
		if h.Get(k) != "" {
			t.Errorf("client credential %s reached the upstream: %q", k, h.Get(k))
		}
	}
	if h.Get("x-halo-ring") != "ring0" {
		t.Errorf("cohort must come from the verified key, got x-halo-ring=%q", h.Get("x-halo-ring"))
	}

	// non-streaming and token counting are routed too
	for _, op := range []string{"generateContent", "countTokens"} {
		if r := gemPost(t, e, "/v1beta/models/gemini-default:"+op, jwt, geminiBody, nil); r.StatusCode != 200 {
			t.Errorf("%s: status %d", op, r.StatusCode)
		}
	}
}

func TestGeminiKeyOnlyAcceptedOnGeminiWire(t *testing.T) {
	srv, s := upstream(t, respond(200, `{}`))
	e := geminiEnv(t, policy.Upstream{URL: srv.URL, Kind: "gemini"}, nil)
	jwt := e.token(t, "alice@acme.com")
	before := s.hitCount()
	// the same token in x-goog-api-key on another wire is no credential
	if r := gemPost(t, e, "/v1/messages", jwt, msgBody, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("anthropic wire accepted x-goog-api-key: status %d", r.StatusCode)
	}
	if r := gemPost(t, e, "/v1/responses", jwt, `{"model":"sonnet","input":"hi"}`, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("responses wire accepted x-goog-api-key: status %d", r.StatusCode)
	}
	// bad or missing key on the gemini wire
	for name, key := range map[string]string{"garbage": "not-a-jwt", "missing": ""} {
		if r := gemPost(t, e, "/v1beta/models/gemini-default:generateContent", key, geminiBody, nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s key: status %d, want 401", name, r.StatusCode)
		}
	}
	if s.hitCount() != before {
		t.Fatal("unauthenticated requests reached the upstream")
	}
}

func TestGeminiUnknownModelDenied(t *testing.T) {
	srv, s := upstream(t, respond(200, `{}`))
	e := geminiEnv(t, policy.Upstream{URL: srv.URL, Kind: "gemini"}, nil)
	jwt := e.token(t, "alice@acme.com")
	for _, path := range []string{"/v1beta/models/gemini-ultra-secret:generateContent", "/v1beta/models/gemini-default:embedContent", "/v1/models/gemini-default:batchEmbedContents"} {
		r := gemPost(t, e, path, jwt, geminiBody, nil)
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusBadRequest && r.StatusCode != http.StatusNotFound && r.StatusCode != http.StatusUnauthorized { // unsupported ops are not a gemini model call: refused at identity or routing
			t.Errorf("%s: status %d: %s", path, r.StatusCode, b)
		}
		if !strings.Contains(string(b), `"status"`) && r.StatusCode == http.StatusBadRequest {
			t.Errorf("%s: not a Gemini-shaped error: %s", path, b)
		}
	}
	if s.hitCount() != 0 {
		t.Fatal("a refused request reached the upstream")
	}
}

func TestGeminiUpstreamCredentialIsTheGateways(t *testing.T) {
	srv, s := upstream(t, respond(200, `{}`))
	e := geminiEnv(t, policy.Upstream{URL: srv.URL, Kind: "gemini", Credential: &policy.Credential{Env: "GEMINI_KEY"}}, func(c *Config) {
		c.UpstreamHosts, c.AllowInsecureUpstreams, c.ForwardAuth = []string{"127.0.0.1"}, true, true
	})
	e.p.getenv = func(string) string { return "gateway-gemini-key" }
	r := gemPost(t, e, "/v1beta/models/gemini-default:generateContent?key=client", e.token(t, "alice@acme.com"), geminiBody, nil)
	if r.StatusCode != 200 {
		t.Fatalf("status %d", r.StatusCode)
	}
	_, h, _, _ := s.get()
	if h.Get("x-goog-api-key") != "gateway-gemini-key" || h.Get("Authorization") != "" {
		t.Errorf("upstream credentials: %v", h)
	}
}

func TestGeminiWireSkipsNonGeminiTargets(t *testing.T) {
	srv, s := upstream(t, respond(200, `{}`))
	e := geminiEnv(t, policy.Upstream{URL: srv.URL, Kind: "anthropic"}, nil) // an anthropic upstream cannot answer a gemini client
	r := gemPost(t, e, "/v1beta/models/gemini-default:generateContent", e.token(t, "alice@acme.com"), geminiBody, nil)
	if r.StatusCode != http.StatusBadGateway || s.hitCount() != 0 {
		t.Fatalf("status %d hits %d", r.StatusCode, s.hitCount())
	}
}
