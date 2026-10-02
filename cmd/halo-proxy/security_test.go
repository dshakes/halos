package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// trailerServer records the request trailers the upstream received.
func trailerServer(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // trailers are only populated after EOF
		mu.Lock()
		got = r.Trailer.Clone()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header { mu.Lock(); defer mu.Unlock(); return got }
}

// Request trailers are headers too: a chunked request can carry x-halo-*,
// identity or credential "headers" after the body. None may reach an upstream,
// on the routed path, the nextHop path or the non-model passthrough.
func TestRequestTrailersNeverForwarded(t *testing.T) {
	up, upTrailers := trailerServer(t)
	next, nextTrailers := trailerServer(t)
	for _, tc := range []struct {
		name    string
		mod     func(*Config, *policy.Org)
		path    string
		body    string
		trailer func() http.Header
	}{
		{"routed model call", nil, "/v1/messages", msgBody, upTrailers},
		{"nextHop model call", func(c *Config, _ *policy.Org) { c.NextHop = next.URL }, "/v1/messages", msgBody, nextTrailers},
		{"passthrough", func(c *Config, _ *policy.Org) { c.DefaultUpstream = next.URL }, "/v1/models", "x", nextTrailers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := testEnv(t, up, tc.mod)
			req, _ := http.NewRequest(http.MethodPost, e.proxy.URL+tc.path, io.MultiReader(strings.NewReader(tc.body))) // unknown length => chunked
			req.Header.Set("Authorization", "Bearer "+e.token(t, "alice@acme.com", "ai-platform"))
			req.Trailer = http.Header{"X-Halo-Ring": {"ga"}, "X-Halo-Experiment": {"evil"}, "X-Acme-User": {"mallory"}, "X-Api-Key": {"client-key"}}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if got := tc.trailer(); len(got) != 0 {
				t.Fatalf("client trailers reached the upstream: %v", got)
			}
		})
	}
}

// Every inbound x-halo-* is dropped whatever its case or repetition, and over
// HTTP/2 (lowercase on the wire).
func TestHaloHeadersStrippedAnyCaseRepeatedAndH2(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, nil)
	h2 := httptest.NewUnstartedServer(e.p)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	t.Cleanup(h2.Close)
	h2c := h2.Client()
	h2c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}} //nolint:gosec // test server cert

	for _, tc := range []struct {
		name   string
		base   string
		client *http.Client
		wantH2 bool
	}{{"http1", e.proxy.URL, http.DefaultClient, false}, {"h2", h2.URL, h2c, true}} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, tc.base+"/v1/messages", strings.NewReader(msgBody))
			req.Header.Set("Authorization", "Bearer "+e.token(t, "alice@acme.com"))
			// Non-canonical keys bypass Header.Set canonicalization, as a raw client would send them.
			req.Header["x-halo-ring"] = []string{"ring0", "ring0"}
			req.Header["X-HALO-VARIANT"] = []string{"direct"}
			req.Header["x-Halo-Experiment"] = []string{"a", "b"}
			req.Header["X-Halo-Release"] = []string{"sha256:evil"}
			req.Header["x-halo-killswitch"] = []string{"ok"}
			req.Header["X-Halo-Whatever"] = []string{"1", "2", "3"}
			resp, err := tc.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || (resp.ProtoMajor == 2) != tc.wantH2 {
				t.Fatalf("status %d proto %s", resp.StatusCode, resp.Proto)
			}
			_, h, _, _ := s.get()
			for k, v := range h {
				if !strings.HasPrefix(strings.ToLower(k), "x-halo-") {
					continue
				}
				if k != "X-Halo-Ring" || len(v) != 1 || v[0] != "ga" { // the gateway's own, from the verified (group-less) subject
					t.Errorf("client x-halo header reached upstream: %s=%v", k, v)
				}
			}
		})
	}
}

// Credentials and tokens never reach the logs, on success, on rejection, or on
// an upstream failure.
func TestSecretsNeverLogged(t *testing.T) {
	const secret = "SENTINEL-SECRET-9f2c"
	up, _ := recordingServer(t)
	var buf syncBuffer
	e := testEnv(t, up, func(c *Config, _ *policy.Org) {
		c.UpstreamHeaders = map[string]map[string]string{"up": {"x-api-key": secret + "-provider"}}
	})
	e.p.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	wait := e.awaitHandlers(t, 4)
	good := e.token(t, "alice@acme.com")
	hdr := map[string]string{"x-api-key": secret + "-xapikey", "Proxy-Authorization": "Basic " + secret, "Cookie": "s=" + secret}
	e.post(t, "/v1/messages", good, msgBody, hdr)                        // 200
	e.post(t, "/v1/messages", secret+".bad.jwt", msgBody, hdr)           // 401, logged rejection
	e.post(t, "/v1/messages", good[:len(good)-4]+"AAAA", msgBody, hdr)   // 401, bad signature
	e.post(t, "/v1/messages?key="+secret, good, `{"model":"nope"}`, hdr) // 400
	wait()

	// Upstream failure with forwardAuth (credentials and ?key= are forwarded):
	// the transport error is logged, the credentials are not.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	e2 := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.ForwardAuth = true
		o.Gateway.Upstreams["up"] = policy.Upstream{URL: dead.URL, Kind: "anthropic"}
	})
	e2.p.log = e.p.log
	good2 := e2.token(t, "alice@acme.com")
	wait = e2.awaitHandlers(t, 2)
	if r := e2.post(t, "/v1/messages?key="+secret, good2, msgBody, hdr); r.StatusCode != http.StatusBadGateway {
		t.Fatalf("dead upstream: status %d", r.StatusCode)
	}
	e2.cfg.NextHop = dead.URL
	e2.p.next, _ = parseBase(dead.URL)
	if r := e2.post(t, "/v1/messages?key="+secret, good2, msgBody, hdr); r.StatusCode != http.StatusBadGateway {
		t.Fatalf("dead next hop: status %d", r.StatusCode)
	}
	wait()

	logs := buf.String()
	if !strings.Contains(logs, "upstream error") {
		t.Fatalf("expected the upstream failure to be logged:\n%s", logs)
	}
	if !strings.Contains(logs, "identity rejected") {
		t.Fatalf("expected rejection to be logged:\n%s", logs)
	}
	for _, s := range []string{secret, good, good[strings.LastIndex(good, ".")+1:], good2} {
		if strings.Contains(logs, s) {
			t.Fatalf("secret %q found in logs:\n%s", s, logs)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// allowAnonymous only ever yields default routing: a caller whose token fails
// verification is never enrolled, even in a 100% experiment on every ring.
func TestAllowAnonymousNeverGetsExperiment(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.Identity.AllowAnonymous = true
		o.Experiments = []*policy.Experiment{{
			Meta: policy.Meta{Name: "all-in"}, Type: policy.ExperimentCanary, Axis: policy.AxisTraffic,
			Status: "running", Rings: []string{"ring0", "ga", "unknown"},
			Variants: []policy.Variant{{Name: "control", Weight: 0, Control: true},
				{Name: "treat", Weight: 100, Routes: map[string]policy.ModelRoute{"sonnet": {Upstream: "up", Model: "treat-model"}}}},
		}}
	})
	// Positive control: a verified user is enrolled.
	e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), msgBody, nil)
	if _, h, body, _ := s.get(); h.Get("x-halo-experiment") != "all-in" || !strings.Contains(body, "treat-model") {
		t.Fatalf("verified user not enrolled: %v %s", h, body)
	}
	other, _ := e.iss.Mint(map[string]any{"aud": "someone-else", "email": "alice@acme.com"})
	for name, tok := range map[string]string{"none": "", "garbage": "x.y.z", "wrong aud": other} {
		t.Run(name, func(t *testing.T) {
			resp := e.post(t, "/v1/messages", tok, msgBody, map[string]string{"x-halo-experiment": "all-in", "x-halo-variant": "treat", "x-halo-ring": "ga"})
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			_, h, body, _ := s.get()
			if h.Get("x-halo-ring") != "unknown" || h.Get("x-halo-experiment") != "" || h.Get("x-halo-variant") != "" || !strings.Contains(body, `"real-model"`) {
				t.Fatalf("anonymous caller enrolled: ring=%q exp=%q variant=%q body=%s", h.Get("x-halo-ring"), h.Get("x-halo-experiment"), h.Get("x-halo-variant"), body)
			}
		})
	}
}

// trusted_header: X-Forwarded-For / X-Real-IP never stand in for the TCP peer.
func TestTrustedHeaderIgnoresForwardedFor(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, _ *policy.Org) {
		c.Identity = IdentityConfig{Mode: "trusted_header", IdentityHeader: "x-acme-user", TrustedProxyCIDRs: []string{"10.0.0.0/8"}}
	})
	resp := e.post(t, "/v1/messages", "", msgBody, map[string]string{
		"x-acme-user": "alice", "X-Forwarded-For": "10.1.2.3", "X-Real-IP": "10.1.2.3", "Forwarded": "for=10.1.2.3"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("peer 127.0.0.1 outside CIDRs with spoofed XFF: status %d want 401", resp.StatusCode)
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatal("request reached upstream")
	}
}

// trusted_header with no CIDRs fails closed: 503, nothing forwarded.
func TestTrustedHeaderWithoutCIDRsFailsClosed(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, _ *policy.Org) {
		c.Identity = IdentityConfig{Mode: "trusted_header", IdentityHeader: "x-acme-user", AllowAnonymous: true}
	})
	if resp := e.post(t, "/v1/messages", "", msgBody, map[string]string{"x-acme-user": "alice"}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d want 503", resp.StatusCode)
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatal("request reached upstream")
	}
}

// Bedrock: client credentials and x-amz* never reach AWS, even with forwardAuth.
func TestBedrockClientCredentialsDroppedEvenWithForwardAuth(t *testing.T) {
	up, s := recordingServer(t)
	e := bedrockEnv(t, up, "AKIDTEST")
	e.p.cfg.ForwardAuth = true
	tok := e.token(t, "bob@acme.com")
	resp := e.post(t, "/model/sonnet/invoke", tok, `{"messages":[]}`, map[string]string{
		"x-api-key": "client-key", "X-Amz-Security-Token": "client-sts", "X-Amz-Date": "20000101T000000Z", "X-Amzn-Bedrock-Trace": "ENABLED"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, h, _, _ := s.get()
	if a := h.Get("Authorization"); !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
		t.Fatalf("Authorization %q: client bearer must be replaced by the gateway's SigV4", a)
	}
	for k, want := range map[string]string{"X-Api-Key": "", "X-Amz-Security-Token": "", "X-Amzn-Bedrock-Trace": ""} {
		if got := h.Get(k); got != want {
			t.Errorf("%s=%q reached Bedrock", k, got)
		}
	}
	if h.Get("X-Amz-Date") == "20000101T000000Z" {
		t.Error("client X-Amz-Date entered the signature")
	}
}

// SSRF: the upstream comes from policy/config only. An absolute-form request
// target, a Host header or a path cannot move the request to another host.
func TestClientCannotSteerUpstreamHost(t *testing.T) {
	up, s := recordingServer(t)
	var evilHits atomic.Int64
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilHits.Add(1) }))
	defer evil.Close()
	e := testEnv(t, up, nil)
	tok := e.token(t, "alice@acme.com")
	evilHost := strings.TrimPrefix(evil.URL, "http://")
	for _, target := range []string{evil.URL + "/v1/messages", "/v1/messages", "//" + evilHost + "/v1/messages"} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(e.proxy.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			target, evilHost, tok, len(msgBody), msgBody)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		_ = conn.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status %d", target, resp.StatusCode)
		}
	}
	if evilHits.Load() != 0 {
		t.Fatalf("client steered the proxy to another host (%d hits)", evilHits.Load())
	}
	if _, h, _, _ := s.get(); h == nil {
		t.Fatal("policy upstream never reached")
	}
}
