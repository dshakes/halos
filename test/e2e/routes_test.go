//go:build e2e

package e2e

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
)

// fakeUpstream is a model upstream whose behaviour the test flips at runtime.
type fakeUpstream struct {
	*httptest.Server
	name string
	mode atomic.Value // "ok" | "503" | "midstream"
	hits atomic.Int32
}

func newFake(t *testing.T, name string) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{name: name}
	f.mode.Store("ok")
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Mock-Served-By", name)
		for k, v := range r.Header {
			if l := strings.ToLower(k); strings.HasPrefix(l, "x-halo-") {
				w.Header().Set("X-Seen-"+l, strings.Join(v, ","))
			}
		}
		switch f.mode.Load() {
		case "503":
			http.Error(w, `{"error":"overloaded"}`, http.StatusServiceUnavailable)
		case "midstream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: message_start\ndata: {}\n\n")
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
			panic(http.ErrAbortHandler) // die after the first byte
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// TestRoutes: a real halo-proxy in front of fake upstreams, driven by a Gateway
// policy with weighted and priority routes.
func TestRoutes(t *testing.T) {
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()

	fk := map[string]*fakeUpstream{}
	for _, n := range []string{"sa", "sb", "fp", "fs", "mp", "ms", "bp", "bs"} {
		fk[n] = newFake(t, n)
	}

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	org := gatewayPolicy(t, pol, iss.URL, "http://unused.invalid", "http://unused.invalid")
	_ = org
	if err := os.Remove(filepath.Join(pol, "experiments/shadow.yaml")); err != nil {
		t.Fatal(err)
	}
	var ups, models strings.Builder
	for n, f := range fk {
		fmt.Fprintf(&ups, "  %s: {url: %q, kind: anthropic}\n", n, f.URL)
	}
	pair := func(alias, a, b string, weighted bool) {
		if weighted {
			fmt.Fprintf(&models, "  %s:\n    targets:\n      - {upstream: %s, model: m-%s, weight: 50}\n      - {upstream: %s, model: m-%s, weight: 50}\n", alias, a, a, b, b)
			return
		}
		fmt.Fprintf(&models, "  %s:\n    targets:\n      - {upstream: %s, model: m-%s}\n      - {upstream: %s, model: m-%s, priority: 1}\n", alias, a, a, b, b)
	}
	fmt.Fprintf(&models, "  sonnet: {upstream: sa, model: claude-sonnet-4-5}\n") // the e2e profile's default alias
	pair("split", "sa", "sb", true)
	pair("failover", "fp", "fs", false)
	pair("midstream", "mp", "ms", false)
	pair("breaker", "bp", "bs", false)
	writeFile(t, filepath.Join(pol, "gateway.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Gateway
name: acme-gateway
baseURL: https://ai.acme.example
protocols:
  claude-code: anthropic-messages
auth:
  helperCommand: /usr/local/bin/acme-token
  ttlSeconds: 3300
upstreams:
`+ups.String()+`models:
`+models.String())
	if r := run(t, nil, "", "halo", "validate", pol); r.code != 0 {
		t.Fatalf("routes policy invalid: %s", r)
	}
	snap := filepath.Join(dir, "policy.json")
	must(t, nil, "halo", "gateway", "compile", pol, "-o", snap)
	org, err = policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr, adminAddr := freeAddr(t), freeAddr(t)
	cfg := filepath.Join(dir, "proxy.yaml")
	writeFile(t, cfg, "route:\n  maxAttempts: 3\n  breakerFailures: 2\n  breakerCooldown: 1s\n")
	start(t, nil, "halo-proxy", "--config", cfg, "--listen", proxyAddr, "--admin-listen", adminAddr, "--policy", snap)
	waitUp(t, "http://"+adminAddr+"/healthz", 200)

	user := usersByRing(t, org)["ring1-ga"]
	tok := mint(t, iss, user)
	send := func(alias, session string, stream bool, hdr map[string]string) (*http.Response, string, error) {
		t.Helper()
		body := fmt.Sprintf(`{"model":%q,"max_tokens":5,"stream":%v,"messages":[{"role":"user","content":"hi"}]}`, alias, stream)
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/v1/messages", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("x-claude-code-session-id", session)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp, string(b), err
	}
	servedBy := func(alias, session string) string {
		t.Helper()
		resp, body, err := send(alias, session, false, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s/%s: status %d err %v: %s", alias, session, resp.StatusCode, err, body)
		}
		return resp.Header.Get("X-Mock-Served-By")
	}

	t.Run("weighted split is sticky per user and session", func(t *testing.T) {
		route := org.Gateway.Models["split"]
		seen := map[string]int{}
		for i := 0; i < 60; i++ {
			sess := fmt.Sprint("sess-", i)
			want := gateway.RouteOrder("split", route, gateway.StickyKey(user, sess))[0].Upstream
			for range 2 {
				if got := servedBy("split", sess); got != want {
					t.Fatalf("session %s served by %s, want %s", sess, got, want)
				}
			}
			seen[want]++
		}
		if seen["sa"] == 0 || seen["sb"] == 0 {
			t.Fatalf("split never used both targets: %v", seen)
		}
	})

	t.Run("failover on 503 before the first byte", func(t *testing.T) {
		fk["fp"].mode.Store("503")
		if got := servedBy("failover", "s"); got != "fs" {
			t.Fatalf("served by %s, want fs", got)
		}
		if fk["fp"].hits.Load() != 1 {
			t.Fatalf("primary hits %d, want 1", fk["fp"].hits.Load())
		}
	})

	t.Run("no retry after a mid-stream failure", func(t *testing.T) {
		fk["mp"].mode.Store("midstream")
		resp, body, err := send("midstream", "s", true, nil)
		if !strings.Contains(body, "message_start") || err == nil {
			t.Fatalf("want a truncated stream: status %d body %q err %v", resp.StatusCode, body, err)
		}
		if fk["mp"].hits.Load() != 1 || fk["ms"].hits.Load() != 0 {
			t.Fatalf("retried after streaming began: primary %d secondary %d", fk["mp"].hits.Load(), fk["ms"].hits.Load())
		}
	})

	t.Run("circuit breaker opens, then recovers half-open", func(t *testing.T) {
		fk["bp"].mode.Store("503")
		for range 2 {
			if got := servedBy("breaker", "s"); got != "bs" {
				t.Fatalf("served by %s, want bs", got)
			}
		}
		if h := fk["bp"].hits.Load(); h != 2 {
			t.Fatalf("primary hits %d, want 2", h)
		}
		if got := servedBy("breaker", "s"); got != "bs" || fk["bp"].hits.Load() != 2 {
			t.Fatalf("open breaker still sent traffic to the primary (hits %d)", fk["bp"].hits.Load())
		}
		fk["bp"].mode.Store("ok")
		time.Sleep(1200 * time.Millisecond) // cooldown elapsed: one probe goes through
		if got := servedBy("breaker", "s"); got != "bp" {
			t.Fatalf("half-open probe served by %s, want bp", got)
		}
		if got := servedBy("breaker", "s"); got != "bp" {
			t.Fatalf("breaker did not close after a good probe: served by %s", got)
		}
	})

	t.Run("spoofed x-halo headers are stripped", func(t *testing.T) {
		resp, _, err := send("failover", "spoof", false, map[string]string{"x-halo-ring": "ring0-canary", "x-halo-variant": "evil", "x-halo-provider": "evil"})
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("status %d err %v", resp.StatusCode, err)
		}
		if got := resp.Header.Get("X-Seen-X-Halo-Ring"); got != "ring1-ga" {
			t.Fatalf("upstream saw x-halo-ring %q, want ring1-ga", got)
		}
		if resp.Header.Get("X-Seen-X-Halo-Variant") != "" || resp.Header.Get("X-Seen-X-Halo-Provider") != "" {
			t.Fatalf("spoofed headers reached the upstream: %v", resp.Header)
		}
	})
}

// TestGeminiWire: gemini-cli's wire (x-goog-api-key = the developer's JWT,
// :streamGenerateContent?alt=sse) through a real halo-proxy.
func TestGeminiWire(t *testing.T) {
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()

	var gotPath, gotQuery, gotKey, gotAuth atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		gotQuery.Store(r.URL.RawQuery)
		gotKey.Store(r.Header.Get("x-goog-api-key"))
		gotAuth.Store(r.Header.Get("Authorization"))
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "data: {\"candidates\":[{\"index\":%d}]}\n\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond)
		}
	}))
	defer up.Close()

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	gatewayPolicy(t, pol, iss.URL, "http://unused.invalid", "http://unused.invalid")
	if err := os.Remove(filepath.Join(pol, "experiments/shadow.yaml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(pol, "gateway.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Gateway
name: acme-gateway
baseURL: https://ai.acme.example
protocols:
  claude-code: anthropic-messages
  gemini-cli: gemini
auth:
  helperCommand: /usr/local/bin/acme-token
  ttlSeconds: 3300
upstreams:
  anthropic: {url: "`+up.URL+`", kind: anthropic}
  gemini: {url: "`+up.URL+`", kind: gemini}
models:
  sonnet: {upstream: anthropic, model: claude-sonnet-4-5}
  gemini-default: {upstream: gemini, model: gemini-2.5-pro}
`)
	if r := run(t, nil, "", "halo", "validate", pol); r.code != 0 {
		t.Fatalf("gemini policy invalid: %s", r)
	}
	snap := filepath.Join(dir, "policy.json")
	must(t, nil, "halo", "gateway", "compile", pol, "-o", snap)
	proxyAddr, adminAddr := freeAddr(t), freeAddr(t)
	start(t, nil, "halo-proxy", "--listen", proxyAddr, "--admin-listen", adminAddr, "--policy", snap)
	waitUp(t, "http://"+adminAddr+"/healthz", 200)

	tok := mint(t, iss, "dev@acme.com")
	call := func(path, key string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+path, strings.NewReader(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("x-goog-api-key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	t.Run("streams through, alias rewritten, key stripped", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/v1beta/models/gemini-default:streamGenerateContent?alt=sse&key=leak", strings.NewReader(`{"contents":[]}`))
		req.Header.Set("x-goog-api-key", tok)
		t0 := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var first time.Duration
		n := 0
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data: ") {
				if n == 0 {
					first = time.Since(t0)
				}
				n++
			}
		}
		if resp.StatusCode != 200 || n != 3 || time.Since(t0)-first < 80*time.Millisecond {
			t.Fatalf("status %d events %d first %s total %s", resp.StatusCode, n, first, time.Since(t0))
		}
		if gotPath.Load() != "/v1beta/models/gemini-2.5-pro:streamGenerateContent" {
			t.Errorf("upstream path %v", gotPath.Load())
		}
		if q := gotQuery.Load().(string); !strings.Contains(q, "alt=sse") || strings.Contains(q, "key=") {
			t.Errorf("upstream query %q", q)
		}
		if gotKey.Load() != "" || gotAuth.Load() != "" {
			t.Errorf("client credential reached the upstream: key=%v auth=%v", gotKey.Load(), gotAuth.Load())
		}
	})
	t.Run("unknown model 400 (permanent, not retried)", func(t *testing.T) {
		resp, body := call("/v1beta/models/gemini-ultra:generateContent", tok)
		if resp.StatusCode != 400 || !strings.Contains(body, "INVALID_ARGUMENT") || !strings.Contains(body, "gemini-ultra") {
			t.Fatalf("status %d: %s", resp.StatusCode, body)
		}
	})
	t.Run("bad key 401, key refused on other wires", func(t *testing.T) {
		if resp, _ := call("/v1beta/models/gemini-default:generateContent", "garbage"); resp.StatusCode != 401 {
			t.Fatalf("garbage key: status %d", resp.StatusCode)
		}
		if resp, _ := call("/v1/messages", tok); resp.StatusCode != 401 {
			t.Fatalf("x-goog-api-key accepted on the anthropic wire: status %d", resp.StatusCode)
		}
	})
}
