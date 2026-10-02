package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/gateway/upstreamauth"
	"github.com/dshakes/halos/internal/policy"
)

const benchBody = `{"model":"sonnet","messages":[{"role":"user","content":"hi"}],"max_tokens":8,"stream":false}`

// benchUpstream serves plain JSON, or SSE (20 events) when the body asks for it.
func benchUpstream(tb testing.TB) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			f := w.(http.Flusher)
			for i := 0; i < 20; i++ {
				fmt.Fprintf(w, "event: content_block_delta\ndata: {\"delta\":{\"text\":\"tok%d\"}}\n\n", i)
				f.Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_1","content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":3,"output_tokens":5}}`)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

func benchEnv(b *testing.B) (*env, string) {
	e := testEnv(b, benchUpstream(b), nil)
	return e, e.token(b, "alice@acme.com", "ai-platform")
}

func BenchmarkJWTVerify(b *testing.B) {
	e, tok := benchEnv(b)
	org, _ := e.p.snap.Get()
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if rec := httptest.NewRecorder(); func() bool { _, ok := e.p.authenticate(rec, r, org); return !ok }() {
			b.Fatal("verify failed", rec.Body.String())
		}
	}
}

func BenchmarkRingVariantDecide(b *testing.B) {
	e, _ := benchEnv(b)
	org, _ := e.p.snap.Get()
	sub := &policy.Subject{ID: "alice@acme.com", Groups: []string{"ai-platform"}}
	h := http.Header{"Content-Type": {"application/json"}}
	body := []byte(benchBody)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res := gateway.PrepareVerified(org, sub, h, "/v1/messages", body); res.Reject != nil {
			b.Fatal("rejected")
		}
	}
}

// BenchmarkHeaderHygiene is the header work ServeHTTP does on every forwarded call.
func BenchmarkHeaderHygiene(b *testing.B) {
	e, _ := benchEnv(b)
	org, _ := e.p.snap.Get()
	names := append([]string{"x-halo-ring", "x-halo-variant", "x-halo-user"}, e.p.cfg.identityOptions().HeaderNames(org)...)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := http.Header{"Authorization": {"Bearer x"}, "X-Api-Key": {"k"}, "X-Halo-Ring": {"ring0"},
			"X-Halo-Variant": {"a"}, "User-Agent": {"claude-cli/1.0"}, "Content-Type": {"application/json"}}
		for _, n := range names {
			h.Del(n)
		}
		upstreamauth.StripClientCredentials(h)
		h.Set("x-api-key", "provider-key")
	}
}

// BenchmarkForward drives the full handler (auth, decide, rewrite, reverse proxy) against a local upstream.
func BenchmarkForward(b *testing.B) {
	for _, stream := range []bool{false, true} {
		name := map[bool]string{false: "json", true: "sse"}[stream]
		body := strings.Replace(benchBody, `"stream":false`, fmt.Sprintf(`"stream":%v`, stream), 1)
		b.Run(name+"/direct", func(b *testing.B) {
			up := benchUpstream(b)
			benchLoop(b, up.URL+"/v1/messages", "", body)
		})
		b.Run(name+"/proxy", func(b *testing.B) {
			e, tok := benchEnv(b)
			benchLoop(b, e.proxy.URL+"/v1/messages", tok, body)
		})
	}
}

func benchLoop(b *testing.B, url, tok, body string) {
	cl := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}} // default of 2 idle conns exhausts ephemeral ports
	defer cl.CloseIdleConnections()
	b.ReportAllocs()
	b.SetParallelism(4)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("POST", url, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			resp, err := cl.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// Pooled copy buffers are shared across responses: concurrent bodies larger than one buffer must arrive intact.
func TestPooledCopyBuffersKeepBodiesIntact(t *testing.T) {
	want := strings.Repeat("0123456789abcdef", 16<<10) // 256 KiB > 32 KiB buffer
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, want) }))
	t.Cleanup(up.Close)
	e := testEnv(t, up, nil)
	tok := e.token(t, "alice@acme.com")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := e.post(t, "/v1/messages", tok, benchBody, nil)
			defer resp.Body.Close()
			if b, _ := io.ReadAll(resp.Body); string(b) != want {
				t.Errorf("body corrupted: got %d bytes, want %d", len(b), len(want))
			}
		}()
	}
	wg.Wait()
}
