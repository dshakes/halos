package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// fakeGitHubToken is assembled at runtime: no literal secret in the repo.
func fakeGitHubToken() string {
	const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := []byte("gh" + "p_")
	for i := range 36 {
		b = append(b, set[(i*7+3)%len(set)])
	}
	return string(b)
}

// dlpSink is a fake halo-server DLP audit endpoint.
type dlpSink struct {
	mu     sync.Mutex
	events []gateway.DLPEvent
}

func newDLPSink(t *testing.T) (*httptest.Server, *dlpSink) {
	t.Helper()
	s := &dlpSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/gateway/dlp/events" || r.Header.Get("Authorization") != "Bearer dlp-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		var b gateway.DLPBatch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.mu.Lock()
		s.events = append(s.events, b.Events...)
		s.mu.Unlock()
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

func dlpProxy(t *testing.T, up *httptest.Server, sink *httptest.Server, d *policy.DLP) *env {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "dlp.token")
	if err := os.WriteFile(tok, []byte("dlp-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return testEnv(t, up, func(c *Config, o *policy.Org) {
		c.DLP = DLPConfig{URL: sink.URL + "/api/v1/gateway/dlp", TokenFile: tok}
		o.Gateway.DLP = d
	})
}

// The request's secret is redacted before the upstream sees it; the streamed
// response, which echoes the secret, reaches the client byte for byte; both
// findings are audited without the secret.
func TestDLPRedactsRequestAndMonitorsStream(t *testing.T) {
	secret := fakeGitHubToken()
	sse := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5}}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"your token is " + secret[:20] + "\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"" + secret[20:] + " ok\"}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n"
	var mu sync.Mutex
	var upBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		upBody = string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		for _, ev := range strings.SplitAfter(sse, "\n\n") {
			_, _ = io.WriteString(w, ev)
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(up.Close)
	sinkSrv, sink := newDLPSink(t)
	e := dlpProxy(t, up, sinkSrv, &policy.DLP{Secrets: policy.DLPSecrets{Action: policy.DLPRedact}})

	body := `{"model":"sonnet","stream":true,"messages":[{"role":"user","content":"push with ` + secret + `"}]}`
	wait := e.awaitHandlers(t, 1)
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), body, nil)
	got, _ := io.ReadAll(resp.Body)
	wait()
	if resp.StatusCode != 200 || string(got) != sse {
		t.Fatalf("stream changed: %d\n%q\nwant\n%q", resp.StatusCode, got, sse)
	}
	mu.Lock()
	fwd := upBody
	mu.Unlock()
	marker := gateway.RedactionMarker("github-token", gateway.SecretHash(secret))
	if strings.Contains(fwd, secret) || !strings.Contains(fwd, marker) || !json.Valid([]byte(fwd)) {
		t.Fatalf("upstream saw %s", fwd)
	}
	if err := e.p.dlpAudit.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	evs := sink.events
	sink.mu.Unlock()
	if len(evs) != 2 {
		t.Fatalf("audit events %+v", evs)
	}
	req, res := evs[0], evs[1]
	if req.Direction != gateway.DLPRequest || req.Action != policy.DLPRedact || req.Detector != "github-token" || req.Subject != "alice@acme.com" || req.Ring != "ga" ||
		req.Location != "messages[0].content" || req.Hash != gateway.SecretHash(secret) {
		t.Fatalf("request event %+v", req)
	}
	if res.Direction != gateway.DLPResponse || res.Action != policy.DLPMonitor || res.Hash != req.Hash {
		t.Fatalf("response event %+v", res)
	}
	raw, _ := json.Marshal(evs)
	if strings.Contains(string(raw), secret) {
		t.Fatal("audit event carries the secret")
	}
	m := metricsText(t, e)
	for _, want := range []string{
		`halo_proxy_dlp_findings_total{kind="secret",detector="github-token",action="redact",direction="request"} 1`,
		`halo_proxy_dlp_findings_total{kind="secret",detector="github-token",action="monitor",direction="response"} 1`,
		`halo_proxy_dlp_scans_total{direction="request",outcome="redacted"} 1`,
		`halo_proxy_dlp_audit_events_total{outcome="sent"} 2`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	if strings.Contains(m, secret) {
		t.Fatal("metrics carry the secret")
	}
}

func TestDLPBlockNeverReachesUpstream(t *testing.T) {
	up, s := recordingServer(t)
	sinkSrv, sink := newDLPSink(t)
	e := dlpProxy(t, up, sinkSrv, &policy.DLP{Secrets: policy.DLPSecrets{Action: policy.DLPMonitor},
		Rules: []policy.DLPRule{{Rings: []string{"ga"}, Secrets: policy.DLPBlock}}})
	secret := fakeGitHubToken()
	resp := e.post(t, "/v1/messages", e.token(t, "bob@acme.com"), `{"model":"sonnet","messages":[{"role":"user","content":"`+secret+`"}]}`, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), `"invalid_request_error"`) || !strings.Contains(string(b), "github-token") || strings.Contains(string(b), secret) {
		t.Fatalf("block: %d %s", resp.StatusCode, b)
	}
	if s.hitCount() != 0 {
		t.Fatal("blocked request reached the upstream")
	}
	if err := e.p.dlpAudit.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 || sink.events[0].Action != policy.DLPBlock {
		t.Fatalf("events %+v", sink.events)
	}
}

func TestDLPConfigBuild(t *testing.T) {
	if r, err := (DLPConfig{}).build(nil); r != nil || err != nil {
		t.Fatalf("empty: %v %v", r, err)
	}
	for name, c := range map[string]DLPConfig{
		"token without url": {TokenFile: "x"},
		"url without token": {URL: "https://h/api/v1/gateway/dlp"},
		"missing file":      {URL: "https://h/api/v1/gateway/dlp", TokenFile: filepath.Join(t.TempDir(), "nope")},
	} {
		if _, err := c.build(nil); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
