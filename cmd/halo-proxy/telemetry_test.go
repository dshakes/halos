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

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/telemetry/gwmetrics"
)

// Model calls are exported as halo.gateway.* with the decided cohort; token
// counting and non-model paths are not; identities never leave the proxy.
func TestRequestMetricsExported(t *testing.T) {
	var mu sync.Mutex
	var bodies, auths []string
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies, auths = append(bodies, string(b)), append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer col.Close()

	tokFile := filepath.Join(t.TempDir(), "otlp-token")
	if err := os.WriteFile(tokFile, []byte("gw-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up, _ := recordingServer(t)
	e := testEnv(t, up, func(c *Config, _ *policy.Org) {
		c.Telemetry = gwmetrics.Config{OTLPEndpoint: col.URL, Protocol: gwmetrics.ProtoJSON, UnitSalt: "t", TokenFile: tokFile}
	})
	wait := e.awaitHandlers(t, 3) // flush only after all three handlers recorded
	tok := e.token(t, "alice@acme.com", "ai-platform")
	hdr := map[string]string{"x-claude-code-session-id": "sess-secret", "User-Agent": "claude-cli/2.1.300 (external, cli)"}
	body := strings.Replace(msgBody, `"hi"`, `"prompt-canary"`, 1)
	// The same verified user rotating session ids stays one unit (one series).
	for _, sess := range []string{"sess-secret", "sess-rotated"} {
		hdr["x-claude-code-session-id"] = sess
		if r := e.post(t, "/v1/messages", tok, body, hdr); r.StatusCode != 200 {
			t.Fatalf("status %d", r.StatusCode)
		}
	}
	e.post(t, "/v1/messages/count_tokens", tok, body, hdr)
	wait()
	if err := e.p.otlp.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || auths[0] != "Bearer gw-token" {
		t.Fatalf("%d exports (auth %q), want 1 with the gateway token", len(bodies), auths)
	}
	b := bodies[0]
	for _, want := range []string{`"halo.gateway.requests"`, `"halo.gateway.latency_ms"`, `"ring0"`, `"real-model"`, `"2xx"`, `"halo.unit"`, `"claude-code"`} {
		if !strings.Contains(b, want) {
			t.Errorf("export lacks %s: %s", want, b)
		}
	}
	for _, leak := range []string{"alice", "sess-secret", "sess-rotated", "prompt-canary"} {
		if strings.Contains(b, leak) {
			t.Errorf("export leaks %q", leak)
		}
	}
	if n := strings.Count(b, `"asInt"`); n != 1 || !strings.Contains(b, `"asInt":"2"`) {
		t.Errorf("want the two model calls in one per-user series (count_tokens excluded), got %d series: %s", n, b)
	}
}

func TestTelemetryConfigValidated(t *testing.T) {
	_, err := loadConfig([]string{"--policy", "p.json", "--telemetry-otlp-endpoint", "collector:4318"}, func(string) string { return "" }, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "otlpEndpoint") {
		t.Fatalf("want otlpEndpoint error, got %v", err)
	}
	env := map[string]string{"HALO_PROXY_TELEMETRY_TOKEN_FILE": "/run/otlp-token"}
	cfg, err := loadConfig([]string{"--policy", "p.json"}, func(k string) string { return env[k] }, io.Discard)
	if err != nil || cfg.Telemetry.TokenFile != "/run/otlp-token" {
		t.Fatalf("telemetry token file from env: %q %v", cfg.Telemetry.TokenFile, err)
	}
}

// A routed call exports the route it took: provider kind, the upstream/model that
// answered (policy-bounded, never per-user) and whether an earlier target failed.
func TestRouteAttributesExported(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer col.Close()

	pSrv, _ := upstream(t, respond(503, `{"error":"overloaded"}`))
	sSrv, _ := upstream(t, respond(200, `{"ok":true}`))
	ups, targets := primarySecondary(pSrv, sSrv)
	e := routeEnv(t, ups, targets, func(c *Config) {
		c.Telemetry = gwmetrics.Config{OTLPEndpoint: col.URL, Protocol: gwmetrics.ProtoJSON, UnitSalt: "t"}
	})
	org, _ := e.p.snap.Get()
	org.Gateway.Upstreams["direct"] = policy.Upstream{URL: sSrv.URL, Kind: "anthropic"}
	org.Gateway.Models["plain"] = policy.ModelRoute{Upstream: "direct", Model: "m-plain"}
	e.writePolicy(t, org)
	waitPolicy(t, e, "plain")

	wait := e.awaitHandlers(t, 2)
	tok := e.token(t, "alice@acme.com")
	if r := e.post(t, "/v1/messages", tok, opusBody, nil); r.StatusCode != 200 { // primary 503 -> secondary
		t.Fatalf("failover request: status %d", r.StatusCode)
	}
	if r := e.post(t, "/v1/messages", tok, strings.Replace(opusBody, `"opus"`, `"plain"`, 1), nil); r.StatusCode != 200 {
		t.Fatalf("plain request: status %d", r.StatusCode)
	}
	wait()
	if err := e.p.otlp.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("%d exports, want 1", len(bodies))
	}
	var doc struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Sum struct {
						DataPoints []struct {
							Attributes []struct {
								Key   string
								Value struct{ StringValue string }
							}
						}
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(bodies[0]), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, dp := range doc.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Sum.DataPoints {
		a := map[string]string{}
		for _, kv := range dp.Attributes {
			a[kv.Key] = kv.Value.StringValue
		}
		got[a["halo.gateway.provider"]+"|"+a["halo.gateway.target"]+"|"+a["halo.gateway.failover"]+"|"+a["model"]] = true
	}
	for _, want := range []string{
		"anthropic|s/m-secondary|true|m-secondary", // served by the secondary after the primary's 503
		"anthropic|direct/m-plain|false|m-plain",   // answered by its only target
	} {
		if !got[want] {
			t.Errorf("missing series %q in %v", want, got)
		}
	}
	for _, leak := range []string{"alice", "acme.com"} {
		if strings.Contains(bodies[0], leak) {
			t.Errorf("export leaks %q", leak)
		}
	}
}
