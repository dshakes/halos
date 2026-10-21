package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/telemetry/gwmetrics"
)

const (
	sseUsage = "event: message_start\n" +
		`data: {"type":"message_start","message":{"model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":25,"cache_read_input_tokens":5,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","delta":{"text":"COMPLETION-CANARY"}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":42}}` + "\n\n"
	jsonUsage = `{"id":"r1","model":"gpt-4o-2024-08-06","output":[{"content":[{"text":"hi \"usage\": {\"input_tokens\": 999}"}]}],"usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18}}`
	geminiRes = `{"candidates":[{"content":{"parts":[{"text":"x"}]}}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":4,"thoughtsTokenCount":3},"modelVersion":"gemini-2.5-pro"}`
)

type rd struct{ io.Reader }

func (rd) Close() error { return nil }

// GenAI telemetry reads usage from the one parser, gateway.UsageTap, and the
// model and TTFT from genaiTap; the numbers must not depend on chunking.
func TestGenAITap(t *testing.T) {
	for _, tc := range []struct {
		name         string
		proto        string
		body         string
		stream       bool
		in, out      int64
		model        string
		ok           bool
		wantTTFTUnit bool
	}{
		{"anthropic sse", gateway.ProtoAnthropic, sseUsage, true, 30, 42, "claude-sonnet-4-5-20250929", true, true},
		{"responses json ignores escaped usage in text", gateway.ProtoResponses, jsonUsage, false, 11, 7, "gpt-4o-2024-08-06", true, false},
		{"gemini json counts thoughts as output", gateway.ProtoGemini, geminiRes, false, 9, 7, "gemini-2.5-pro", true, false},
		{"openai responses sse", gateway.ProtoResponses, "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5\",\"usage\":{\"input_tokens\":3,\"output_tokens\":4}}}\r\n\r\n", true, 3, 4, "gpt-5", true, true},
		{"no usage", gateway.ProtoAnthropic, `{"ok":true}`, false, 0, 0, "", false, false},
		{"usage null", gateway.ProtoResponses, "data: {\"model\":\"m\",\"usage\":null}\n\n", true, 0, 0, "m", false, true},
		{"truncated usage object", gateway.ProtoAnthropic, `{"usage":{"input_tokens":5,"outp`, false, 0, 0, "", false, false},
		{"model with hostile chars is dropped", gateway.ProtoAnthropic, `{"model":"a b\u0000<script>","usage":{"input_tokens":1}}`, false, 1, 0, "", true, false},
		{"overlong sse line, next line scanned", gateway.ProtoAnthropic, "data: " + strings.Repeat("x", 2<<20) + "\ndata: {\"usage\":{\"input_tokens\":2,\"output_tokens\":3}}\n", true, 2, 3, "", true, true},
	} {
		for _, chunk := range []int{1, 7, 1 << 20} {
			ctype := "application/json"
			if tc.stream {
				ctype = "text/event-stream"
			}
			tap := newGenAITap(rd{strings.NewReader(tc.body)}, tc.stream, true, time.Now())
			body := gateway.UsageTap(tc.proto, ctype, "", tap, tap.usage)
			buf := make([]byte, chunk)
			for {
				if _, err := body.Read(buf); err != nil {
					break
				}
			}
			_ = body.Close()
			in, out, model, ok := tap.result()
			if in != tc.in || out != tc.out || model != tc.model || ok != tc.ok {
				t.Errorf("%s (chunk %d): got in=%d out=%d model=%q ok=%v", tc.name, chunk, in, out, model, ok)
			}
			if got := tap.ttft() >= 0; got != tc.wantTTFTUnit {
				t.Errorf("%s (chunk %d): ttft measured=%v, want %v", tc.name, chunk, got, tc.wantTTFTUnit)
			}
		}
	}
}

func TestGenAIMapping(t *testing.T) {
	for _, tc := range []struct{ proto, kind, op, prov string }{
		{"anthropic-messages", "", "chat", "anthropic"},
		{"openai-responses", "", "chat", "openai"},
		{"gemini", "", "generate_content", "gcp.gemini"},
		{"bedrock-invoke", "", "chat", "aws.bedrock"},
		{"anthropic-messages", "bedrock", "chat", "aws.bedrock"},
		{"anthropic-messages", "vertex", "chat", "gcp.vertex_ai"},
		{"openai-responses", "azure-openai", "chat", "azure.ai.openai"},
		{"anthropic-messages", "orchestrator", "chat", "anthropic"}, // no registered provider: protocol decides
	} {
		if op, prov := genaiOperation(tc.proto), genaiProvider(tc.proto, tc.kind); op != tc.op || prov != tc.prov {
			t.Errorf("%+v: got %s/%s", tc, op, prov)
		}
	}
}

type otlpSink struct {
	mu     sync.Mutex
	bodies map[string][]string
}

func newSink(t *testing.T) (*httptest.Server, *otlpSink) {
	s := &otlpSink{bodies: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies[r.URL.Path] = append(s.bodies[r.URL.Path], string(b))
		s.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

func (s *otlpSink) get(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.bodies[path]...)
}

type attrKV struct {
	Key   string
	Value struct{ StringValue, IntValue string }
}

func attrMap(kvs []attrKV) map[string]string {
	m := map[string]string{}
	for _, kv := range kvs {
		m[kv.Key] = kv.Value.StringValue + kv.Value.IntValue
	}
	return m
}

type otlpHist struct {
	Attributes     []attrKV
	Count          string
	Sum            float64
	ExplicitBounds []float64
}

func genaiHists(t *testing.T, body string) map[string][]otlpHist {
	t.Helper()
	var doc struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Name      string
					Histogram struct{ DataPoints []otlpHist }
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string][]otlpHist{}
	for _, m := range doc.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		out[m.Name] = m.Histogram.DataPoints
	}
	return out
}

func genaiEnv(t *testing.T, upstreamHandler http.HandlerFunc, tel gwmetrics.Config) (*env, *otlpSink) {
	t.Helper()
	col, sink := newSink(t)
	tel.OTLPEndpoint, tel.Protocol, tel.UnitSalt = col.URL, gwmetrics.ProtoJSON, "salt"
	up, _ := upstream(t, upstreamHandler)
	e := routeEnv(t, map[string]policy.Upstream{"d": anthropic(up.URL)}, []policy.RouteTarget{{Upstream: "d", Model: "m-direct"}},
		func(c *Config) { c.Telemetry = tel })
	return e, sink
}

func sse(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, body)
	}
}

// A streamed model call exports the GenAI semconv instruments with the spec
// attribute names, the cohort and measured values, and leaks no content/identity.
func TestGenAIMetricsExported(t *testing.T) {
	e, sink := genaiEnv(t, sse(sseUsage), gwmetrics.Config{})
	wait := e.awaitHandlers(t, 2)
	tok := e.token(t, "alice@acme.com")
	body := strings.Replace(opusBody, `"hi"`, `"PROMPT-CANARY"`, 1)
	for i := 0; i < 2; i++ {
		if r := e.post(t, "/v1/messages", tok, body, map[string]string{"User-Agent": "claude-cli/2.1.300 (external, cli)"}); r.StatusCode != 200 {
			t.Fatalf("status %d", r.StatusCode)
		}
	}
	wait()
	if err := e.p.otlp.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(sink.get("/v1/traces")); n != 0 {
		t.Fatalf("spans exported by default: %d", n)
	}
	ms := sink.get("/v1/metrics")
	if len(ms) != 1 {
		t.Fatalf("%d metric exports, want 1", len(ms))
	}
	h := genaiHists(t, ms[0])
	for _, name := range []string{"gen_ai.client.token.usage", "gen_ai.client.operation.duration", "gen_ai.server.time_to_first_token"} {
		if len(h[name]) == 0 {
			t.Fatalf("missing %s in %v", name, h)
		}
	}
	// Token usage: input 25+5 cached, output 42, two calls each.
	got := map[string]otlpHist{}
	for _, dp := range h["gen_ai.client.token.usage"] {
		a := attrMap(dp.Attributes)
		got[a["gen_ai.token.type"]] = dp
		for k, want := range map[string]string{"gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic",
			"gen_ai.request.model": "m-direct", "gen_ai.response.model": "claude-sonnet-4-5-20250929", "halo.ring": "ga", "halo.harness": "claude-code"} {
			if a[k] != want {
				t.Errorf("token usage attr %s = %q, want %q (%v)", k, a[k], want, a)
			}
		}
	}
	if in, out := got["input"], got["output"]; in.Count != "2" || in.Sum != 60 || out.Count != "2" || out.Sum != 84 {
		t.Errorf("token usage in=%+v out=%+v", in, out)
	}
	if b := h["gen_ai.client.token.usage"][0].ExplicitBounds; len(b) != 14 || b[0] != 1 || b[13] != 67108864 {
		t.Errorf("token bounds %v", b)
	}
	if d := h["gen_ai.client.operation.duration"][0]; d.Count != "2" || attrMap(d.Attributes)["error.type"] != "" || d.ExplicitBounds[0] != 0.01 {
		t.Errorf("duration %+v", d)
	}
	if tt := h["gen_ai.server.time_to_first_token"][0]; tt.Count != "2" || tt.Sum < 0 {
		t.Errorf("ttft %+v", tt)
	}
	for _, leak := range []string{"alice", "acme.com", "PROMPT-CANARY", "COMPLETION-CANARY", "halo.unit"} {
		if strings.Contains(strings.SplitN(ms[0], `"gen_ai.client.token.usage"`, 2)[1], leak) {
			t.Errorf("GenAI metrics leak %q", leak)
		}
	}
	if !strings.Contains(ms[0], `"halo.gateway.requests"`) || !strings.Contains(ms[0], `"halo.gateway.latency_ms"`) {
		t.Error("halo.gateway.* must still be exported alongside the GenAI metrics")
	}
}

// Failed calls carry error.type and no token usage; non-stream bodies have no TTFT;
// calls rejected before reaching an upstream are not model operations.
func TestGenAIErrorsAndNonStream(t *testing.T) {
	e, sink := genaiEnv(t, respond(529, `{"type":"error","error":{"type":"overloaded_error"}}`), gwmetrics.Config{})
	wait := e.awaitHandlers(t, 1)
	if r := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil); r.StatusCode != 529 {
		t.Fatalf("status %d", r.StatusCode)
	}
	wait()
	if err := e.p.otlp.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := genaiHists(t, sink.get("/v1/metrics")[0])
	if len(h["gen_ai.client.token.usage"]) != 0 || len(h["gen_ai.server.time_to_first_token"]) != 0 {
		t.Errorf("failed non-stream call must record neither tokens nor TTFT: %v", h)
	}
	if d := h["gen_ai.client.operation.duration"]; len(d) != 1 || attrMap(d[0].Attributes)["error.type"] != "529" {
		t.Errorf("duration %+v", d)
	}
}

func TestGenAIDisabledAndSpans(t *testing.T) {
	off := false
	t.Run("metrics off, no body tap", func(t *testing.T) {
		e, sink := genaiEnv(t, sse(sseUsage), gwmetrics.Config{GenAI: gwmetrics.GenAIConfig{Metrics: &off}})
		wait := e.awaitHandlers(t, 1)
		if r := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), opusBody, nil); r.StatusCode != 200 {
			t.Fatalf("status %d", r.StatusCode)
		}
		wait()
		if err := e.p.otlp.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b := sink.get("/v1/metrics")[0]; strings.Contains(b, "gen_ai.") || !strings.Contains(b, "halo.gateway.requests") {
			t.Errorf("gen_ai metrics must be off and halo.gateway.* on: %s", b)
		}
	})
	t.Run("spans", func(t *testing.T) {
		e, sink := genaiEnv(t, sse(sseUsage), gwmetrics.Config{GenAI: gwmetrics.GenAIConfig{Metrics: &off, Traces: true}})
		wait := e.awaitHandlers(t, 1)
		hdr := map[string]string{"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", "User-Agent": "claude-cli/2.1.300 (external, cli)"}
		body := strings.Replace(opusBody, `"hi"`, `"PROMPT-CANARY"`, 1)
		if r := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), body, hdr); r.StatusCode != 200 {
			t.Fatalf("status %d", r.StatusCode)
		}
		wait()
		if err := e.p.otlp.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		tr := sink.get("/v1/traces")
		if len(tr) != 1 {
			t.Fatalf("%d trace exports, want 1", len(tr))
		}
		var doc struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []struct {
						TraceID, SpanID, ParentSpanID, Name string
						Kind                                int
						Attributes                          []attrKV
					}
				}
			}
		}
		if err := json.Unmarshal([]byte(tr[0]), &doc); err != nil {
			t.Fatal(err)
		}
		sp := doc.ResourceSpans[0].ScopeSpans[0].Spans[0]
		a := attrMap(sp.Attributes)
		if sp.Name != "chat m-direct" || sp.Kind != 3 || sp.TraceID != "0af7651916cd43dd8448eb211c80319c" || sp.ParentSpanID != "b7ad6b7169203331" || len(sp.SpanID) != 16 {
			t.Errorf("span %+v", sp)
		}
		for k, want := range map[string]string{"gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic", "gen_ai.request.model": "m-direct",
			"gen_ai.response.model": "claude-sonnet-4-5-20250929", "gen_ai.usage.input_tokens": "30", "gen_ai.usage.output_tokens": "42",
			"halo.ring": "ga", "halo.harness": "claude-code", "http.response.status_code": "200"} {
			if a[k] != want {
				t.Errorf("span attr %s = %q, want %q", k, a[k], want)
			}
		}
		if len(a["halo.unit"]) != 16 {
			t.Errorf("halo.unit must be the salted hash, got %q", a["halo.unit"])
		}
		for _, leak := range []string{"alice", "acme.com", "PROMPT-CANARY", "COMPLETION-CANARY"} {
			if strings.Contains(tr[0], leak) {
				t.Errorf("span export leaks %q", leak)
			}
		}
		if len(sink.get("/v1/metrics")) != 1 || strings.Contains(sink.get("/v1/metrics")[0], "gen_ai.") {
			t.Error("metrics must still export, without gen_ai.*")
		}
	})
}

func TestTelemetryGenAIFlags(t *testing.T) {
	cfg, err := loadConfig([]string{"--policy", "p.json"}, func(string) string { return "" }, io.Discard)
	if err != nil || cfg.Telemetry.GenAI.Metrics != nil || cfg.Telemetry.GenAI.Traces {
		t.Fatalf("defaults: %+v %v", cfg.Telemetry.GenAI, err)
	}
	env := map[string]string{"HALO_PROXY_TELEMETRY_GENAI_METRICS": "false", "HALO_PROXY_TELEMETRY_GENAI_TRACES": "true"}
	cfg, err = loadConfig([]string{"--policy", "p.json"}, func(k string) string { return env[k] }, io.Discard)
	if err != nil || cfg.Telemetry.GenAI.Metrics == nil || *cfg.Telemetry.GenAI.Metrics || !cfg.Telemetry.GenAI.Traces {
		t.Fatalf("env: %+v %v", cfg.Telemetry.GenAI, err)
	}
	if _, err = loadConfig([]string{"--policy", "p.json", "--telemetry-genai-metrics=maybe"}, func(string) string { return "" }, io.Discard); err == nil {
		t.Fatal("want parse error for a non-boolean")
	}
}
