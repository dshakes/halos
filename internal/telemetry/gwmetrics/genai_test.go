package gwmetrics

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

	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

func genaiReq(status int, in, out int64, ttft time.Duration) Request {
	return Request{Ring: "ga", Release: "r1", Experiment: "e", Variant: "t", Harness: "claude-code", Model: "m", Subject: "alice@example.com",
		Status: status, Latency: 2 * time.Second, Start: time.Unix(1_700_000_000, 0),
		GenAI: &GenAI{Operation: "chat", Provider: "anthropic", ResponseModel: "m-2025", InputTokens: in, OutputTokens: out, TTFT: ttft}}
}

func TestGenAIProtobuf(t *testing.T) {
	srv, _, bodies := collector(t, 200)
	e, _ := New(Config{OTLPEndpoint: srv.URL, UnitSalt: "x-salt-0123456789"})
	e.Record(genaiReq(200, 100, 5, 300*time.Millisecond))
	e.Record(genaiReq(200, 100, 5, 300*time.Millisecond))
	e.Record(genaiReq(503, -1, -1, -1))
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var msg metricspb.MetricsData
	if err := proto.Unmarshal((*bodies)[0], &msg); err != nil {
		t.Fatal(err)
	}
	byName := map[string]*metricspb.Histogram{}
	for _, m := range msg.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		if h := m.GetHistogram(); h != nil {
			if h.AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA {
				t.Errorf("%s not delta", m.Name)
			}
			byName[m.Name] = h
		}
	}
	tok, dur, ttft := byName["gen_ai.client.token.usage"], byName["gen_ai.client.operation.duration"], byName["gen_ai.server.time_to_first_token"]
	if tok == nil || dur == nil || ttft == nil {
		t.Fatalf("instruments %v", byName)
	}
	if len(tok.DataPoints) != 2 { // input and output; the failed call recorded none
		t.Fatalf("token series %d", len(tok.DataPoints))
	}
	for _, dp := range tok.DataPoints {
		if dp.GetCount() != 2 || len(dp.BucketCounts) != len(dp.ExplicitBounds)+1 || len(dp.ExplicitBounds) != 14 {
			t.Errorf("token dp %v", dp)
		}
	}
	if len(dur.DataPoints) != 2 { // success series and the 503 series (error.type)
		t.Fatalf("duration series %d", len(dur.DataPoints))
	}
	if len(ttft.DataPoints) != 1 || ttft.DataPoints[0].GetCount() != 2 || ttft.DataPoints[0].GetSum() != 0.6 {
		t.Errorf("ttft %v", ttft.DataPoints)
	}
	keys := map[string]string{}
	for _, dp := range dur.DataPoints {
		for _, kv := range dp.Attributes {
			keys[kv.Key] += kv.Value.GetStringValue() + ","
		}
	}
	if !strings.Contains(keys["error.type"], "503") || keys["halo.unit"] != "" {
		t.Errorf("attrs %v", keys)
	}
}

func TestGenAIToggles(t *testing.T) {
	off := false
	for _, tc := range []struct {
		name            string
		c               GenAIConfig
		metrics, traces bool
	}{
		{"default", GenAIConfig{}, true, false},
		{"metrics off", GenAIConfig{Metrics: &off}, false, false},
		{"traces only", GenAIConfig{Metrics: &off, Traces: true}, false, true},
		{"both", GenAIConfig{Traces: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := New(Config{OTLPEndpoint: "http://c", GenAI: tc.c})
			e.Record(genaiReq(200, 1, 1, 0))
			if got := len(e.gen.duration) > 0; got != tc.metrics {
				t.Errorf("metrics recorded = %v", got)
			}
			if got := len(e.spans) > 0; got != tc.traces {
				t.Errorf("spans recorded = %v", got)
			}
			if e.GenAIEnabled() != (tc.metrics || tc.traces) {
				t.Errorf("GenAIEnabled = %v", e.GenAIEnabled())
			}
			if len(e.series) != 1 {
				t.Error("halo.gateway.* series must be recorded regardless")
			}
		})
	}
	var nilE *Emitter
	if nilE.GenAIEnabled() {
		t.Error("nil emitter must report disabled")
	}
	e, _ := New(Config{OTLPEndpoint: "http://c"})
	r := genaiReq(200, 1, 1, 0)
	r.GenAI = nil
	e.Record(r) // no GenAI detail: nothing semconv recorded
	if len(e.gen.duration) != 0 {
		t.Error("recorded GenAI without details")
	}
}

func TestGenAIBounds(t *testing.T) {
	e, _ := New(Config{OTLPEndpoint: "http://c", GenAI: GenAIConfig{Traces: true}})
	for i := 0; i < maxGenAISeries+50; i++ {
		r := genaiReq(200, 1, 1, 0)
		r.Model = "m" + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
		e.Record(r)
	}
	if n := len(e.gen.duration); n != maxGenAISeries {
		t.Errorf("duration series %d, want cap %d", n, maxGenAISeries)
	}
	for i := 0; i < maxSpans+10; i++ {
		e.Record(genaiReq(200, 1, 1, 0))
	}
	if len(e.spans) != maxSpans {
		t.Errorf("spans %d, want cap %d", len(e.spans), maxSpans)
	}
}

func TestParseTraceparent(t *testing.T) {
	const tid, pid = "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"00-" + tid + "-" + pid + "-01", true},
		{"00-" + tid + "-" + pid + "-00", true},
		{"", false},
		{"01-" + tid + "-" + pid + "-01", false},
		{"00-" + strings.ToUpper(tid) + "-" + pid + "-01", false},
		{"00-" + strings.Repeat("0", 32) + "-" + pid + "-01", false},
		{"00-" + tid + "-" + strings.Repeat("0", 16) + "-01", false},
		{"00-" + tid + "-" + pid + "-0g", false},
		{"00-" + tid + "_" + pid + "-01", false},
		{"00-" + tid + "-" + pid + "-01-extra", false},
	} {
		tr, p, ok := parseTraceparent(tc.in)
		if ok != tc.ok || (ok && (tr != tid || p != pid)) {
			t.Errorf("%q: %q %q %v", tc.in, tr, p, ok)
		}
	}
}

func TestSpanExportAndErrors(t *testing.T) {
	var mu sync.Mutex
	var body []byte
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/v1/traces" {
			body = b
			w.WriteHeader(status)
		}
	}))
	t.Cleanup(srv.Close)
	e, _ := New(Config{OTLPEndpoint: srv.URL, Protocol: ProtoJSON, UnitSalt: "x-salt-0123456789", GenAI: GenAIConfig{Traces: true}})
	e.Record(genaiReq(200, 10, 20, 0))
	e.Record(genaiReq(500, -1, -1, -1))
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					TraceID, SpanID, ParentSpanID, Name string
					StartTimeUnixNano, EndTimeUnixNano  string
					Status                              struct{ Code int }
				}
			}
		}
	}
	mu.Lock()
	err := json.Unmarshal(body, &doc)
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	sp := doc.ResourceSpans[0].ScopeSpans[0].Spans
	if len(sp) != 2 || sp[0].Name != "chat m" || len(sp[0].TraceID) != 32 || sp[0].TraceID == sp[1].TraceID || sp[0].ParentSpanID != "" {
		t.Fatalf("spans %+v", sp)
	}
	if sp[0].StartTimeUnixNano != "1700000000000000000" || sp[0].EndTimeUnixNano != "1700000002000000000" {
		t.Errorf("span times %s %s", sp[0].StartTimeUnixNano, sp[0].EndTimeUnixNano)
	}
	if sp[0].Status.Code != 0 || sp[1].Status.Code != 2 {
		t.Errorf("status codes %d %d", sp[0].Status.Code, sp[1].Status.Code)
	}
	// A failing traces export is reported.
	mu.Lock()
	status = 503
	mu.Unlock()
	e.Record(genaiReq(200, 1, 1, 0))
	if err := e.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "spans") || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("want span export error, got %v", err)
	}
}

// DLP counts ride on the span only, for the session ledger (ADR-0033).
func TestSpanCarriesDLPCounts(t *testing.T) {
	e, _ := New(Config{OTLPEndpoint: "http://127.0.0.1:1", UnitSalt: "x-salt-0123456789"})
	r := genaiReq(200, 1, 1, time.Millisecond)
	r.DLPSecrets, r.DLPInjections = 2, 1
	got := map[string]int64{}
	for _, a := range e.newSpan(r, "").attrs {
		if strings.HasPrefix(a.k, "halo.dlp.") {
			got[a.k] = a.i
		}
	}
	if got["halo.dlp.secrets"] != 2 || got["halo.dlp.injections"] != 1 {
		t.Fatalf("span attrs %v", got)
	}
	for _, a := range e.newSpan(genaiReq(200, 1, 1, time.Millisecond), "").attrs {
		if strings.HasPrefix(a.k, "halo.dlp.") {
			t.Fatalf("clean call carries %s", a.k)
		}
	}
}
