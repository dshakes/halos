package gwmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Config
		err  string
	}{
		{"disabled", Config{}, ""},
		{"ok json", Config{OTLPEndpoint: "http://c:4318", Protocol: ProtoJSON, Interval: time.Second}, ""},
		{"ok default proto", Config{OTLPEndpoint: "https://c:4318"}, ""},
		{"bad url", Config{OTLPEndpoint: "c:4318"}, "not an http(s) URL"},
		{"bad protocol", Config{OTLPEndpoint: "http://c:4318", Protocol: "grpc"}, "telemetry.protocol"},
		{"interval too short", Config{OTLPEndpoint: "http://c:4318", Interval: time.Millisecond}, "telemetry.interval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("Validate() = %v, want %q", err, tc.err)
			}
			if _, nerr := New(tc.c); (nerr == nil) != (err == nil) {
				t.Fatalf("New disagrees with Validate: %v vs %v", nerr, err)
			}
		})
	}
	if e, err := New(Config{}); e != nil || err != nil {
		t.Fatalf("empty endpoint must disable: %v %v", e, err)
	}
}

func TestNilEmitterIsNoop(t *testing.T) {
	var e *Emitter
	e.Record(Request{Status: 200})
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.Run(context.Background(), nil) // returns immediately
}

func TestUnitHashing(t *testing.T) {
	e, _ := New(Config{OTLPEndpoint: "http://c", UnitSalt: "s1"})
	e2, _ := New(Config{OTLPEndpoint: "http://c", UnitSalt: "s2"})
	if u := e.Unit(""); u != "" {
		t.Fatalf("anonymous request must not be an experiment unit, got %q", u)
	}
	u := e.Unit("alice")
	if len(u) != 16 || strings.Contains(u, "alice") {
		t.Errorf("unit %q leaks or has wrong shape", u)
	}
	if u != e.Unit("alice") || u == e2.Unit("alice") || u == e.Unit("bob") {
		t.Error("unit must be stable per salt and subject, and differ across salts and subjects")
	}
}

// One verified user rotating client-controlled session ids stays one unit:
// sessions must not multiply a user's weight in per-unit statistics.
func TestUnitIgnoresSessions(t *testing.T) {
	e, _ := New(Config{OTLPEndpoint: "http://c", UnitSalt: "s"})
	for i := 0; i < 100; i++ {
		e.Record(Request{Experiment: "x", Variant: "treatment", Subject: "alice", Status: 200})
		e.Record(Request{Experiment: "x", Variant: "treatment", Status: 200}) // anonymous
	}
	units := map[string]uint64{}
	for k, a := range e.series {
		units[k.unit] += a.n
	}
	if len(units) != 2 || units[e.Unit("alice")] != 100 || units[""] != 100 {
		t.Fatalf("units %v: want one subject unit and one unit-less series", units)
	}
}

func collector(t *testing.T, status int) (*httptest.Server, *[]*http.Request, *[][]byte) {
	t.Helper()
	var mu sync.Mutex
	var reqs []*http.Request
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs, bodies = append(reqs, r), append(bodies, b)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs, &bodies
}

func TestFlushJSON(t *testing.T) {
	srv, reqs, bodies := collector(t, 200)
	e, err := New(Config{OTLPEndpoint: srv.URL + "/", Protocol: ProtoJSON, UnitSalt: "x"})
	if err != nil {
		t.Fatal(err)
	}
	base := Request{Ring: "ring1", Release: "r1", Experiment: "exp", Variant: "treatment", Harness: "claude-code",
		Model: "m", Subject: "alice@example.com"}
	for _, r := range []struct {
		status int
		ms     float64
	}{{200, 5}, {200, 10}, {200, 10.5}, {529, 800}, {0, 1e9}} {
		x := base
		x.Status, x.Latency = r.status, time.Duration(r.ms*float64(time.Millisecond))
		e.Record(x)
	}
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(context.Background()); err != nil || len(*reqs) != 1 {
		t.Fatalf("empty flush must not export: %v, %d posts", err, len(*reqs))
	}
	r := (*reqs)[0]
	if r.URL.Path != "/v1/metrics" || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("posted %s %s", r.URL.Path, r.Header.Get("Content-Type"))
	}
	body := string((*bodies)[0])
	for _, leak := range []string{"alice"} {
		if strings.Contains(body, leak) {
			t.Errorf("body leaks %q", leak)
		}
	}
	var doc struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Name string
					Sum  struct {
						AggregationTemporality int
						DataPoints             []struct {
							AsInt      string
							Attributes []struct{ Key string }
						}
					}
					Histogram struct {
						DataPoints []struct {
							Count          string
							Sum            float64
							BucketCounts   []string
							ExplicitBounds []float64
							Attributes     []struct {
								Key   string
								Value struct{ StringValue string }
							}
						}
					}
				}
			}
		}
	}
	if err := json.Unmarshal((*bodies)[0], &doc); err != nil {
		t.Fatal(err)
	}
	ms := doc.ResourceMetrics[0].ScopeMetrics[0].Metrics
	if ms[0].Name != "halo.gateway.requests" || ms[1].Name != "halo.gateway.latency_ms" || ms[0].Sum.AggregationTemporality != 1 {
		t.Fatalf("metrics %+v", ms)
	}
	// Three series: 2xx, 5xx, other.
	classes := map[string]string{}
	for _, dp := range ms[1].Histogram.DataPoints {
		attrs := map[string]string{}
		for _, a := range dp.Attributes {
			attrs[a.Key] = a.Value.StringValue
		}
		if attrs["halo.variant"] != "treatment" || attrs["halo.unit"] == "" || attrs["halo.ring"] != "ring1" {
			t.Errorf("attrs %v", attrs)
		}
		classes[attrs["status_class"]] = dp.Count
		if attrs["status_class"] == "2xx" {
			if dp.Sum != 25.5 || len(dp.BucketCounts) != len(dp.ExplicitBounds)+1 {
				t.Errorf("2xx hist sum=%v buckets=%d bounds=%d", dp.Sum, len(dp.BucketCounts), len(dp.ExplicitBounds))
			}
			// 5 and 10 land in the first bucket (<= 10), 10.5 in the second.
			if dp.BucketCounts[0] != "2" || dp.BucketCounts[1] != "1" {
				t.Errorf("bucket placement %v", dp.BucketCounts[:3])
			}
		}
		if attrs["status_class"] == "other" && dp.BucketCounts[len(dp.BucketCounts)-1] != "1" {
			t.Error("overflow latency must land in the +Inf bucket")
		}
	}
	if fmt.Sprint(classes) != "map[2xx:3 5xx:1 other:1]" {
		t.Errorf("status classes %v", classes)
	}
}

// walk checks buf is well-formed protobuf and collects every length-delimited
// field (recursing into those that parse as messages).
func walk(t *testing.T, buf []byte, out map[string]bool) {
	t.Helper()
	if !isMsg(buf) {
		t.Fatal("malformed protobuf")
	}
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		buf = buf[n:]
		m := protowire.ConsumeFieldValue(num, typ, buf)
		if typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(buf)
			out[string(v)] = true
			if len(v) > 0 && isMsg(v) {
				walk(t, v, out)
			}
		}
		buf = buf[m:]
	}
}

func isMsg(v []byte) bool {
	for len(v) > 0 {
		num, typ, n := protowire.ConsumeTag(v)
		if n < 0 || num == 0 {
			return false
		}
		v = v[n:]
		m := protowire.ConsumeFieldValue(num, typ, v)
		if m < 0 {
			return false
		}
		v = v[m:]
	}
	return true
}

func TestFlushProtobuf(t *testing.T) {
	srv, reqs, bodies := collector(t, 200)
	e, _ := New(Config{OTLPEndpoint: srv.URL, UnitSalt: "x"}) // default protocol
	e.Record(Request{Ring: "ring1", Experiment: "exp", Variant: "control", Subject: "subject-raw", Status: 200, Latency: 42 * time.Millisecond})
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ct := (*reqs)[0].Header.Get("Content-Type"); ct != "application/x-protobuf" {
		t.Fatalf("content-type %q", ct)
	}
	strs := map[string]bool{}
	walk(t, (*bodies)[0], strs)
	for _, want := range []string{"halo.gateway.requests", "halo.gateway.latency_ms", "halo.variant", "control", "status_class", "2xx", "halo-proxy"} {
		if !strs[want] {
			t.Errorf("protobuf body lacks %q", want)
		}
	}
	if strs["subject-raw"] {
		t.Error("raw subject exported")
	}
}

func TestFlushErrors(t *testing.T) {
	bad, _, _ := collector(t, 500)
	for _, tc := range []struct{ name, url, want string }{
		{"http 500", bad.URL, "HTTP 500"},
		{"unreachable", "http://127.0.0.1:1", "export 1 series"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := New(Config{OTLPEndpoint: tc.url})
			e.Record(Request{Status: 200})
			err := e.Flush(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// The collector's gateway receiver authenticates halo-proxy by bearer token.
func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	srv, reqs, _ := collector(t, 200)
	for _, tc := range []struct {
		name, file, wantAuth, wantErr string
	}{
		{"token sent", write("tok", "gw-secret\n"), "Bearer gw-secret", ""},
		{"no token file", "", "", ""},
		{"empty file", write("empty", " \n"), "", "is empty"},
		{"missing file", filepath.Join(dir, "nope"), "", "token file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := New(Config{OTLPEndpoint: srv.URL, TokenFile: tc.file})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			e.Record(Request{Status: 200})
			if err := e.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := (*reqs)[len(*reqs)-1].Header.Get("Authorization"); got != tc.wantAuth {
				t.Fatalf("Authorization %q, want %q", got, tc.wantAuth)
			}
		})
	}
}

// The hand-rolled protobuf encoder must decode with the real OTLP schema.
func TestProtobufWireCompat(t *testing.T) {
	srv, _, bodies := collector(t, 200)
	e, _ := New(Config{OTLPEndpoint: srv.URL, UnitSalt: "x"})
	base := Request{Ring: "ring1", Experiment: "exp", Variant: "treatment", Harness: "claude-code", Subject: "alice"}
	ok, fail := base, base
	ok.Status, ok.Latency = 200, 42*time.Millisecond
	fail.Status, fail.Latency = 503, 7*time.Millisecond
	e.Record(ok)
	e.Record(fail)
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var req metricspb.MetricsData // same wire format as ExportMetricsServiceRequest (field 1: resource_metrics), without the gRPC deps
	if err := proto.Unmarshal((*bodies)[0], &req); err != nil {
		t.Fatalf("not valid OTLP metrics: %v", err)
	}
	rm := req.GetResourceMetrics()
	if len(rm) != 1 || rm[0].GetResource().GetAttributes()[0].GetValue().GetStringValue() != "halo-proxy" {
		t.Fatalf("resource %v", rm)
	}
	sm := rm[0].GetScopeMetrics()
	if len(sm) != 1 || sm[0].GetScope().GetName() != "halo-proxy" || len(sm[0].GetMetrics()) != 2 {
		t.Fatalf("scope metrics %v", sm)
	}
	reqs, lat := sm[0].GetMetrics()[0], sm[0].GetMetrics()[1]
	delta := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
	sum := reqs.GetSum()
	if reqs.GetName() != "halo.gateway.requests" || reqs.GetUnit() != "{request}" || !sum.GetIsMonotonic() ||
		sum.GetAggregationTemporality() != delta || len(sum.GetDataPoints()) != 2 {
		t.Fatalf("requests metric %v", reqs)
	}
	attrs := func(kvs []*commonpb.KeyValue) map[string]string {
		m := map[string]string{}
		for _, kv := range kvs {
			m[kv.GetKey()] = kv.GetValue().GetStringValue()
		}
		return m
	}
	for _, dp := range sum.GetDataPoints() {
		a := attrs(dp.GetAttributes())
		if dp.GetAsInt() != 1 || a["halo.variant"] != "treatment" || a["halo.unit"] != e.Unit("alice") || dp.GetTimeUnixNano() < dp.GetStartTimeUnixNano() {
			t.Errorf("sum point %v attrs %v", dp, a)
		}
	}
	h := lat.GetHistogram()
	if lat.GetName() != "halo.gateway.latency_ms" || lat.GetUnit() != "ms" || h.GetAggregationTemporality() != delta || len(h.GetDataPoints()) != 2 {
		t.Fatalf("latency metric %v", lat)
	}
	for _, dp := range h.GetDataPoints() {
		a := attrs(dp.GetAttributes())
		want := map[string]float64{"2xx": 42, "5xx": 7}[a["status_class"]]
		var n uint64
		for _, c := range dp.GetBucketCounts() {
			n += c
		}
		if dp.GetCount() != 1 || dp.GetSum() != want || n != 1 || len(dp.GetBucketCounts()) != len(dp.GetExplicitBounds())+1 ||
			dp.GetExplicitBounds()[0] != LatencyBoundsMS[0] {
			t.Errorf("histogram point %v attrs %v", dp, a)
		}
	}
}

func TestSeriesCap(t *testing.T) {
	e, _ := New(Config{OTLPEndpoint: "http://c"})
	for i := 0; i < maxSeries+50; i++ {
		e.Record(Request{Subject: fmt.Sprint(i), Status: 200})
	}
	if n := len(e.series); n != maxSeries+1 {
		t.Fatalf("series = %d, want cap %d + one unit-less overflow series", n, maxSeries)
	}
	if a := e.series[key{class: "2xx"}]; a == nil || a.n != 50 {
		t.Fatalf("overflow series %+v", a)
	}
}

func TestRunExportsAndStops(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { posts.Add(1) }))
	defer srv.Close()
	e, _ := New(Config{OTLPEndpoint: srv.URL, Interval: time.Second})
	e.interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx, func(err error) { t.Error(err) }); close(done) }()
	e.Record(Request{Status: 200})
	for deadline := time.Now().Add(5 * time.Second); posts.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if posts.Load() == 0 {
		t.Fatal("Run never exported")
	}
}
