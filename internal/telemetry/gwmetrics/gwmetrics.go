// Package gwmetrics is halo-proxy's per-request OTLP metrics emitter: the
// gateway assigns ring/variant itself, so these are the best-attributed online
// samples for halo.api.error_rate and halo.latency.* (and the only ones for
// traffic-axis experiments). Requests are aggregated in memory per interval and
// exported as DELTA temporality over OTLP/HTTP (JSON or protobuf):
//
//	halo.gateway.requests   sum        {halo.ring, halo.release, halo.experiment, halo.variant, halo.harness, model, status_class, halo.unit,
//	                                    halo.gateway.provider, halo.gateway.target, halo.gateway.failover}
//	halo.gateway.latency_ms histogram  same attributes; total request time incl. streaming
//
// Privacy: no prompt content, headers, user ids or session ids are ever
// exported. halo.unit is HMAC-SHA256(salt, verified subject), truncated, so
// per-unit samples are possible without identifying anyone. It is never derived
// from client-controlled values (session headers): one user rotating session ids
// must stay one unit, or they would dominate the per-unit statistics. Requests
// without a verified subject are counted with an empty halo.unit, which
// internal/promote excludes from per-unit samples. Stdlib only apart from
// protowire (already in the module graph).
package gwmetrics

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Protocols accepted by Config.Protocol.
const (
	ProtoJSON     = "http/json"
	ProtoProtobuf = "http/protobuf"
)

// Config is halo-proxy's `telemetry:` block.
type Config struct {
	// OTLPEndpoint is the collector's OTLP/HTTP base URL (e.g.
	// http://otel-collector:4318); /v1/metrics is appended. Empty disables.
	OTLPEndpoint string        `yaml:"otlpEndpoint"`
	Protocol     string        `yaml:"protocol"` // http/protobuf (default) | http/json
	Interval     time.Duration `yaml:"interval"` // export interval, default 10s
	// UnitSalt keys the halo.unit hash. Set the same value on every replica
	// (and keep it across restarts) so one user stays one unit; empty = a
	// random per-process salt.
	UnitSalt string `yaml:"unitSalt"`
	// TokenFile holds the bearer token for the collector's authenticated
	// gateway receiver (`halo telemetry collector-config`: otlp/gateway, 4319),
	// read once at startup. Without it the collector rejects the export (401).
	TokenFile string `yaml:"tokenFile"`
}

// Validate checks c; an empty endpoint is valid (emitter off).
func (c Config) Validate() error {
	if c.OTLPEndpoint == "" {
		return nil
	}
	u, err := url.Parse(c.OTLPEndpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("telemetry.otlpEndpoint %q is not an http(s) URL", c.OTLPEndpoint)
	}
	if c.Protocol != "" && c.Protocol != ProtoJSON && c.Protocol != ProtoProtobuf {
		return fmt.Errorf("telemetry.protocol %q: want %s or %s", c.Protocol, ProtoProtobuf, ProtoJSON)
	}
	if c.Interval != 0 && c.Interval < time.Second {
		return fmt.Errorf("telemetry.interval %s: must be >= 1s", c.Interval)
	}
	return nil
}

// Request is one proxied model call. Subject (the verified identity; "" when
// anonymous) is hashed into halo.unit and never exported raw.
type Request struct {
	Ring, Release, Experiment, Variant, Harness, Model string
	// Provider (upstream kind), Target (upstream/model that served it) and
	// Failover (an earlier target failed before this one answered) describe
	// the route taken; empty Provider = not routed through a policy route.
	Provider, Target string
	Failover         bool
	Subject          string
	Status           int
	Latency          time.Duration
}

// LatencyBoundsMS are the histogram bucket upper bounds: ~12% apart from 10ms
// to 10min, fine enough that interpolated p50/p95 regressions of 10% resolve.
var LatencyBoundsMS = func() []float64 {
	var b []float64
	for v := 10.0; v <= 600_000; v *= 1.12 {
		b = append(b, math.Round(v))
	}
	return b
}()

// maxSeries caps distinct attribute sets per interval; beyond it new units are
// folded into halo.unit="" (still counted, just not per-unit) so memory stays
// bounded.
const maxSeries = 20_000

type key struct {
	ring, release, experiment, variant, harness, model, class, unit string
	provider, target, failover                                      string
}

type agg struct {
	n       uint64
	sum     float64
	buckets []uint64
}

// Emitter aggregates Requests and exports them. The zero of *Emitter (nil) is
// a valid no-op, so callers need no "telemetry enabled" branches.
type Emitter struct {
	url, proto string
	token      string
	interval   time.Duration
	salt       []byte
	client     *http.Client
	now        func() time.Time

	mu     sync.Mutex
	start  time.Time
	series map[key]*agg
}

// New returns an emitter for c, or nil when c.OTLPEndpoint is empty.
func New(c Config) (*Emitter, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.OTLPEndpoint == "" {
		return nil, nil
	}
	e := &Emitter{
		url: strings.TrimRight(c.OTLPEndpoint, "/") + "/v1/metrics", proto: c.Protocol, interval: c.Interval,
		salt: []byte(c.UnitSalt), client: &http.Client{Timeout: 10 * time.Second}, now: time.Now,
		series: map[key]*agg{},
	}
	if e.proto == "" {
		e.proto = ProtoProtobuf
	}
	if e.interval == 0 {
		e.interval = 10 * time.Second
	}
	if c.TokenFile != "" {
		b, err := os.ReadFile(c.TokenFile) //nolint:gosec // operator-supplied path is the point
		if err != nil {
			return nil, fmt.Errorf("gwmetrics: telemetry token file: %w", err)
		}
		if e.token = strings.TrimSpace(string(b)); e.token == "" {
			return nil, fmt.Errorf("gwmetrics: telemetry token file %s is empty", c.TokenFile)
		}
	}
	if len(e.salt) == 0 {
		e.salt = make([]byte, 32)
		if _, err := rand.Read(e.salt); err != nil {
			return nil, fmt.Errorf("gwmetrics: salt: %w", err)
		}
	}
	e.start = e.now()
	return e, nil
}

// Unit is the exported per-unit id for a verified subject; "" (not an
// experiment unit) when the request is anonymous.
func (e *Emitter) Unit(subject string) string {
	if subject == "" {
		return ""
	}
	m := hmac.New(sha256.New, e.salt)
	m.Write([]byte("u:" + subject))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// Record adds one request to the current interval. Safe for concurrent use.
func (e *Emitter) Record(r Request) {
	if e == nil {
		return
	}
	k := key{ring: r.Ring, release: r.Release, experiment: r.Experiment, variant: r.Variant, harness: r.Harness, model: r.Model,
		class: statusClass(r.Status), unit: e.Unit(r.Subject), provider: r.Provider, target: r.Target}
	if r.Provider != "" {
		k.failover = strconv.FormatBool(r.Failover)
	}
	ms := float64(r.Latency) / float64(time.Millisecond)
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.series[k]
	if a == nil {
		if len(e.series) >= maxSeries {
			k.unit = ""
			a = e.series[k]
		}
		if a == nil {
			a = &agg{buckets: make([]uint64, len(LatencyBoundsMS)+1)}
			e.series[k] = a
		}
	}
	a.n++
	a.sum += ms
	a.buckets[sort.SearchFloat64s(LatencyBoundsMS, ms)]++ // first bound >= ms: OTLP buckets are (prev, bound]
}

func statusClass(s int) string {
	if s < 100 || s > 599 {
		return "other"
	}
	return strconv.Itoa(s/100) + "xx"
}

// Run exports every interval until ctx is done. Export errors are reported to
// onErr (may be nil) and the interval's data is dropped: telemetry must never
// back-pressure the proxy. Call Flush after the server drains for the tail.
func (e *Emitter) Run(ctx context.Context, onErr func(error)) {
	if e == nil {
		return
	}
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.Flush(ctx); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// Flush exports and resets the current interval. No-op when empty.
func (e *Emitter) Flush(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	series, start, end := e.series, e.start, e.now()
	e.series, e.start = map[key]*agg{}, end
	e.mu.Unlock()
	if len(series) == 0 {
		return nil
	}
	var body []byte
	ct := "application/json"
	if e.proto == ProtoProtobuf {
		body, ct = encodeProto(series, start, end), "application/x-protobuf"
	} else {
		var err error
		if body, err = json.Marshal(encodeJSON(series, start, end)); err != nil {
			return fmt.Errorf("gwmetrics: encode: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gwmetrics: export to %s: %w", e.url, err)
	}
	req.Header.Set("Content-Type", ct)
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("gwmetrics: export %d series to %s: %w", len(series), e.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("gwmetrics: export %d series to %s: HTTP %d: %s", len(series), e.url, resp.StatusCode, bytes.TrimSpace(msg))
	}
	_, _ = io.Copy(io.Discard, resp.Body) // keep-alive
	return nil
}

// attrs are the exported data point attributes (empty values omitted).
func (k key) attrs() [][2]string {
	var out [][2]string
	for _, kv := range [][2]string{
		{"halo.ring", k.ring}, {"halo.release", k.release}, {"halo.experiment", k.experiment},
		{"halo.variant", k.variant}, {"halo.harness", k.harness}, {"model", k.model},
		{"status_class", k.class}, {"halo.unit", k.unit},
		{"halo.gateway.provider", k.provider}, {"halo.gateway.target", k.target}, {"halo.gateway.failover", k.failover},
	} {
		if kv[1] != "" {
			out = append(out, kv)
		}
	}
	return out
}

func sortedKeys(series map[key]*agg) []key {
	ks := make([]key, 0, len(series))
	for k := range series {
		ks = append(ks, k)
	}
	slices.SortFunc(ks, func(a, b key) int {
		return cmp.Or(cmp.Compare(a.ring, b.ring), cmp.Compare(a.release, b.release), cmp.Compare(a.experiment, b.experiment),
			cmp.Compare(a.variant, b.variant), cmp.Compare(a.harness, b.harness), cmp.Compare(a.model, b.model),
			cmp.Compare(a.class, b.class), cmp.Compare(a.unit, b.unit), cmp.Compare(a.provider, b.provider),
			cmp.Compare(a.target, b.target), cmp.Compare(a.failover, b.failover))
	})
	return ks
}

const temporalityDelta = 1 // AGGREGATION_TEMPORALITY_DELTA

var resourceAttrs = [][2]string{{"service.name", "halo-proxy"}}

// encodeJSON renders the OTLP/JSON ExportMetricsServiceRequest.
func encodeJSON(series map[key]*agg, start, end time.Time) map[string]any {
	type m = map[string]any
	kvs := func(a [][2]string) []m {
		out := make([]m, 0, len(a))
		for _, kv := range a {
			out = append(out, m{"key": kv[0], "value": m{"stringValue": kv[1]}})
		}
		return out
	}
	st, et := strconv.FormatInt(start.UnixNano(), 10), strconv.FormatInt(end.UnixNano(), 10)
	var reqs, hists []m
	for _, k := range sortedKeys(series) {
		a := series[k]
		bc := make([]string, len(a.buckets))
		for i, c := range a.buckets {
			bc[i] = strconv.FormatUint(c, 10)
		}
		reqs = append(reqs, m{"attributes": kvs(k.attrs()), "startTimeUnixNano": st, "timeUnixNano": et, "asInt": strconv.FormatUint(a.n, 10)})
		hists = append(hists, m{"attributes": kvs(k.attrs()), "startTimeUnixNano": st, "timeUnixNano": et,
			"count": strconv.FormatUint(a.n, 10), "sum": a.sum, "bucketCounts": bc, "explicitBounds": LatencyBoundsMS})
	}
	return m{"resourceMetrics": []m{{
		"resource": m{"attributes": kvs(resourceAttrs)},
		"scopeMetrics": []m{{"scope": m{"name": "halo-proxy"}, "metrics": []m{
			{"name": "halo.gateway.requests", "unit": "{request}", "sum": m{"aggregationTemporality": temporalityDelta, "isMonotonic": true, "dataPoints": reqs}},
			{"name": "halo.gateway.latency_ms", "unit": "ms", "histogram": m{"aggregationTemporality": temporalityDelta, "dataPoints": hists}},
		}}},
	}}}
}

// encodeProto renders the same request as OTLP protobuf (opentelemetry-proto
// metrics/v1 field numbers).
func encodeProto(series map[key]*agg, start, end time.Time) []byte {
	msg := func(b []byte, num protowire.Number, v []byte) []byte {
		b = protowire.AppendTag(b, num, protowire.BytesType)
		return protowire.AppendBytes(b, v)
	}
	str := func(b []byte, num protowire.Number, s string) []byte {
		b = protowire.AppendTag(b, num, protowire.BytesType)
		return protowire.AppendString(b, s)
	}
	fixed := func(b []byte, num protowire.Number, v uint64) []byte {
		b = protowire.AppendTag(b, num, protowire.Fixed64Type)
		return protowire.AppendFixed64(b, v)
	}
	varint := func(b []byte, num protowire.Number, v uint64) []byte {
		b = protowire.AppendTag(b, num, protowire.VarintType)
		return protowire.AppendVarint(b, v)
	}
	kv := func(k, v string) []byte { // KeyValue{key=1, value=2 AnyValue{string_value=1}}
		return msg(str(nil, 1, k), 2, str(nil, 1, v))
	}
	st, et := uint64(start.UnixNano()), uint64(end.UnixNano()) //nolint:gosec // wall-clock nanos are positive
	var reqs, hists []byte
	for _, k := range sortedKeys(series) {
		a := series[k]
		var attrs []byte
		for _, p := range k.attrs() {
			attrs = msg(attrs, 7, kv(p[0], p[1])) // NumberDataPoint.attributes = 7
		}
		dp := fixed(fixed(nil, 2, st), 3, et) // start_time_unix_nano=2, time_unix_nano=3
		dp = append(dp, attrs...)
		dp = fixed(dp, 6, a.n) // as_int=6 (sfixed64)
		reqs = msg(reqs, 1, dp)

		var hattrs []byte
		for _, p := range k.attrs() {
			hattrs = msg(hattrs, 9, kv(p[0], p[1])) // HistogramDataPoint.attributes = 9
		}
		h := fixed(fixed(nil, 2, st), 3, et)
		h = fixed(h, 4, a.n)                     // count=4
		h = fixed(h, 5, math.Float64bits(a.sum)) // sum=5 (double)
		var bc, eb []byte
		for _, c := range a.buckets {
			bc = protowire.AppendFixed64(bc, c)
		}
		for _, v := range LatencyBoundsMS {
			eb = protowire.AppendFixed64(eb, math.Float64bits(v))
		}
		h = msg(h, 6, bc) // bucket_counts=6 packed fixed64
		h = msg(h, 7, eb) // explicit_bounds=7 packed double
		h = append(h, hattrs...)
		hists = msg(hists, 1, h)
	}
	sum := varint(varint(append([]byte(nil), reqs...), 2, temporalityDelta), 3, 1)                 // Sum{data_points=1, temporality=2, is_monotonic=3}
	hist := varint(append([]byte(nil), hists...), 2, temporalityDelta)                             // Histogram{data_points=1, temporality=2}
	metrics := msg(nil, 2, msg(str(str(nil, 1, "halo.gateway.requests"), 3, "{request}"), 7, sum)) // Metric{name=1, unit=3, sum=7}
	metrics = msg(metrics, 2, msg(str(str(nil, 1, "halo.gateway.latency_ms"), 3, "ms"), 9, hist))  // histogram=9
	scope := append(msg(nil, 1, str(nil, 1, "halo-proxy")), metrics...)                            // ScopeMetrics{scope=1, metrics=2}
	var res []byte
	for _, p := range resourceAttrs {
		res = msg(res, 1, kv(p[0], p[1])) // Resource.attributes=1
	}
	rm := msg(msg(nil, 1, res), 2, scope) // ResourceMetrics{resource=1, scope_metrics=2}
	return msg(nil, 1, rm)                // ExportMetricsServiceRequest{resource_metrics=1}
}
