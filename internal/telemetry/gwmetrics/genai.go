package gwmetrics

// OpenTelemetry GenAI semantic conventions, exported next to (never instead of)
// the halo.gateway.* series, which stay the stable API the controller reads.
//
// Implemented against semantic-conventions v1.40.0 (docs/gen-ai/gen-ai-metrics.md
// and gen-ai-spans.md); every GenAI convention is still "Development" stability,
// so names may move. The upstream project has since split these into the
// semantic-conventions-genai repository and reworked the token instruments
// (gen_ai.client.inference.*); this keeps the widely deployed v1.40 names.
//
//	gen_ai.client.token.usage        histogram {token}  gen_ai.token.type = input | output
//	gen_ai.client.operation.duration histogram s        error.type on HTTP status >= 400
//	gen_ai.server.time_to_first_token histogram s       streams only, successful responses
//
// All carry gen_ai.operation.name, gen_ai.provider.name, gen_ai.request.model
// and (when the response names one) gen_ai.response.model, plus the halo.ring /
// release / experiment / variant / harness cohort and, for a delegated agent
// (ADR-0024), halo.actor.agent. Spans also carry halo.actor.depth,
// halo.actor.chain and gen_ai.agent.name (the current agent): v1.40 lists
// gen_ai.agent.name on agent spans; the registry attribute means the same
// thing on the inference span the agent caused, so it is set there too. Token usage is recorded only
// when the provider reported it. Never exported: prompts, completions, headers,
// raw user or session ids (spans carry the same salted halo.unit hash as the
// halo.gateway.* series). Content capture is deliberately not implemented.

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// GenAIConfig is the `telemetry.genai` block.
type GenAIConfig struct {
	// Metrics toggles the gen_ai.* metrics; nil (unset) means on.
	Metrics *bool `yaml:"metrics"`
	// Traces enables one `{operation} {model}` span per model call, exported as
	// OTLP/JSON to /v1/traces. Off by default.
	Traces bool `yaml:"traces"`
}

func (g GenAIConfig) metricsOn() bool { return g.Metrics == nil || *g.Metrics }

type genaiOpts struct{ metrics, traces bool }

// GenAI is the semantic-convention view of one proxied model call.
type GenAI struct {
	Operation, Provider string
	ResponseModel       string // "" when the response did not name one
	// InputTokens / OutputTokens < 0: the response carried no usage.
	InputTokens, OutputTokens int64
	// TTFT < 0: not a stream, so not measurable.
	TTFT time.Duration
}

// Histogram bucket advice from the specification.
var (
	genaiTokenBounds    = []float64{1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864}
	genaiDurationBounds = []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92}
	genaiTTFTBounds     = []float64{0.001, 0.005, 0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}
)

const (
	// maxGenAISeries bounds each instrument's distinct attribute sets per interval
	// (models and cohorts are policy-bounded; response.model is also length-capped).
	maxGenAISeries = 5_000
	// maxSpans bounds spans held between exports; later ones are dropped.
	maxSpans = 4_096
)

type gkey struct {
	op, provider, reqModel, respModel, tokenType, errType string
	ring, release, experiment, variant, harness           string
	actor                                                 string
}

func (k gkey) attrs() [][2]string {
	var out [][2]string
	for _, kv := range [][2]string{
		{"gen_ai.operation.name", k.op}, {"gen_ai.provider.name", k.provider},
		{"gen_ai.request.model", k.reqModel}, {"gen_ai.response.model", k.respModel},
		{"gen_ai.token.type", k.tokenType}, {"error.type", k.errType},
		{"halo.ring", k.ring}, {"halo.release", k.release}, {"halo.experiment", k.experiment},
		{"halo.variant", k.variant}, {"halo.harness", k.harness}, {"halo.actor.agent", k.actor},
	} {
		if kv[1] != "" {
			out = append(out, kv)
		}
	}
	return out
}

// genaiSnap is one interval's GenAI aggregates.
type genaiSnap struct{ tokens, duration, ttft map[gkey]*agg }

func newGenaiSnap() *genaiSnap {
	return &genaiSnap{tokens: map[gkey]*agg{}, duration: map[gkey]*agg{}, ttft: map[gkey]*agg{}}
}

func observe(m map[gkey]*agg, k gkey, v float64, bounds []float64) {
	a := m[k]
	if a == nil {
		if len(m) >= maxGenAISeries {
			return
		}
		a = &agg{buckets: make([]uint64, len(bounds)+1)}
		m[k] = a
	}
	a.n++
	a.sum += v
	a.buckets[sort.SearchFloat64s(bounds, v)]++
}

// recordGenAI folds r into the GenAI aggregates and span buffer. e.mu is held.
func (e *Emitter) recordGenAI(r Request) {
	g := r.GenAI
	if g == nil || !e.genai.metrics && !e.genai.traces {
		return
	}
	errType := ""
	if r.Status >= 400 {
		errType = strconv.Itoa(r.Status)
	}
	k := gkey{op: g.Operation, provider: g.Provider, reqModel: r.Model, respModel: g.ResponseModel,
		ring: r.Ring, release: r.Release, experiment: r.Experiment, variant: r.Variant, harness: r.Harness, actor: r.Actor}
	if e.genai.metrics {
		dk := k
		dk.errType = errType
		observe(e.gen.duration, dk, r.Latency.Seconds(), genaiDurationBounds)
		if g.InputTokens >= 0 {
			k.tokenType = "input"
			observe(e.gen.tokens, k, float64(g.InputTokens), genaiTokenBounds)
		}
		if g.OutputTokens >= 0 {
			k.tokenType = "output"
			observe(e.gen.tokens, k, float64(g.OutputTokens), genaiTokenBounds)
		}
		k.tokenType = ""
		if g.TTFT >= 0 && errType == "" {
			observe(e.gen.ttft, k, g.TTFT.Seconds(), genaiTTFTBounds)
		}
	}
	if e.genai.traces && len(e.spans) < maxSpans {
		e.spans = append(e.spans, e.newSpan(r, errType))
	}
}

// ---- spans ----

type spanAttr struct {
	k, s  string
	i     int64
	isInt bool
}

type span struct {
	traceID, spanID, parentID string // hex; parentID "" for a root
	name                      string
	start, end                time.Time
	attrs                     []spanAttr
	errType                   string // non-empty marks the span as an error
}

func (e *Emitter) newSpan(r Request, errType string) span {
	g := r.GenAI
	sp := span{name: g.Operation + " " + r.Model, errType: errType, end: r.Start.Add(r.Latency), start: r.Start}
	if sp.start.IsZero() { // callers that did not stamp the start: derive it
		sp.end = e.now()
		sp.start = sp.end.Add(-r.Latency)
	}
	var id [24]byte
	_, _ = rand.Read(id[:]) // crypto/rand does not fail on supported platforms; a zero id is merely a useless one
	sp.traceID, sp.spanID = hex.EncodeToString(id[:16]), hex.EncodeToString(id[16:])
	if t, p, ok := parseTraceparent(r.TraceParent); ok { // join the caller's trace
		sp.traceID, sp.parentID = t, p
	}
	add := func(k, v string) {
		if v != "" {
			sp.attrs = append(sp.attrs, spanAttr{k: k, s: v})
		}
	}
	add("gen_ai.operation.name", g.Operation)
	add("gen_ai.provider.name", g.Provider)
	add("gen_ai.request.model", r.Model)
	add("gen_ai.response.model", g.ResponseModel)
	if g.InputTokens >= 0 {
		sp.attrs = append(sp.attrs, spanAttr{k: "gen_ai.usage.input_tokens", i: g.InputTokens, isInt: true})
	}
	if g.OutputTokens >= 0 {
		sp.attrs = append(sp.attrs, spanAttr{k: "gen_ai.usage.output_tokens", i: g.OutputTokens, isInt: true})
	}
	add("error.type", errType)
	sp.attrs = append(sp.attrs, spanAttr{k: "http.response.status_code", i: int64(r.Status), isInt: true})
	add("halo.ring", r.Ring)
	add("halo.release", r.Release)
	add("halo.experiment", r.Experiment)
	add("halo.variant", r.Variant)
	add("halo.harness", r.Harness)
	add("halo.unit", e.Unit(r.Subject))
	if r.Actor != "" {
		add("gen_ai.agent.name", r.Actor)
		add("halo.actor.agent", r.Actor)
		add("halo.actor.chain", r.Chain)
		sp.attrs = append(sp.attrs, spanAttr{k: "halo.actor.depth", i: int64(r.ActorDepth), isInt: true})
	}
	return sp
}

// parseTraceparent accepts a W3C traceparent `00-<32 hex>-<16 hex>-<2 hex>`
// with non-zero ids and returns trace and parent span id.
func parseTraceparent(h string) (trace, parent string, ok bool) {
	if len(h) != 55 || h[:3] != "00-" || h[35] != '-' || h[52] != '-' {
		return "", "", false
	}
	trace, parent = h[3:35], h[36:52]
	for _, s := range []string{trace, parent, h[53:]} {
		for i := 0; i < len(s); i++ {
			if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return "", "", false
			}
		}
	}
	if trace == "00000000000000000000000000000000" || parent == "0000000000000000" {
		return "", "", false
	}
	return trace, parent, true
}

const (
	spanKindClient = 3 // SPAN_KIND_CLIENT
	statusError    = 2 // STATUS_CODE_ERROR
)

// encodeSpansJSON renders the OTLP/JSON ExportTraceServiceRequest.
func encodeSpansJSON(spans []span) map[string]any {
	type m = map[string]any
	out := make([]m, 0, len(spans))
	for _, s := range spans {
		attrs := make([]m, 0, len(s.attrs))
		for _, a := range s.attrs {
			v := m{"stringValue": a.s}
			if a.isInt {
				v = m{"intValue": strconv.FormatInt(a.i, 10)} // OTLP/JSON encodes int64 as a string
			}
			attrs = append(attrs, m{"key": a.k, "value": v})
		}
		o := m{"traceId": s.traceID, "spanId": s.spanID, "name": s.name, "kind": spanKindClient,
			"startTimeUnixNano": strconv.FormatInt(s.start.UnixNano(), 10),
			"endTimeUnixNano":   strconv.FormatInt(s.end.UnixNano(), 10), "attributes": attrs}
		if s.parentID != "" {
			o["parentSpanId"] = s.parentID
		}
		if s.errType != "" {
			o["status"] = m{"code": statusError}
		}
		out = append(out, o)
	}
	res := make([]m, 0, len(resourceAttrs))
	for _, kv := range resourceAttrs {
		res = append(res, m{"key": kv[0], "value": m{"stringValue": kv[1]}})
	}
	return m{"resourceSpans": []m{{
		"resource":   m{"attributes": res},
		"scopeSpans": []m{{"scope": m{"name": "halo-proxy"}, "spans": out}},
	}}}
}

// ---- metric encoding ----

type genaiInstr struct {
	name, unit string
	bounds     []float64
	series     map[gkey]*agg
}

func (s *genaiSnap) instruments() []genaiInstr {
	return []genaiInstr{
		{"gen_ai.client.token.usage", "{token}", genaiTokenBounds, s.tokens},
		{"gen_ai.client.operation.duration", "s", genaiDurationBounds, s.duration},
		{"gen_ai.server.time_to_first_token", "s", genaiTTFTBounds, s.ttft},
	}
}

func sortedGKeys(m map[gkey]*agg) []gkey {
	ks := make([]gkey, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return gkeyString(ks[i]) < gkeyString(ks[j]) })
	return ks
}

func gkeyString(k gkey) string {
	s := ""
	for _, kv := range k.attrs() {
		s += kv[0] + "=" + kv[1] + "\x00"
	}
	return s
}

func genaiMetricsJSON(s *genaiSnap, st, et string) []map[string]any {
	type m = map[string]any
	var out []m
	for _, in := range s.instruments() {
		if len(in.series) == 0 {
			continue
		}
		var dps []m
		for _, k := range sortedGKeys(in.series) {
			a := in.series[k]
			attrs := make([]m, 0, 8)
			for _, kv := range k.attrs() {
				attrs = append(attrs, m{"key": kv[0], "value": m{"stringValue": kv[1]}})
			}
			bc := make([]string, len(a.buckets))
			for i, c := range a.buckets {
				bc[i] = strconv.FormatUint(c, 10)
			}
			dps = append(dps, m{"attributes": attrs, "startTimeUnixNano": st, "timeUnixNano": et,
				"count": strconv.FormatUint(a.n, 10), "sum": a.sum, "bucketCounts": bc, "explicitBounds": in.bounds})
		}
		out = append(out, m{"name": in.name, "unit": in.unit, "histogram": m{"aggregationTemporality": temporalityDelta, "dataPoints": dps}})
	}
	return out
}

// genaiMetricsProto returns ScopeMetrics.metrics (field 2) entries.
func genaiMetricsProto(s *genaiSnap, st, et uint64) []byte {
	var out []byte
	for _, in := range s.instruments() {
		if len(in.series) == 0 {
			continue
		}
		var eb []byte
		for _, v := range in.bounds {
			eb = protowire.AppendFixed64(eb, math.Float64bits(v))
		}
		var hist []byte
		for _, k := range sortedGKeys(in.series) {
			a := in.series[k]
			h := pbFixed(pbFixed(nil, 2, st), 3, et)
			h = pbFixed(h, 4, a.n)
			h = pbFixed(h, 5, math.Float64bits(a.sum))
			var bc []byte
			for _, c := range a.buckets {
				bc = protowire.AppendFixed64(bc, c)
			}
			h = pbMsg(h, 6, bc)
			h = pbMsg(h, 7, eb)
			for _, kv := range k.attrs() {
				h = pbMsg(h, 9, pbKV(kv[0], kv[1])) // HistogramDataPoint.attributes = 9
			}
			hist = pbMsg(hist, 1, h)
		}
		hist = pbVarint(hist, 2, temporalityDelta)
		out = pbMsg(out, 2, pbMsg(pbStr(pbStr(nil, 1, in.name), 3, in.unit), 9, hist))
	}
	return out
}

// GenAIEnabled reports whether the emitter wants GenAI call details (and so
// whether callers should pay for observing response bodies). Nil-safe.
func (e *Emitter) GenAIEnabled() bool {
	return e != nil && (e.genai.metrics || e.genai.traces)
}
