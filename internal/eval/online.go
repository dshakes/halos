package eval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/shadow"
	"github.com/dshakes/halos/internal/stats"
)

// PairSource yields halo-shadow pairs.
type PairSource interface {
	Pairs(ctx context.Context) ([]shadow.Pair, error)
}

// FilePairs reads halo-shadow's JSONL pair store, decrypting sealed rows with
// Keys (current and retired). An unreadable row fails the read: grading a
// silently partial sample would bias it.
type FilePairs struct {
	Path string
	Keys [][]byte
}

func (f FilePairs) Pairs(ctx context.Context) ([]shadow.Pair, error) {
	in, err := os.Open(f.Path)
	if err != nil {
		return nil, fmt.Errorf("pair store: %w", err)
	}
	defer func() { _ = in.Close() }() // read-only
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20) // pairs hold two full responses
	var out []shadow.Pair
	for n := 1; sc.Scan(); n++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		p, err := shadow.DecodePair(sc.Bytes(), f.Keys...)
		if err != nil {
			return nil, fmt.Errorf("pair store %s line %d: %w", f.Path, n, err)
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("pair store %s: %w", f.Path, err)
	}
	return out, nil
}

// OnlineOptions configures one online grading pass.
type OnlineOptions struct {
	Judge  *Judge
	Rubric *Rubric
	// Sample caps graded pairs per experiment (0 = all); the sample is a
	// seeded shuffle, so a rerun with the same seed grades the same pairs.
	Sample int
	Seed   uint64
	// Experiment limits grading to one experiment ("" = all).
	Experiment string
	// Skip holds pair ids already graded (from the history file).
	Skip map[string]bool
	Now  func() time.Time
}

// OnlineResult is one experiment's online quality reading.
type OnlineResult struct {
	Experiment  string  `json:"experiment"`
	Rubric      string  `json:"rubric"`
	JudgeModel  string  `json:"judgeModel"`
	Pairs       int     `json:"pairs"`  // eligible pairs seen
	Graded      int     `json:"graded"` // pairs with both sides judged
	JudgeErrors int     `json:"judgeErrors"`
	Control     float64 `json:"controlScore"`
	Candidate   float64 `json:"candidateScore"`
	// Delta is candidate - control score, paired by pair, with a bootstrap CI.
	Delta   MetricDelta `json:"delta"`
	WinRate float64     `json:"winRate"` // share of pairs the candidate scored higher (ties count half)
	// ControlVariant/CandidateVariant name the arms (shadow target variants).
	ControlVariant   string   `json:"controlVariant"`
	CandidateVariant string   `json:"candidateVariant"`
	PairIDs          []string `json:"pairIds"`
}

// judgeSideCap bounds each request/response handed to the judge.
const judgeSideCap = 24 << 10

func clip(b []byte) string {
	if len(b) > judgeSideCap {
		return string(b[:judgeSideCap]) + "\n[... truncated ...]"
	}
	return string(b)
}

func pairInput(p shadow.Pair, s shadow.Side) string {
	return "## Request (as sent by the coding agent)\n\n```json\n" + clip(p.Request) +
		"\n```\n\n## Model response\n\n```json\n" + clip(s.Response) + "\n```\n"
}

func usable(s shadow.Side) bool {
	return s.Error == "" && s.Status == http.StatusOK && len(s.Response) > 0
}

// RunOnline samples pairs per experiment and grades both sides with the
// rubric. Pairs where either side errored are skipped (that is a reliability
// signal the gateway metrics already carry, not a quality one). A judge error
// on either side drops the pair from the scores and is counted.
func RunOnline(ctx context.Context, src PairSource, o OnlineOptions) ([]OnlineResult, error) {
	if o.Judge == nil || o.Rubric == nil {
		return nil, errors.New("online eval: judge and rubric are required")
	}
	pairs, err := src.Pairs(ctx)
	if err != nil {
		return nil, fmt.Errorf("online eval: %w", err)
	}
	byExp := map[string][]shadow.Pair{}
	for _, p := range pairs {
		if (o.Experiment != "" && p.Experiment != o.Experiment) || o.Skip[p.ID] || !usable(p.Control) || !usable(p.Candidate) {
			continue
		}
		byExp[p.Experiment] = append(byExp[p.Experiment], p)
	}
	exps := make([]string, 0, len(byExp))
	for e := range byExp {
		exps = append(exps, e)
	}
	sort.Strings(exps)
	var out []OnlineResult
	for _, e := range exps {
		ps := byExp[e]
		sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
		rng := rand.New(rand.NewPCG(o.Seed, o.Seed^0x9e3779b97f4a7c15)) //nolint:gosec // reproducible sampling, not security
		rng.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
		if o.Sample > 0 && len(ps) > o.Sample {
			ps = ps[:o.Sample]
		}
		r := OnlineResult{Experiment: e, Rubric: o.Rubric.Ref(), JudgeModel: o.Judge.Model, Pairs: len(byExp[e]),
			ControlVariant: or(ps[0].Control.Target.Variant, "control"), CandidateVariant: or(ps[0].Candidate.Target.Variant, "candidate")}
		var cs, ts []float64
		wins := 0.0
		for _, p := range ps {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			cv, cerr := o.Judge.Grade(ctx, o.Rubric, pairInput(p, p.Control))
			tv, terr := o.Judge.Grade(ctx, o.Rubric, pairInput(p, p.Candidate))
			r.PairIDs = append(r.PairIDs, p.ID)
			if cerr != nil || terr != nil {
				r.JudgeErrors++
				continue
			}
			cs, ts = append(cs, cv.Score), append(ts, tv.Score)
			switch {
			case tv.Score > cv.Score:
				wins++
			case tv.Score == cv.Score:
				wins += 0.5
			}
		}
		r.Graded = len(cs)
		if r.Graded > 0 {
			for i := range cs {
				r.Control += cs[i] / float64(r.Graded)
				r.Candidate += ts[i] / float64(r.Graded)
			}
			r.WinRate = wins / float64(r.Graded)
			b, err := stats.PairedBootstrap(cs, ts, bootstrapIters, o.Seed, bootstrapAlpha)
			if err != nil {
				return nil, fmt.Errorf("online eval %s: %w", e, err)
			}
			r.Delta = MetricDelta{Mean: b.Mean, CILo: b.CILo, CIHi: b.CIHi, Baseline: r.Control}
		}
		out = append(out, r)
	}
	return out, nil
}

// HistoryEntry is one line of the scorecard history (JSONL): an offline
// suite run or an online reading, appended so trends survive across runs.
type HistoryEntry struct {
	Time     time.Time      `json:"time"`
	Kind     string         `json:"kind"` // offline | online
	Suite    string         `json:"suite,omitempty"`
	Gate     *Gate          `json:"gate,omitempty"`
	Variants []VariantScore `json:"variants,omitempty"`
	Online   *OnlineResult  `json:"online,omitempty"`
}

// OfflineHistory summarises sc as a history entry (trials omitted).
func OfflineHistory(sc *Scorecard, at time.Time) HistoryEntry {
	return HistoryEntry{Time: at.UTC(), Kind: "offline", Suite: sc.Suite, Gate: sc.Gate, Variants: sc.Variants}
}

// AppendHistory appends entries to the JSONL file at path (created 0644).
func AppendHistory(path string, entries ...HistoryEntry) error {
	var buf bytes.Buffer
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("history: encode: %w", err)
		}
		buf.Write(append(b, '\n'))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // operator-chosen history file
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close() // already failing
		return fmt.Errorf("history %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("history %s: %w", path, err)
	}
	return nil
}

// GradedPairs returns the pair ids already recorded in the history file
// (missing file = none).
func GradedPairs(path string) (map[string]bool, error) {
	out := map[string]bool{}
	b, err := os.ReadFile(path) //nolint:gosec // operator-chosen history file
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}
	for n, l := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var e HistoryEntry
		if err := json.Unmarshal(l, &e); err != nil {
			return nil, fmt.Errorf("history %s line %d: %w", path, n+1, err)
		}
		if e.Online != nil {
			for _, id := range e.Online.PairIDs {
				out[id] = true
			}
		}
	}
	return out, nil
}

// OTLPExporter posts halo.eval.* metrics to an OTel collector over OTLP/HTTP
// JSON. Point it at the authenticated gateway receiver (4319, with the
// halo-proxy token) so the readings carry halo.source=gateway: the CLI
// receiver is client-reachable and its rows are client-controlled evidence.
type OTLPExporter struct {
	URL   string // collector base URL; /v1/metrics is appended
	Token string // bearer token (optional)
	HTTP  *http.Client
}

// Online eval metric names (halo.* schema, see internal/telemetry).
const (
	MetricJudgeScore   = "halo.eval.judge.score"    // gauge per arm, 0..1
	MetricJudgeDelta   = "halo.eval.judge.delta"    // gauge, candidate - control
	MetricJudgeWinRate = "halo.eval.judge.win_rate" // gauge
	MetricPairsGraded  = "halo.eval.pairs.graded"   // sum (delta)
	MetricJudgeErrors  = "halo.eval.judge.errors"   // sum (delta)
)

// Export sends one data point per metric per result, stamped at now.
func (x *OTLPExporter) Export(ctx context.Context, rs []OnlineResult, start, now time.Time) error {
	if len(rs) == 0 {
		return nil
	}
	type m = map[string]any
	kvs := func(kv ...string) []m {
		var out []m
		for i := 0; i+1 < len(kv); i += 2 {
			out = append(out, m{"key": kv[i], "value": m{"stringValue": kv[i+1]}})
		}
		return out
	}
	st, et := strconv.FormatInt(start.UnixNano(), 10), strconv.FormatInt(now.UnixNano(), 10)
	gauge := func(v float64, attrs []m) m { return m{"attributes": attrs, "timeUnixNano": et, "asDouble": v} }
	count := func(v int, attrs []m) m {
		return m{"attributes": attrs, "startTimeUnixNano": st, "timeUnixNano": et, "asInt": strconv.Itoa(v)}
	}
	var score, delta, win, graded, errs []m
	for _, r := range rs {
		base := []string{"halo.experiment", r.Experiment, "halo.eval.rubric", r.Rubric, "halo.eval.judge", r.JudgeModel}
		score = append(score,
			gauge(r.Control, kvs(append(base, "halo.variant", r.ControlVariant)...)),
			gauge(r.Candidate, kvs(append(base, "halo.variant", r.CandidateVariant)...)))
		delta = append(delta, gauge(r.Delta.Mean, kvs(append(base, "halo.variant", r.CandidateVariant)...)))
		win = append(win, gauge(r.WinRate, kvs(append(base, "halo.variant", r.CandidateVariant)...)))
		graded = append(graded, count(r.Graded, kvs(base...)))
		errs = append(errs, count(r.JudgeErrors, kvs(base...)))
	}
	sum := func(dp []m) m {
		return m{"aggregationTemporality": temporalityDelta, "isMonotonic": true, "dataPoints": dp}
	}
	body := m{"resourceMetrics": []m{{
		"resource": m{"attributes": kvs("service.name", "halo-eval")},
		"scopeMetrics": []m{{"scope": m{"name": "halo-eval"}, "metrics": []m{
			{"name": MetricJudgeScore, "unit": "1", "gauge": m{"dataPoints": score}},
			{"name": MetricJudgeDelta, "unit": "1", "gauge": m{"dataPoints": delta}},
			{"name": MetricJudgeWinRate, "unit": "1", "gauge": m{"dataPoints": win}},
			{"name": MetricPairsGraded, "unit": "{pair}", "sum": sum(graded)},
			{"name": MetricJudgeErrors, "unit": "{pair}", "sum": sum(errs)},
		}}},
	}}}
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("otlp: encode: %w", err)
	}
	u := strings.TrimRight(x.URL, "/") + "/v1/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("otlp: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if x.Token != "" {
		req.Header.Set("Authorization", "Bearer "+x.Token)
	}
	hc := x.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("otlp: export to %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("otlp: export to %s: HTTP %d: %s", u, resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

const temporalityDelta = 1 // AGGREGATION_TEMPORALITY_DELTA

// OnlineTable renders online results as a compact terminal table.
func OnlineTable(rs []OnlineResult) string {
	if len(rs) == 0 {
		return "no new pairs to grade\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-24s  %6s  %6s  %7s  %7s  %-22s  %4s  %s\n", "EXPERIMENT", "GRADED", "ERRORS", "CONTROL", "CAND", "DELTA (95% CI)", "WIN", "RUBRIC")
	for _, r := range rs {
		fmt.Fprintf(&b, "%-24s  %6d  %6d  %7.2f  %7.2f  %-22s  %3.0f%%  %s\n", r.Experiment, r.Graded, r.JudgeErrors, r.Control, r.Candidate,
			fmt.Sprintf("%+.2f (%+.2f..%+.2f)", r.Delta.Mean, r.Delta.CILo, r.Delta.CIHi), 100*r.WinRate, r.Rubric)
	}
	return b.String()
}
