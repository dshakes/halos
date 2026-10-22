package shadow

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

const maxBody = 8 << 20

// appendTimeout bounds the final pair write, which outlives shutdown.
const appendTimeout = 5 * time.Second

// DefaultBudgetUSD caps estimated spend when Config.BudgetUSD is unset.
const DefaultBudgetUSD = 50

// defaultMaxOut is the output-token estimate when a body sets no max tokens.
const defaultMaxOut = 8192

// ReplayHeaders is the only client-originated header set halo-shadow forwards.
var ReplayHeaders = map[string]bool{"anthropic-version": true, "anthropic-beta": true, "openai-beta": true}

// Config for the halo-shadow server.
type Config struct {
	Queue   int // bounded queue length (default 64)
	Workers int // default 4
	Token   string
	// Policy returns the current org (gateway.Snapshot.Get). Both sides of a
	// pair are resolved from it; jobs never name upstreams. Required.
	Policy func() (*policy.Org, error)
	// UpstreamHeaders are halo-shadow's own credentials, keyed by policy upstream
	// name; they are only ever sent to that upstream's URL.
	UpstreamHeaders map[string]map[string]string
	// BudgetUSD caps estimated spend (default DefaultBudgetUSD). Each job
	// reserves a worst-case estimate before anything is sent, so concurrency
	// can't overshoot; the reservation is settled to actual usage afterwards.
	BudgetUSD       float64
	PriceInPerMTok  float64
	PriceOutPerMTok float64
	HTTP            *http.Client // default: NewHTTPClient()
	Log             *slog.Logger
	// Budget, when set, replaces the per-process budget (BudgetUSD) with a
	// shared one (SharedBudget), so the cap holds across replicas.
	Budget Budget
	// Ping, when set, gates /readyz on the shared store being reachable.
	Ping func(context.Context) error
}

// NewHTTPClient never follows redirects (a 3xx is recorded as the response:
// credentials must not travel to wherever an upstream points) and bounds
// every phase of the call.
func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 10 * time.Second
	tr.ResponseHeaderTimeout = 2 * time.Minute
	tr.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Timeout:       3 * time.Minute,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Server is halo-shadow.
type Server struct {
	cfg   Config
	store Store
	q     chan task
	wg    sync.WaitGroup

	mirrored, dropped, errors atomic.Int64
	budget                    Budget
}

// side is one fully resolved call target.
type side struct {
	t       Target
	base    *url.URL
	headers map[string]string
}

type task struct {
	id        string // reservation and pair id
	j         Job
	ctl, cand side
	reserve   float64
}

func New(cfg Config, store Store) *Server {
	if cfg.Queue <= 0 {
		cfg.Queue = 64
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.BudgetUSD <= 0 {
		cfg.BudgetUSD = DefaultBudgetUSD
	}
	if cfg.HTTP == nil {
		cfg.HTTP = NewHTTPClient()
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Policy == nil {
		cfg.Policy = func() (*policy.Org, error) { return nil, errors.New("shadow: no policy source configured") }
	}
	s := &Server{cfg: cfg, store: store, q: make(chan task, cfg.Queue), budget: cfg.Budget}
	if s.budget == nil {
		s.budget = &localBudget{limit: cfg.BudgetUSD}
	}
	return s
}

// Start launches workers; they exit when ctx is cancelled after finishing
// their current job. Wait blocks until they have.
func (s *Server) Start(ctx context.Context) {
	for i := 0; i < s.cfg.Workers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t := <-s.q:
					s.process(ctx, t)
				}
			}
		}()
	}
}

func (s *Server) Wait() { s.wg.Wait() }

// budgetTimeout bounds one budget call against a shared store.
const budgetTimeout = 5 * time.Second

// Spent is the running estimated spend in USD (settled jobs only); with a
// shared budget, every replica's. A store error reads as 0 and is logged.
func (s *Server) Spent() float64 {
	ctx, cancel := context.WithTimeout(context.Background(), budgetTimeout)
	defer cancel()
	v, err := s.budget.Spent(ctx)
	if err != nil {
		s.cfg.Log.Error("read spend", "err", err)
	}
	return v
}

// reserve atomically books t's estimate against the budget; false = over
// budget, or the shared budget is unreachable (nothing is spent unbooked).
func (s *Server) reserve(ctx context.Context, t task) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budgetTimeout)
	defer cancel()
	ok, err := s.budget.Reserve(ctx, t.id, t.reserve)
	if err != nil {
		s.errors.Add(1)
		s.cfg.Log.Error("reserve budget", "err", err)
		return false
	}
	return ok
}

// settle swaps t's reservation for the charged cost (see process: never less
// than the estimate, so unparseable usage can't zero the spend).
func (s *Server) settle(t task, actual float64) {
	ctx, cancel := context.WithTimeout(context.Background(), budgetTimeout)
	defer cancel()
	if err := s.budget.Settle(ctx, t.id, t.reserve, actual); err != nil {
		// A shared reservation left behind is reaped and charged in full at expiry.
		s.errors.Add(1)
		s.cfg.Log.Error("settle budget", "id", t.id, "err", err)
	}
}

func (s *Server) authorized(r *http.Request) bool {
	return s.cfg.Token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get(TokenHeader)), []byte(s.cfg.Token)) == 1
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mirror", s.handleMirror)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	// /healthz: liveness — process is alive. Always 200.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	// /readyz: readiness — policy snapshot loaded. 503 until the snapshot is readable.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Ping != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			err := s.cfg.Ping(ctx)
			cancel()
			if err != nil {
				s.cfg.Log.Warn("readyz: database unreachable", "err", err)
				http.Error(w, "database unreachable", http.StatusServiceUnavailable)
				return
			}
		}
		if org, err := s.cfg.Policy(); org == nil {
			msg := "policy not loaded"
			if err != nil {
				msg += ": " + err.Error()
			}
			http.Error(w, msg, http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// MetricsHandler serves /metrics without the token, for a separate
// scrape-only listener (Prometheus can't send X-Halo-Shadow-Token). It exposes
// counters and spend gauges only; keep it off untrusted networks.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", s.writeMetrics)
	return mux
}

func (s *Server) handleMirror(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var j Job
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields() // a job naming an upstream/model is an old or hostile sender
	if err := dec.Decode(&j); err != nil {
		http.Error(w, "bad job: "+err.Error(), http.StatusBadRequest)
		return
	}
	t, status, err := s.resolve(j)
	if err != nil {
		s.cfg.Log.Warn("rejected mirror job", "experiment", j.Experiment, "variant", j.Variant, "err", err)
		http.Error(w, err.Error(), status)
		return
	}
	if !s.reserve(r.Context(), t) {
		s.dropped.Add(1)
		http.Error(w, "budget exhausted", http.StatusServiceUnavailable)
		return
	}
	select {
	case s.q <- t:
		w.WriteHeader(http.StatusAccepted)
	default:
		s.settle(t, 0)
		s.dropped.Add(1)
		http.Error(w, "queue full", http.StatusTooManyRequests)
	}
}

// resolve validates j against the current policy and fixes both targets.
func (s *Server) resolve(j Job) (task, int, error) {
	bad := func(format string, a ...any) (task, int, error) {
		return task{}, http.StatusBadRequest, fmt.Errorf("shadow: "+format, a...)
	}
	if j.Method != http.MethodPost {
		return bad("method %q not allowed", j.Method)
	}
	// Exact protocol paths only; the path is never a URL fragment we trust.
	if proto := gateway.ProtocolForPath(j.Path); proto == "" || proto != j.Protocol || gateway.IsCountTokens(j.Path) {
		return bad("path %q is not a %q model call", j.Path, j.Protocol)
	}
	if len(j.Body) == 0 {
		return bad("empty body")
	}
	org, err := s.cfg.Policy()
	if org == nil || org.Gateway == nil {
		return task{}, http.StatusServiceUnavailable, fmt.Errorf("shadow: policy unavailable: %v", err)
	}
	alias, _ := gateway.Inspect(j.Protocol, j.Path, j.Body)
	if alias == "" {
		return bad("no model alias in request")
	}
	var exp *policy.Experiment
	for _, e := range org.Experiments {
		if e.Name == j.Experiment && e.Type == policy.ExperimentShadow && e.Status == "running" {
			exp = e
		}
	}
	if exp == nil {
		return bad("no running shadow experiment %q", j.Experiment)
	}
	ctlRoute, ok := org.Gateway.Models[alias]
	var candRoute policy.ModelRoute
	var candOK bool
	for _, v := range exp.Variants {
		r, has := v.Routes[alias]
		switch {
		case v.Control && has:
			ctlRoute, ok = r, true
		case !v.Control && v.Name == j.Variant:
			candRoute, candOK = r, has
		}
	}
	if !ok || !candOK {
		return bad("experiment %q variant %q has no route for model %q", j.Experiment, j.Variant, alias)
	}
	ctl, err := s.side(org, "", ctlRoute)
	if err != nil {
		return task{}, http.StatusInternalServerError, err
	}
	cand, err := s.side(org, j.Variant, candRoute)
	if err != nil {
		return task{}, http.StatusInternalServerError, err
	}
	return task{id: newID(), j: j, ctl: ctl, cand: cand, reserve: 2 * s.estimate(j.Body)}, 0, nil
}

func (s *Server) side(org *policy.Org, variant string, r policy.ModelRoute) (side, error) {
	r = r.Primary() // shadow does not fail over
	up, ok := org.Gateway.Upstreams[r.Upstream]
	if !ok {
		return side{}, fmt.Errorf("shadow: policy upstream %q not defined", r.Upstream)
	}
	u, err := url.Parse(up.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return side{}, fmt.Errorf("shadow: policy upstream %q has a bad url", r.Upstream)
	}
	return side{t: Target{Variant: variant, Upstream: r.Upstream, Model: r.Model}, base: u, headers: s.cfg.UpstreamHeaders[r.Upstream]}, nil
}

// estimate is a deliberately high per-side cost bound: ~3 bytes per input
// token and the request's own output cap.
func (s *Server) estimate(body []byte) float64 {
	var b struct {
		MaxTokens int64 `json:"max_tokens"`
		MaxOutput int64 `json:"max_output_tokens"`
	}
	_ = json.Unmarshal(body, &b)
	out := max(b.MaxTokens, b.MaxOutput)
	if out <= 0 {
		out = defaultMaxOut
	}
	return float64(len(body))/3/1e6*s.cfg.PriceInPerMTok + float64(out)/1e6*s.cfg.PriceOutPerMTok
}

func (s *Server) process(ctx context.Context, t task) {
	var ctl, cand Side
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ctl = s.call(ctx, t.j, t.ctl) }()
	go func() { defer wg.Done(); cand = s.call(ctx, t.j, t.cand) }()
	wg.Wait()

	cost := s.cost(ctl) + s.cost(cand)
	// Missing or unparseable usage must not zero the spend: charge at least
	// the reservation, which is a deliberate over-estimate.
	s.settle(t, max(cost, t.reserve))

	j := t.j
	p := Pair{ID: t.id, Time: time.Now().UTC(), Experiment: j.Experiment, Ring: j.Ring, SessionID: j.SessionID,
		Protocol: j.Protocol, Request: j.Body, Control: ctl, Candidate: cand, CostUSD: cost}
	// The upstream calls are already paid for: a shutdown (ctx cancelled)
	// must not lose the pair, so the store gets its own short deadline.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)
	defer cancel()
	if err := s.store.Append(actx, p); err != nil {
		s.errors.Add(1)
		s.cfg.Log.Error("store pair", "err", err)
		return
	}
	s.mirrored.Add(1)
}

func (s *Server) cost(sd Side) float64 {
	return float64(sd.InputTokens)/1e6*s.cfg.PriceInPerMTok + float64(sd.OutputTokens)/1e6*s.cfg.PriceOutPerMTok
}

func (s *Server) call(ctx context.Context, j Job, t side) (sd Side) {
	sd.Target = t.t
	fail := func(err error) Side {
		sd.Error = err.Error()
		s.errors.Add(1)
		return sd
	}
	path, body, err := gateway.ForceNonStreaming(j.Protocol, j.Path, j.Body)
	if err != nil {
		return fail(err)
	}
	path, body, err = gateway.RewriteRequest(j.Protocol, path, body, t.t.Model)
	if err != nil {
		return fail(err)
	}
	// JoinPath keeps scheme/host from the policy URL whatever path holds.
	target := t.base.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fail(fmt.Errorf("build request: %w", err))
	}
	for k, v := range j.Headers {
		if ReplayHeaders[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return fail(fmt.Errorf("call upstream %s: %w", t.t.Upstream, err))
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	sd.LatencyMS = time.Since(start).Milliseconds()
	sd.Status = resp.StatusCode
	if err != nil {
		return fail(fmt.Errorf("read upstream %s: %w", t.t.Upstream, err))
	}
	if json.Valid(rb) {
		sd.Response = rb
	} else {
		sd.Response, _ = json.Marshal(string(rb))
	}
	sd.InputTokens, sd.OutputTokens = parseUsage(rb)
	if resp.StatusCode >= 300 {
		sd.Error = fmt.Sprintf("upstream status %d", resp.StatusCode)
		s.errors.Add(1)
	}
	return sd
}

// parseUsage reads token usage from any supported response shape:
// Anthropic/OpenAI Responses (input_tokens/output_tokens), OpenAI chat
// (prompt_tokens/completion_tokens) and Bedrock Converse
// (inputTokens/outputTokens). Unknown shapes yield 0, 0.
func parseUsage(body []byte) (in, out int64) {
	var u struct {
		Usage struct {
			In         int64 `json:"input_tokens"`
			Out        int64 `json:"output_tokens"`
			Prompt     int64 `json:"prompt_tokens"`
			Completion int64 `json:"completion_tokens"`
			BedrockIn  int64 `json:"inputTokens"`
			BedrockOut int64 `json:"outputTokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(body, &u) // non-JSON or no usage: charged at the estimate
	x := u.Usage
	return max(x.In, x.Prompt, x.BedrockIn), max(x.Out, x.Completion, x.BedrockOut)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.writeMetrics(w, r)
}

func (s *Server) writeMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE halo_shadow_mirrored_total counter\nhalo_shadow_mirrored_total %d\n", s.mirrored.Load())
	fmt.Fprintf(w, "# TYPE halo_shadow_dropped_total counter\nhalo_shadow_dropped_total %d\n", s.dropped.Load())
	fmt.Fprintf(w, "# TYPE halo_shadow_errors_total counter\nhalo_shadow_errors_total %d\n", s.errors.Load())
	fmt.Fprintf(w, "# TYPE halo_shadow_spend_usd gauge\nhalo_shadow_spend_usd %g\n", s.Spent())
	fmt.Fprintf(w, "# TYPE halo_shadow_budget_usd gauge\nhalo_shadow_budget_usd %g\n", s.cfg.BudgetUSD)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
