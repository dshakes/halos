package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/gateway/upstreamauth"
	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/shadow"
	"github.com/dshakes/halos/internal/telemetry/gwmetrics"
)

// Proxy is the stack-agnostic traffic plane: verify identity, decide cohort,
// rewrite the model, mirror eligible requests, then forward. Response bodies
// are streamed, never buffered.
type Proxy struct {
	cfg    Config
	snap   *gateway.Snapshot
	ids    identity.Resolver
	next   *url.URL // nil unless nextHop
	def    *url.URL // nil unless defaultUpstream
	rp     *httputil.ReverseProxy
	mirror *shadow.Mirrorer // nil = mirroring off
	sigv4  *upstreamauth.Bedrock
	kill   *gateway.KillSwitch    // nil = no kill switch
	pc     *gateway.PostureClient // nil = posture gate off
	otlp   *gwmetrics.Emitter     // nil = request metrics export off
	m      *metrics
	log    *slog.Logger

	breaker    *gateway.Breaker
	getenv     func(string) string
	vertexOnce sync.Once
	vertexTS   upstreamauth.TokenSource // nil = Google ADC, resolved on first use
	vertexErr  error
}

// routeCtx carries the per-request routing outcome into ReverseProxy.Rewrite.
type routeCtx struct {
	target  *url.URL
	escPath string // escaped request path after model rewrite
	start   time.Time
	ttfb    time.Duration // -1 until upstream headers arrive

	// Routed model calls: the failover list and which target answered.
	attempts []attempt
	served   *attempt
	failover bool // an earlier target failed or was skipped
}

type ctxKey struct{}

type bufPool struct{ sync.Pool }

func (b *bufPool) Get() []byte  { return *b.Pool.Get().(*[]byte) }
func (b *bufPool) Put(p []byte) { b.Pool.Put(&p) }

var copyBufs = &bufPool{sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}}

func newProxy(cfg Config, log *slog.Logger) (*Proxy, error) {
	p := &Proxy{cfg: cfg, snap: gateway.NewSnapshot(cfg.Policy), m: newMetrics(), log: log, sigv4: &upstreamauth.Bedrock{},
		breaker: &gateway.Breaker{Threshold: cfg.Route.BreakerFailures, Cooldown: cfg.Route.BreakerCooldown}, getenv: os.Getenv}
	var err error
	if cfg.NextHop != "" {
		if p.next, err = parseBase(cfg.NextHop); err != nil {
			return nil, fmt.Errorf("halo-proxy: nextHop: %w", err)
		}
	}
	if cfg.DefaultUpstream != "" {
		if p.def, err = parseBase(cfg.DefaultUpstream); err != nil {
			return nil, fmt.Errorf("halo-proxy: defaultUpstream: %w", err)
		}
	}
	if cfg.Shadow.URL != "" {
		if p.mirror, err = shadow.NewMirrorer(cfg.Shadow.URL, cfg.Shadow.Token, 32); err != nil {
			return nil, fmt.Errorf("halo-proxy: shadow: %w", err)
		}
	}
	if p.kill, err = cfg.KillSwitch.build(log); err != nil {
		return nil, err
	}
	if p.pc, err = cfg.Posture.build(log); err != nil {
		return nil, err
	}
	if p.otlp, err = gwmetrics.New(cfg.Telemetry); err != nil {
		return nil, fmt.Errorf("halo-proxy: telemetry: %w", err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true // h2 to TLS upstreams; falls back to 1.1
	tr.DisableCompression = true
	tr.ResponseHeaderTimeout = cfg.UpstreamHeaderTimeout
	tr.MaxIdleConnsPerHost = 64
	p.rp = &httputil.ReverseProxy{
		Rewrite:       p.rewrite,
		BufferPool:    copyBufs,                                          // ReverseProxy otherwise allocates a fresh 32 KiB copy buffer per response
		Transport:     routeTransport{p: p, base: p.sigv4.Transport(tr)}, // SigV4 for kind: bedrock upstreams; failover for routed calls
		FlushInterval: -1,                                                // flush every write: SSE / AWS eventstream must not be batched
		ErrorHandler:  p.upstreamError,
		ErrorLog:      slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		ModifyResponse: func(resp *http.Response) error {
			if rc, ok := resp.Request.Context().Value(ctxKey{}).(*routeCtx); ok {
				rc.ttfb = time.Since(rc.start)
			}
			return nil
		},
	}
	return p, nil
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	rc := pr.In.Context().Value(ctxKey{}).(*routeCtx)
	u := pr.Out.URL
	u.Scheme, u.Host = rc.target.Scheme, rc.target.Host
	full := strings.TrimRight(rc.target.EscapedPath(), "/") + rc.escPath
	u.Path, _ = url.PathUnescape(full)
	u.RawPath = full
	pr.Out.Host = "" // Host follows the target
	pr.SetXForwarded()
}

func (p *Proxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	p.log.Warn("upstream error", "path", r.URL.Path, "err", err)
	if errors.Is(err, context.Canceled) {
		return // client went away; nothing to write
	}
	if errors.Is(err, errNoTarget) {
		writeErr(w, http.StatusServiceUnavailable, "no_available_target", "every upstream target for this model is unavailable")
		return
	}
	if errors.Is(err, upstreamauth.ErrNoSecret) {
		writeErr(w, http.StatusBadGateway, "upstream_auth_error", "halo-proxy has no provider credential for the upstream")
		return
	}
	if errors.Is(err, upstreamauth.ErrCredentials) {
		writeErr(w, http.StatusBadGateway, "upstream_auth_error", "halo-proxy has no AWS credentials to sign the Bedrock request")
		return
	}
	writeErr(w, http.StatusBadGateway, "upstream_error", "upstream request failed")
}

// writeReject answers a gateway Rejection in the caller's wire format.
func writeReject(w http.ResponseWriter, r *gateway.Rejection) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.Status)
	_, _ = w.Write(r.JSON())
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"type":%q,"message":%q}}`+"\n", code, msg)
}

// AdminHandler serves /healthz and /metrics. It is mounted only on the admin
// listener: the public listener serves proxied model traffic and nothing else.
func (p *Proxy) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { p.health(w) })
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var d, f int64
		if p.mirror != nil {
			d, f = p.mirror.Dropped(), p.mirror.Failed()
		}
		p.m.write(w, d, f)
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		fmt.Fprintf(w, "# TYPE go_goroutines gauge\ngo_goroutines %d\n# TYPE go_memstats_heap_inuse_bytes gauge\ngo_memstats_heap_inuse_bytes %d\n", runtime.NumGoroutine(), ms.HeapInuse)
	})
	return mux
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	rc := &routeCtx{start: start, ttfb: -1}
	ring, variant, experiment, upstream, model := "none", "", "", "", ""
	var rewriteErr error
	var gates []string        // failed or unknown gate checks, for the request log
	var gw *gwmetrics.Request // set once the request is a cohort-decided model call
	defer func() {
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		total := time.Since(start)
		if a := rc.served; a != nil {
			upstream, model = a.name, a.model // the target that answered, not the planned first
		}
		if gw != nil {
			gw.Status, gw.Latency = status, total
			if a := rc.served; a != nil { // routed call: provider kind and upstream/model are policy-bounded, never per-user
				gw.Model, gw.Provider, gw.Target, gw.Failover = a.model, a.kind, a.key, rc.failover
			}
			p.otlp.Record(*gw)
		}
		ttfb := -1.0
		if rc.ttfb >= 0 {
			ttfb = rc.ttfb.Seconds()
		}
		p.m.observe(ring, variant, status, ttfb, total.Seconds())
		// Never log bodies, headers or query strings.
		attrs := []any{"method", r.Method, "path", r.URL.Path, "status", status, "bytes", sw.n,
			"duration_ms", total.Milliseconds(), "ring", ring, "remote", r.RemoteAddr}
		if variant != "" {
			attrs = append(attrs, "experiment", experiment, "variant", variant)
		}
		if upstream != "" {
			attrs = append(attrs, "upstream", upstream)
		}
		if model != "" {
			attrs = append(attrs, "upstream_model", model)
		}
		if a := rc.served; a != nil {
			attrs = append(attrs, "provider", a.kind, "failover", rc.failover)
		}
		if rc.ttfb >= 0 {
			attrs = append(attrs, "ttfb_ms", rc.ttfb.Milliseconds())
		}
		if rewriteErr != nil {
			attrs = append(attrs, "rewrite_err", rewriteErr.Error())
		}
		if len(gates) > 0 {
			attrs = append(attrs, "gates", strings.Join(gates, "; "))
		}
		p.log.Info("request", attrs...)
	}()

	org, err := p.snap.Get()
	if err != nil {
		p.log.Warn("policy snapshot", "err", err)
	}
	if org == nil && p.next == nil && p.def == nil {
		writeErr(sw, http.StatusServiceUnavailable, "policy_unavailable", "policy snapshot not loaded")
		return
	}

	sub, ok := p.authenticate(sw, r, org)
	if !ok {
		return
	}

	// Body: bounded for every request; fully read only for model calls, which
	// need inspection/rewrite. Oversize is a hard 413, never a silent no-rewrite.
	escPath := r.URL.EscapedPath()
	if r.ContentLength > p.cfg.MaxBodyBytes {
		writeErr(sw, http.StatusRequestEntityTooLarge, "request_too_large", fmt.Sprintf("request body exceeds %d bytes", p.cfg.MaxBodyBytes))
		return
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(sw, r.Body, p.cfg.MaxBodyBytes)
		if gateway.ProtocolForPath(escPath) != "" {
			body, err = io.ReadAll(r.Body)
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				writeReject(sw, gateway.RejectTooLarge(escPath))
				return
			}
			if err != nil {
				writeErr(sw, http.StatusBadRequest, "bad_request", "could not read request body")
				return
			}
		}
	}

	res := gateway.PrepareVerified(p.kill.Apply(org), sub, r.Header, escPath, body) // killed experiments: control, no shadow
	d := res.Decision
	ring, variant, experiment, upstream, model = d.Ring, d.Variant, d.Experiment, d.UpstreamName, d.UpstreamModel
	rewriteErr = res.RewriteErr
	if res.Protocol != "" && !gateway.IsCountTokens(escPath) { // model calls only; token counting would skew latency
		gw = &gwmetrics.Request{Ring: d.Ring, Release: d.Release, Experiment: d.Experiment, Variant: d.Variant,
			Harness: gateway.HarnessFromUA(r.Header.Get("User-Agent")), Model: d.UpstreamModel} // unit = verified subject only, never the client session header
		if sub != nil {
			gw.Subject = sub.ID
		}
	}
	if res.Reject != nil {
		writeReject(sw, res.Reject)
		return
	}
	if res.Protocol != "" {
		var rej *gateway.Rejection
		if gates, rej = p.gate(r, org, d.Ring, sub, res.Protocol); rej != nil {
			writeReject(sw, rej)
			return
		}
	}

	target := p.next
	// Every routed model call (d.Route non-empty, which is whenever the policy names an upstream for
	// the alias) walks the attempt list: per-target URL, auth, SigV4 and failover live in route.go.
	// Only nextHop / defaultUpstream traffic reaches the transport without attempts.
	var attempts []attempt
	if p.next == nil && len(d.Route) > 0 {
		if attempts = p.buildAttempts(org, d, res.Protocol, escPath, body); len(attempts) == 0 {
			writeErr(sw, http.StatusBadGateway, "bad_upstream", "policy upstream is misconfigured")
			return
		}
		target = attempts[0].base
	}
	if target == nil {
		target = p.def
	}
	if target == nil {
		writeErr(sw, http.StatusBadGateway, "no_route", "no upstream configured for this request")
		return
	}

	// Header hygiene: drop every client x-halo-* and the identity/groups
	// headers (the subject is already derived), stamp the gateway-owned ones.
	for _, n := range append(res.ClearHeaders, p.cfg.identityOptions().HeaderNames(org)...) {
		r.Header.Del(n)
	}
	r.Trailer = nil // request trailers are client headers too (x-halo-*, identity, credentials): never forwarded
	headers := p.cfg.UpstreamHeaders[d.UpstreamName]
	if attempts != nil {
		headers = nil // applied per attempt: one target's key must not leak to the next
	}
	for k, v := range d.Headers {
		r.Header.Set(k, v)
	}
	if res.Protocol == gateway.ProtoGemini {
		r.Header.Del("x-gemini-api-privileged-user-id") // per-install id gemini-cli sends; not for the provider
	}
	if !p.cfg.ForwardAuth {
		upstreamauth.StripClientCredentials(r.Header)
		if res.Protocol == gateway.ProtoGemini { // the Gemini API also takes the key as ?key=
			q := r.URL.Query()
			q.Del("key")
			r.URL.RawQuery = q.Encode()
		}
	}
	for k, v := range headers {
		r.Header.Set(k, os.ExpandEnv(v))
	}
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(res.Body))
		r.ContentLength = int64(len(res.Body))
		r.Header.Set("Content-Length", fmt.Sprint(len(res.Body)))
		r.Header.Del("Transfer-Encoding")
	}
	rc.target, rc.escPath, rc.attempts = target, res.Path, attempts

	p.mirrorJob(res, r.Header, escPath, body)

	ctx := context.WithValue(r.Context(), ctxKey{}, rc)
	p.rp.ServeHTTP(sw, r.WithContext(ctx))
}

// gate applies the ring's posture and version gates to a model call. It
// returns the outcomes for the request log and the 403 to answer, if any gate
// is in enforce mode and failed. Warn mode and unknown posture only count.
func (p *Proxy) gate(r *http.Request, org *policy.Org, ring string, sub *policy.Subject, proto string) ([]string, *gateway.Rejection) {
	var out []string
	var rej *gateway.Rejection
	pf, unknown := gateway.CheckPosture(r.Context(), p.pc, org, ring, sub)
	if unknown {
		p.m.gate(gateway.GatePosture, ring, "unknown")
		out = append(out, "posture unknown")
	}
	for _, f := range []*gateway.Finding{pf, gateway.CheckVersion(org, ring, r.Header.Get("User-Agent"))} {
		if f == nil {
			continue
		}
		p.m.gate(f.Gate, ring, f.Mode)
		out = append(out, f.Gate+" "+f.Mode+": "+f.Reason)
		if rej == nil {
			rej = f.Reject(proto)
		}
	}
	return out, rej
}

// authenticate returns the verified subject (nil = anonymous). ok=false means
// a response was already written.
func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request, org *policy.Org) (*policy.Subject, bool) {
	v, err := p.ids.Get(p.cfg.identityOptions(), org)
	if err != nil {
		p.log.Error("identity misconfigured", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "identity_unavailable", "identity verification is not configured")
		return nil, false
	}
	if v == nil { // mode none
		return nil, true
	}
	vr := r
	if gateway.ProtocolForPath(r.URL.EscapedPath()) == gateway.ProtoGemini && identity.BearerToken(r.Header) == "" {
		// gemini-cli cannot send Authorization to a custom base URL: its
		// GEMINI_API_KEY arrives as x-goog-api-key. Accepted on this wire only,
		// verified exactly like a bearer token, and stripped before forwarding.
		if k := strings.TrimSpace(r.Header.Get("x-goog-api-key")); k != "" {
			vr = r.Clone(r.Context())
			vr.Header.Set("Authorization", "Bearer "+k)
		}
	}
	sub, err := v.Verify(vr)
	if err == nil {
		return &sub, true
	}
	p.m.authFailed()
	if errors.Is(err, identity.ErrAmbiguous) {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", "identity header sent more than once")
		return nil, false
	}
	if p.cfg.Identity.AllowAnonymous {
		return nil, true
	}
	if !errors.Is(err, identity.ErrNoCredentials) {
		p.log.Info("identity rejected", "err", err.Error(), "remote", r.RemoteAddr)
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="halos"`)
	writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid or missing credentials")
	return nil, false
}

// mirrorJob queues first-turn shadow copies. h already holds no x-halo-*; only
// the shadow.ReplayHeaders allowlist is sent, never client credentials, and
// never an upstream: halo-shadow resolves both sides from its own policy.
func (p *Proxy) mirrorJob(res gateway.Result, h http.Header, path string, body []byte) {
	if p.mirror == nil {
		return
	}
	for _, j := range shadow.Jobs(res, h, path, body, p.cfg.Shadow.MaxBytes) {
		p.mirror.Submit(j)
	}
}

func (p *Proxy) health(w http.ResponseWriter) {
	org, err := p.snap.Get()
	if org == nil {
		msg := "policy snapshot not loaded"
		if err != nil {
			msg += ": " + err.Error()
		}
		http.Error(w, msg, http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

// statusWriter records status and bytes while keeping streaming intact.
type statusWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (s *statusWriter) WriteHeader(c int) {
	if s.status == 0 {
		s.status = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.n += int64(n)
	return n, err
}

func (s *statusWriter) Flush() { _ = http.NewResponseController(s.ResponseWriter).Flush() }

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
