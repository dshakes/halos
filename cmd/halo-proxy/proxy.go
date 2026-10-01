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
	"strings"
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
	kill   *gateway.KillSwitch // nil = no kill switch
	otlp   *gwmetrics.Emitter  // nil = request metrics export off
	m      *metrics
	log    *slog.Logger
}

// routeCtx carries the per-request routing outcome into ReverseProxy.Rewrite.
type routeCtx struct {
	target  *url.URL
	escPath string // escaped request path after model rewrite
	start   time.Time
	ttfb    time.Duration // -1 until upstream headers arrive
}

type ctxKey struct{}

func newProxy(cfg Config, log *slog.Logger) (*Proxy, error) {
	p := &Proxy{cfg: cfg, snap: gateway.NewSnapshot(cfg.Policy), m: newMetrics(), log: log, sigv4: &upstreamauth.Bedrock{}}
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
		Transport:     p.sigv4.Transport(tr), // SigV4 for kind: bedrock upstreams
		FlushInterval: -1,                    // flush every write: SSE / AWS eventstream must not be batched
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
	})
	return mux
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	rc := &routeCtx{start: start, ttfb: -1}
	ring, variant, experiment, upstream, model := "none", "", "", "", ""
	var rewriteErr error
	var gw *gwmetrics.Request // set once the request is a cohort-decided model call
	defer func() {
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		total := time.Since(start)
		if gw != nil {
			gw.Status, gw.Latency = status, total
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
		if rc.ttfb >= 0 {
			attrs = append(attrs, "ttfb_ms", rc.ttfb.Milliseconds())
		}
		if rewriteErr != nil {
			attrs = append(attrs, "rewrite_err", rewriteErr.Error())
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
	if res.Protocol != "" && escPath != gateway.PathCountTokens { // model calls only; token counting would skew latency
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

	target, sigRegion := p.next, ""
	if target == nil && d.Upstream != "" {
		if target, err = parseBase(d.Upstream); err != nil {
			p.log.Error("policy upstream url", "upstream", d.UpstreamName, "err", err)
			writeErr(sw, http.StatusBadGateway, "bad_upstream", "policy upstream is misconfigured")
			return
		}
		// Direct Bedrock: halo-proxy signs with its own AWS identity. A bedrock
		// upstream with no region on a non-AWS host is an orchestrator/SigV4
		// sidecar that signs itself: forwarded as before.
		if up := org.Gateway.Upstreams[d.UpstreamName]; up.Kind == "bedrock" {
			if sigRegion, err = upstreamauth.Region(up.Region, target.Host); err != nil && up.Region != "" {
				p.log.Error("policy upstream region", "upstream", d.UpstreamName, "err", err)
				writeErr(sw, http.StatusBadGateway, "bad_upstream", "policy upstream is misconfigured")
				return
			}
			// Never sign for a host that is not an AWS endpoint or on the
			// operator's signHosts allow list: creds must not reach third parties.
			if sigRegion != "" && !upstreamauth.SignableHost(target.Host, p.cfg.SignHosts) {
				p.log.Error("refusing to sigv4-sign for non-AWS host; add it to signHosts if intended", "upstream", d.UpstreamName, "host", target.Host)
				writeErr(sw, http.StatusBadGateway, "bad_upstream", "policy upstream host is not allowed for signing")
				return
			}
		}
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
	if sigRegion != "" {
		upstreamauth.StripClientAmz(r.Header) // only gateway-set x-amz* may be signed
	}
	for k, v := range d.Headers {
		r.Header.Set(k, v)
	}
	if !p.cfg.ForwardAuth {
		r.Header.Del("Authorization")
		r.Header.Del("x-api-key")
	}
	for k, v := range p.cfg.UpstreamHeaders[d.UpstreamName] {
		r.Header.Set(k, os.ExpandEnv(v))
	}
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(res.Body))
		r.ContentLength = int64(len(res.Body))
		r.Header.Set("Content-Length", fmt.Sprint(len(res.Body)))
		r.Header.Del("Transfer-Encoding")
	}
	rc.target, rc.escPath = target, res.Path

	p.mirrorJob(res, r.Header, escPath, body)

	ctx := context.WithValue(r.Context(), ctxKey{}, rc)
	if sigRegion != "" {
		ctx = upstreamauth.WithBedrock(ctx, sigRegion)
	}
	p.rp.ServeHTTP(sw, r.WithContext(ctx))
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
	sub, err := v.Verify(r)
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
