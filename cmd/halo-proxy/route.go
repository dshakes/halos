package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/gateway/upstreamauth"
	"github.com/dshakes/halos/internal/policy"
)

// RouteConfig tunes failover for multi-target model routes.
type RouteConfig struct {
	// MaxAttempts bounds targets tried per request (default 3).
	MaxAttempts int `yaml:"maxAttempts"`
	// BreakerFailures consecutive failures open a target's circuit (default 5);
	// after BreakerCooldown (default 30s) one probe request tests it.
	BreakerFailures int           `yaml:"breakerFailures"`
	BreakerCooldown time.Duration `yaml:"breakerCooldown"`
}

// errNoTarget: every target's circuit is open (or none could be tried).
var errNoTarget = errors.New("no available upstream target")

// attempt is one fully resolved route target for the current request.
type attempt struct {
	name, kind, model string
	key               string // circuit breaker key: upstream/model
	up                policy.Upstream
	base              *url.URL
	out               gateway.Outbound
	region            string // SigV4 region; "" = not signed by halo-proxy
	timeout           time.Duration
}

// buildAttempts resolves d.Route into sendable attempts from the client's
// original request. Targets that cannot serve this client's wire protocol, are
// misconfigured, or point at a host not allowed to receive credentials are
// skipped (and logged), never sent.
func (p *Proxy) buildAttempts(org *policy.Org, d gateway.Decision, proto, escPath string, body []byte) []attempt {
	var out []attempt
	for _, t := range d.Route {
		skip := func(why string, err error) {
			p.log.Error("route target skipped", "upstream", t.Upstream, "model", t.Model, "reason", why, "err", err)
			p.m.attempt(t.Upstream, "skipped")
		}
		up, ok := org.Gateway.Upstreams[t.Upstream]
		if !ok {
			skip("undefined upstream", nil)
			continue
		}
		if !policy.KindServes(up.Kind, proto) {
			skip("kind cannot serve "+proto, nil)
			continue
		}
		base, err := parseBase(up.Endpoint())
		if err != nil {
			skip("bad url", err)
			continue
		}
		if err := upstreamauth.CheckURL(up, base, p.cfg.UpstreamHosts, p.cfg.AllowInsecureUpstreams); err != nil {
			skip("upstream not allowed", err)
			continue
		}
		a := attempt{name: t.Upstream, kind: up.Kind, model: t.Model, key: t.Upstream + "/" + t.Model, up: up, base: base, timeout: p.cfg.UpstreamHeaderTimeout}
		if t.TimeoutSeconds > 0 {
			a.timeout = time.Duration(t.TimeoutSeconds) * time.Second
		}
		if up.Kind == "bedrock" {
			// Direct Bedrock: halo-proxy signs with its own AWS identity. No region
			// on a non-AWS host is an orchestrator/SigV4 sidecar that signs itself.
			a.region, err = upstreamauth.Region(up.Region, base.Host)
			if err != nil && up.Region != "" {
				skip("bad region", err)
				continue
			}
			if a.region != "" && !upstreamauth.SignableHost(base.Host, p.cfg.SignHosts) {
				skip("refusing to sigv4-sign for non-AWS host; add it to signHosts if intended", nil)
				continue
			}
		}
		if a.out, err = gateway.BuildOutbound(proto, up, t.Model, escPath, body); err != nil {
			skip("translate request", err)
			continue
		}
		out = append(out, a)
	}
	return out
}

// routeTransport walks the attempt list of a routed request, else passes through.
type routeTransport struct {
	p    *Proxy
	base http.RoundTripper
}

func (t routeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if rc, _ := req.Context().Value(ctxKey{}).(*routeCtx); rc != nil && len(rc.attempts) > 0 {
		return t.p.failover(t.base, req, rc)
	}
	return t.base.RoundTrip(req)
}

// failover tries attempts in order until one answers with something other than
// a connect error, 5xx or 429. It runs inside RoundTrip, i.e. before any
// response byte reaches the client: once a response is returned its stream is
// never retried. The last failure is returned as-is when nothing succeeds.
func (p *Proxy) failover(base http.RoundTripper, req *http.Request, rc *routeCtx) (*http.Response, error) {
	multi := len(rc.attempts) > 1 // a lone target gains nothing from a breaker
	maxTries := p.cfg.Route.MaxAttempts
	if maxTries <= 0 {
		maxTries = 3
	}
	var held *http.Response
	var heldErr error
	tried := 0
	for i := range rc.attempts {
		a := &rc.attempts[i]
		if tried >= maxTries {
			break
		}
		if multi && !p.breaker.Allow(a.key) {
			p.m.attempt(a.kind, "circuit_open")
			continue
		}
		tried++
		resp, err := p.try(base, req, a)
		if cerr := req.Context().Err(); cerr != nil { // client went away: no verdict on the target
			if multi {
				p.breaker.Cancel(a.key)
			}
			closeBody(held)
			closeBody(resp)
			return nil, cerr
		}
		failed := err != nil || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if multi {
			p.breaker.Done(a.key, !failed)
		}
		closeBody(held)
		rc.served, rc.failover = a, i > 0
		if !failed {
			p.m.attempt(a.kind, "ok")
			return resp, nil
		}
		p.m.attempt(a.kind, "failed")
		held, heldErr = resp, err
		if err != nil {
			p.log.Warn("upstream attempt failed", "upstream", a.name, "model", a.model, "err", err)
		}
	}
	if held != nil {
		return held, nil
	}
	if heldErr != nil {
		return nil, heldErr
	}
	return nil, errNoTarget
}

func closeBody(r *http.Response) {
	if r != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4<<10))
		_ = r.Body.Close()
	}
}

// try sends req to one target: provider URL, translated body, provider auth.
// The target's timeout covers connect + response headers only.
func (p *Proxy) try(base http.RoundTripper, req *http.Request, a *attempt) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	if a.timeout > 0 {
		t := time.AfterFunc(a.timeout, cancel)
		defer t.Stop()
	}
	out := req.Clone(ctx)
	h := out.Header
	if a.region != "" {
		upstreamauth.StripClientAmz(h)
		out = out.WithContext(upstreamauth.WithBedrock(ctx, a.region))
	}
	for k, v := range p.cfg.UpstreamHeaders[a.name] {
		h.Set(k, os.ExpandEnv(v))
	}
	if err := p.authenticateUpstream(ctx, h, a); err != nil {
		cancel()
		return nil, fmt.Errorf("upstream %s: %w", a.name, err)
	}
	u := out.URL
	u.Scheme, u.Host = a.base.Scheme, a.base.Host
	full := strings.TrimRight(a.base.EscapedPath(), "/") + a.out.Path
	u.Path, _ = url.PathUnescape(full)
	u.RawPath = full
	if a.out.SetQuery {
		u.RawQuery = a.out.RawQuery
	}
	out.Host = ""
	out.Body = io.NopCloser(bytes.NewReader(a.out.Body))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(a.out.Body)), nil }
	out.ContentLength = int64(len(a.out.Body))
	h.Del("Content-Length")
	h.Del("Transfer-Encoding")

	resp, err := base.RoundTrip(out)
	if err != nil {
		timedOut := req.Context().Err() == nil && ctx.Err() != nil
		cancel()
		if timedOut {
			return nil, fmt.Errorf("upstream %s: no response headers within %s", a.name, a.timeout)
		}
		return nil, fmt.Errorf("upstream %s: %w", a.name, err)
	}
	if a.out.SSE && resp.StatusCode == http.StatusOK {
		resp.Body = gateway.EventStreamToSSE(resp.Body)
		resp.Header.Set("Content-Type", "text/event-stream")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// authenticateUpstream installs the target's own credential and removes the
// caller's: halo-proxy's provider credentials never come from the client.
func (p *Proxy) authenticateUpstream(ctx context.Context, h http.Header, a *attempt) error {
	switch {
	case a.kind == "vertex":
		ts, err := p.vertexTokens()
		if err != nil {
			return err
		}
		tok, err := ts.Token(ctx)
		if err != nil {
			return err
		}
		upstreamauth.SetBearer(h, tok)
	case upstreamauth.Credentialed(a.up):
		secret, err := upstreamauth.Secret(a.up.Credential, p.getenv)
		if err != nil {
			return err
		}
		upstreamauth.SetAuth(h, a.kind, a.up.Credential, secret)
	}
	return nil
}

func (p *Proxy) vertexTokens() (upstreamauth.TokenSource, error) {
	p.vertexOnce.Do(func() {
		if p.vertexTS == nil {
			p.vertexTS, p.vertexErr = upstreamauth.DefaultTokenSource(p.getenv)
		}
	})
	return p.vertexTS, p.vertexErr
}

// cancelBody releases the attempt's context when the response body is done.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
