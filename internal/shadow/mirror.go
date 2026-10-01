package shadow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/halos-dev/halos/internal/gateway"
)

// Mirrorer is the halo-kong side: Submit never blocks the request path. Jobs go
// through a small bounded queue to a single sender; when full they're dropped
// and counted.
type Mirrorer struct {
	url, token string
	q          chan Job
	client     *http.Client
	dropped    atomic.Int64
	failed     atomic.Int64
}

// checkMirrorURL requires an absolute http(s) URL with a host and no
// userinfo, so a bad shadow_url fails at config time instead of per job.
// ponytail: plain http is allowed to any host because the shipped compose and
// Helm deployments reach halo-shadow over in-cluster http; tighten to
// https-or-loopback once those terminate TLS.
func checkMirrorURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("shadow: mirror url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("shadow: mirror url %q must be http(s)://host[:port]/path without userinfo", u.Redacted())
	}
	return nil
}

// NewMirrorer validates url and starts the single sender goroutine.
func NewMirrorer(url, token string, queue int) (*Mirrorer, error) {
	if err := checkMirrorURL(url); err != nil {
		return nil, err
	}
	if queue <= 0 {
		queue = 32
	}
	m := &Mirrorer{url: url, token: token, q: make(chan Job, queue), client: &http.Client{Timeout: 5 * time.Second}}
	go m.loop()
	return m, nil
}

// Submit reports whether the job was queued.
func (m *Mirrorer) Submit(j Job) bool {
	select {
	case m.q <- j:
		return true
	default:
		m.dropped.Add(1)
		return false
	}
}

func (m *Mirrorer) Dropped() int64 { return m.dropped.Load() }
func (m *Mirrorer) Failed() int64  { return m.failed.Load() }

// ponytail: single sender goroutine for the process lifetime; add Close if the plugin ever needs to unload cleanly.
func (m *Mirrorer) loop() {
	for j := range m.q {
		if err := m.send(j); err != nil {
			m.failed.Add(1)
		}
	}
}

func (m *Mirrorer) send(j Job) error {
	b, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("shadow: marshal job: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("shadow: build mirror request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TokenHeader, m.token)
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("shadow: post mirror job: %w", err)
	}
	_ = resp.Body.Close() // status is all we read
	if resp.StatusCode >= 300 {
		return fmt.Errorf("shadow: mirror job status %d", resp.StatusCode)
	}
	return nil
}

var (
	mirrorMu sync.Mutex
	mirrors  = map[string]*Mirrorer{}
)

// SharedMirrorer returns one Mirrorer per halo-shadow URL (Kong instantiates a
// plugin config per route/service; they share the queue).
func SharedMirrorer(url, token string) (*Mirrorer, error) {
	mirrorMu.Lock()
	defer mirrorMu.Unlock()
	k := url + "\x00" + token
	if m, ok := mirrors[k]; ok {
		return m, nil
	}
	m, err := NewMirrorer(url, token, 32)
	if err != nil {
		return nil, err
	}
	mirrors[k] = m
	return m, nil
}

// Jobs builds the mirror jobs for a prepared gateway request: one per shadow
// target, only the ReplayHeaders allowlist (never client credentials) and
// never an upstream (halo-shadow resolves both sides from its own policy). It
// returns nil when nothing should be mirrored or body exceeds maxBytes.
func Jobs(res gateway.Result, h http.Header, path string, body []byte, maxBytes int) []Job {
	d := res.Decision
	if len(d.Shadow) == 0 || len(body) == 0 || len(body) > maxBytes {
		return nil
	}
	hdrs := map[string]string{}
	for k := range ReplayHeaders {
		if v := h.Get(k); v != "" {
			hdrs[k] = v
		}
	}
	sid := gateway.SessionID(h)
	jobs := make([]Job, 0, len(d.Shadow))
	for _, t := range d.Shadow {
		jobs = append(jobs, Job{
			Experiment: t.Experiment, Variant: t.Variant, Ring: d.Ring, SessionID: sid,
			Protocol: res.Protocol, Method: http.MethodPost, Path: path, Headers: hdrs, Body: body,
		})
	}
	return jobs
}
