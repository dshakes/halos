package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DLP audit reporting (ADR-0033): gateways post findings to halo-server,
// which appends one audit entry per event to its hash-chained log, so the
// ADR-0016 SIEM exporter forwards them with everything else.

// DLP reporter bounds.
const (
	DefaultDLPFlush = 5 * time.Second
	MaxDLPEvents    = 500 // per batch; halo-server refuses more
	maxDLPQueue     = 10_000
	dlpDedupWindow  = time.Hour
	maxDLPDedup     = 50_000
)

// Directions of a DLP event.
const (
	DLPRequest  = "request"
	DLPResponse = "response"
)

// DLPEvent is one finding as audited: who, where, what kind, never the secret.
type DLPEvent struct {
	At        time.Time `json:"at"`
	Gateway   string    `json:"gateway"`           // halo-proxy | halo-kong
	Subject   string    `json:"subject,omitempty"` // verified caller; "" = anonymous
	Chain     string    `json:"chain,omitempty"`   // verified delegation chain (ADR-0024)
	Ring      string    `json:"ring,omitempty"`
	Unit      string    `json:"unit,omitempty"`
	Protocol  string    `json:"protocol"`
	Harness   string    `json:"harness,omitempty"`
	Direction string    `json:"direction"` // DLPRequest | DLPResponse
	Action    string    `json:"action"`    // monitor | redact | block
	DLPFinding
}

// DLPBatch is halo-server's POST /api/v1/gateway/dlp/events body. Batch is
// stable across retries of the same events.
type DLPBatch struct {
	Batch  string     `json:"batch"`
	Events []DLPEvent `json:"events"`
}

// DLPEvents builds the audit events for a request scan.
func DLPEvents(rep *DLPReport, base DLPEvent) []DLPEvent {
	if rep == nil {
		return nil
	}
	out := make([]DLPEvent, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		e := base
		e.Direction, e.DLPFinding = DLPRequest, f
		e.Action = rep.SecretAction
		if f.Kind == DLPInjection {
			e.Action = rep.InjectionAction
		}
		if e.Action == "block" && rep.Blocked != f.Kind {
			e.Action = "monitor" // a block of the other kind refused the request
		}
		out = append(out, e)
	}
	return out
}

// DLPReporter queues events and posts them to halo-server. The zero of
// *DLPReporter (nil) drops everything, so callers need no "configured" branch.
// Report never blocks the request path: past maxDLPQueue events are dropped
// and counted. The same finding (subject, detector, hash, location,
// direction) is reported once per hour; a conversation carries its history on
// every turn.
type DLPReporter struct {
	URL, Token string
	Flush      time.Duration
	Client     *http.Client
	Log        *slog.Logger
	Now        func() time.Time

	mu       sync.Mutex
	queue    []DLPEvent
	inflight *DLPBatch
	seen     map[string]time.Time

	sent, failed, dropped, deduped atomic.Int64
}

// NewDLPReporter validates the config (https unless loopback or allowInsecureInCluster).
func NewDLPReporter(url, token string, flush time.Duration, log *slog.Logger, allowInsecureInCluster bool) (*DLPReporter, error) {
	if url == "" || token == "" {
		return nil, errors.New("gateway: dlp audit needs url and token")
	}
	if err := checkKillURL(url, allowInsecureInCluster); err != nil {
		return nil, fmt.Errorf("gateway: dlp url: %w", err)
	}
	if flush <= 0 {
		flush = DefaultDLPFlush
	}
	return &DLPReporter{URL: strings.TrimRight(url, "/"), Token: token, Flush: flush, Log: log}, nil
}

func (r *DLPReporter) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Report queues events. Safe for concurrent use; nil-safe.
func (r *DLPReporter) Report(evs ...DLPEvent) {
	if r == nil || len(evs) == 0 {
		return
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil || len(r.seen) >= maxDLPDedup {
		r.seen = map[string]time.Time{} // ponytail: forget everything when full; duplicates are harmless
	}
	for _, e := range evs {
		k := strings.Join([]string{e.Subject, e.Detector, e.Hash, e.Location, e.Direction, e.Action}, "\x00")
		if t, ok := r.seen[k]; ok && now.Sub(t) < dlpDedupWindow {
			r.deduped.Add(1)
			continue
		}
		if len(r.queue) >= maxDLPQueue {
			r.dropped.Add(1)
			continue
		}
		r.seen[k] = now
		r.queue = append(r.queue, e)
	}
}

// Run posts every Flush until ctx ends. Call FlushNow after it returns.
func (r *DLPReporter) Run(ctx context.Context) {
	if r == nil {
		return
	}
	t := time.NewTicker(r.Flush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.FlushNow(ctx); err != nil && r.Log != nil && ctx.Err() == nil {
				r.Log.Warn("dlp audit report failed; retrying next interval", "err", err)
			}
			r.prune()
		}
	}
}

func (r *DLPReporter) prune() {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, t := range r.seen {
		if now.Sub(t) >= dlpDedupWindow {
			delete(r.seen, k)
		}
	}
}

// FlushNow sends queued events in batches until none is left or a send
// fails; a failed batch is resent with the same id.
func (r *DLPReporter) FlushNow(ctx context.Context) error {
	if r == nil {
		return nil
	}
	for {
		r.mu.Lock()
		if r.inflight == nil && len(r.queue) > 0 {
			n := min(len(r.queue), MaxDLPEvents)
			r.inflight = &DLPBatch{Batch: newBatchID(), Events: append([]DLPEvent(nil), r.queue[:n]...)}
			r.queue = append(r.queue[:0], r.queue[n:]...)
		}
		b := r.inflight
		r.mu.Unlock()
		if b == nil {
			return nil
		}
		if err := r.post(ctx, b); err != nil {
			r.failed.Add(1)
			if !errors.Is(err, errDLPRefused) {
				return err
			}
			// halo-server refused the batch itself: resending cannot help, and it must not hold back the rest.
			r.dropped.Add(int64(len(b.Events)))
			if r.Log != nil {
				r.Log.Error("dlp audit batch refused by halo-server; dropped", "err", err, "events", len(b.Events))
			}
			r.mu.Lock()
			r.inflight = nil
			r.mu.Unlock()
			continue
		}
		r.sent.Add(int64(len(b.Events)))
		r.mu.Lock()
		r.inflight = nil
		r.mu.Unlock()
	}
}

// Counters for /metrics: events sent, failed posts, events dropped (queue
// full) and deduplicated.
func (r *DLPReporter) Counters() (sent, failed, dropped, deduped int64) {
	if r == nil {
		return 0, 0, 0, 0
	}
	return r.sent.Load(), r.failed.Load(), r.dropped.Load(), r.deduped.Load()
}

func (r *DLPReporter) post(ctx context.Context, b *DLPBatch) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("dlp events: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL+"/events", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("dlp events: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := r.Client
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("dlp events: %w", err)
	}
	_ = resp.Body.Close() // status only
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusUnprocessableEntity, resp.StatusCode == http.StatusBadRequest, resp.StatusCode == http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w: HTTP %d", errDLPRefused, resp.StatusCode)
	}
	return fmt.Errorf("dlp events: HTTP %d", resp.StatusCode)
}

// errDLPRefused: halo-server rejected the batch's content (not an outage).
var errDLPRefused = errors.New("dlp events: batch refused")
