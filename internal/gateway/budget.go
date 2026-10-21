package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/budget"
)

// Budget client defaults (ADR-0017).
const (
	DefaultBudgetTTL   = 30 * time.Second // a verdict is reused this long per principal
	DefaultBudgetGrace = 15 * time.Minute // a cached verdict outlives an unreachable halo-server this long
	DefaultBudgetFlush = 5 * time.Second  // usage report interval

	maxBudgetEntries = 100_000 // cached verdicts
	maxBudgetPending = 100_000 // unreported (principal, minute) records; beyond this usage is dropped and counted
	maxBudgetBatch   = 2_000   // records per report
	maxBudgetBody    = 1 << 20
)

// BudgetCheck is halo-server's POST <url>/check body.
type BudgetCheck struct {
	budget.Principal
}

// BudgetVerdict is halo-server's answer: every counter the principal is charged to.
type BudgetVerdict struct {
	Budgets []budget.Status `json:"budgets"`
}

// BudgetUsage is halo-server's POST <url>/usage body. Batch is stable across
// retries so the server applies a batch once.
type BudgetUsage struct {
	Batch   string          `json:"batch"`
	Records []budget.Record `json:"records"`
}

// BudgetClient is one halo-proxy replica's side of the budget design:
// halo-server holds the authoritative counters; the replica caches each
// principal's verdict for TTL and reports its own usage every Flush. Between
// refreshes the replica adds the usage it has seen to the cached verdict, so
// one busy caller cannot outrun the cache on a single replica.
type BudgetClient struct {
	URL, Token        string // URL: .../api/v1/gateway/budget
	TTL, Grace, Flush time.Duration
	Client            *http.Client
	Now               func() time.Time
	Log               *slog.Logger

	mu        sync.Mutex
	cache     map[string]*budgetEntry
	pending   map[pendingKey]*budget.Record
	unflushed map[string]budget.Spend // per principal: pending + in flight, not yet in any verdict
	inflight  *BudgetUsage

	reported, reportErrs, dropped atomic.Int64
}

type budgetEntry struct {
	st    []budget.Status
	at    time.Time
	local budget.Spend // usage this replica saw since the verdict was fetched
}

type pendingKey struct {
	principal string
	minute    int64
}

// NewBudgetClient validates the config (https unless loopback or allowInsecureInCluster).
func NewBudgetClient(url, token string, ttl, grace, flush time.Duration, log *slog.Logger, allowInsecureInCluster bool) (*BudgetClient, error) {
	if url == "" || token == "" {
		return nil, errors.New("gateway: budgets need url and token")
	}
	if err := checkKillURL(url, allowInsecureInCluster); err != nil {
		return nil, fmt.Errorf("gateway: budgets url: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultBudgetTTL
	}
	if grace <= 0 {
		grace = DefaultBudgetGrace
	}
	if flush <= 0 {
		flush = DefaultBudgetFlush
	}
	return &BudgetClient{URL: strings.TrimRight(url, "/"), Token: token, TTL: ttl, Grace: grace, Flush: flush, Log: log}, nil
}

// Time is the client's clock (Now, or the wall clock).
func (c *BudgetClient) Time() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func principalKey(p budget.Principal) string {
	g := slices.Clone(p.Groups)
	slices.Sort(g)
	return p.Subject + "\x00" + p.Ring + "\x00" + strings.Join(g, "\x00")
}

// Check returns the counters p is charged to, with this replica's unreported
// usage added. known=false when halo-server could not be asked and no
// verdict younger than Grace is cached.
// ponytail: concurrent misses for one principal each call halo-server, as in
// PostureClient; add singleflight if a burst after TTL expiry shows up.
func (c *BudgetClient) Check(ctx context.Context, p budget.Principal) (st []budget.Status, known bool) {
	k, now := principalKey(p), c.Time()
	c.mu.Lock()
	e := c.cache[k]
	if e != nil && now.Sub(e.at) < c.TTL {
		st = e.view()
		c.mu.Unlock()
		return st, true
	}
	c.mu.Unlock()
	v, err := c.check(ctx, p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		stale := e != nil && now.Sub(e.at) < c.Grace
		if c.Log != nil {
			c.Log.Warn("budget lookup failed", "err", err, "cached", stale)
		}
		if stale {
			return e.view(), true
		}
		return nil, false
	}
	if c.cache == nil {
		c.cache = map[string]*budgetEntry{}
	}
	if len(c.cache) >= maxBudgetEntries {
		for ck, old := range c.cache { // ponytail: O(n) sweep when full, as in PostureClient
			if now.Sub(old.at) >= c.Grace {
				delete(c.cache, ck)
			}
		}
		if len(c.cache) >= maxBudgetEntries {
			clear(c.cache)
		}
	}
	// Usage not yet reported is in no server verdict: carry it over.
	e = &budgetEntry{st: v.Budgets, at: now, local: c.unflushed[k]}
	c.cache[k] = e
	return e.view(), true
}

func (e *budgetEntry) view() []budget.Status {
	out := slices.Clone(e.st)
	for i := range out {
		out[i].SpentUSD += e.local.USD
		out[i].SpentTokens += e.local.Tokens
	}
	return out
}

// Record queues usage for the next report and charges it to p's cached verdict.
func (c *BudgetClient) Record(p budget.Principal, s budget.Spend, at time.Time) {
	k := principalKey(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending, c.unflushed = map[pendingKey]*budget.Record{}, map[string]budget.Spend{}
	}
	minute := at.UTC().Truncate(time.Minute)
	pk := pendingKey{k, minute.Unix()}
	r := c.pending[pk]
	if r == nil {
		if len(c.pending) >= maxBudgetPending {
			c.dropped.Add(1)
			return
		}
		r = &budget.Record{Principal: budget.Principal{Subject: p.Subject, Groups: slices.Clone(p.Groups), Ring: p.Ring}, At: minute}
		c.pending[pk] = r
	}
	r.USD += s.USD
	r.Tokens += s.Tokens
	u := c.unflushed[k]
	u.USD += s.USD
	u.Tokens += s.Tokens
	c.unflushed[k] = u
	if e := c.cache[k]; e != nil {
		e.local.USD += s.USD
		e.local.Tokens += s.Tokens
	}
}

// Run reports usage every Flush until ctx ends. Call FlushNow after it
// returns to send what the last interval left.
func (c *BudgetClient) Run(ctx context.Context) {
	t := time.NewTicker(c.Flush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.FlushNow(ctx); err != nil && c.Log != nil && ctx.Err() == nil {
				c.Log.Warn("budget usage report failed; retrying next interval", "err", err)
			}
		}
	}
}

// FlushNow sends pending usage in batches until none is left or a send fails.
// A failed batch is kept and resent with the same id.
func (c *BudgetClient) FlushNow(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.inflight == nil && len(c.pending) > 0 {
			b := &BudgetUsage{Batch: newBatchID()}
			for pk, r := range c.pending {
				if len(b.Records) == maxBudgetBatch {
					break
				}
				b.Records = append(b.Records, *r)
				delete(c.pending, pk)
			}
			c.inflight = b
		}
		b := c.inflight
		c.mu.Unlock()
		if b == nil {
			return nil
		}
		if err := c.post(ctx, "/usage", b, nil); err != nil {
			c.reportErrs.Add(1)
			return err
		}
		c.reported.Add(1)
		c.mu.Lock()
		for _, r := range b.Records {
			k := principalKey(r.Principal)
			u := c.unflushed[k]
			u.USD -= r.USD
			u.Tokens -= r.Tokens
			if u.Tokens <= 0 && u.USD < 1e-9 {
				delete(c.unflushed, k)
			} else {
				c.unflushed[k] = u
			}
		}
		c.inflight = nil
		c.mu.Unlock()
	}
}

// Counters for /metrics: reports sent, reports failed, records dropped.
func (c *BudgetClient) Counters() (reported, failed, dropped int64) {
	return c.reported.Load(), c.reportErrs.Load(), c.dropped.Load()
}

func newBatchID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return hex.EncodeToString(b)
}

func (c *BudgetClient) check(ctx context.Context, p budget.Principal) (BudgetVerdict, error) {
	var v BudgetVerdict
	err := c.post(ctx, "/check", BudgetCheck{p}, &v)
	return v, err
}

func (c *BudgetClient) post(ctx context.Context, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("budget%s: encode: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("budget%s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.Client
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("budget%s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("budget%s: HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBudgetBody)).Decode(out); err != nil {
		return fmt.Errorf("budget%s: decode: %w", path, err)
	}
	return nil
}
