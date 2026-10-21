package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/dshakes/halos/internal/budget"
)

// Hand-written Prometheus text exposition (no client library needed for three
// metric families).

// Buckets (seconds) span fast rejections to long agentic generations.
var latencyBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600}

type reqKey struct {
	ring, variant string
	status        int
}

type hist struct {
	counts []uint64 // per bucket, non-cumulative; last slot is +Inf
	sum    float64
	n      uint64
}

func (h *hist) observe(v float64) {
	if h.counts == nil {
		h.counts = make([]uint64, len(latencyBuckets)+1)
	}
	i := 0
	for i < len(latencyBuckets) && v > latencyBuckets[i] {
		i++
	}
	h.counts[i]++
	h.sum += v
	h.n++
}

type metrics struct {
	mu           sync.Mutex
	reqs         map[reqKey]uint64
	ttfb, total  hist
	authFailures uint64
	attempts     map[[2]string]uint64 // {provider kind, outcome}
	gates        map[[3]string]uint64 // {gate, ring, outcome}

	budgets   map[[2]string]uint64 // {budget, outcome}
	budgetRes map[string]uint64    // metered responses by outcome
	budgetUSD float64
	budgetTok budget.Usage
}

func newMetrics() *metrics {
	return &metrics{reqs: map[reqKey]uint64{}, attempts: map[[2]string]uint64{}, gates: map[[3]string]uint64{},
		budgets: map[[2]string]uint64{}, budgetRes: map[string]uint64{}}
}

// budget counts one budget check outcome per counter a request is charged
// to: ok, alert, exceeded (warn budget), refused (enforce budget) or unknown.
func (m *metrics) budget(name, outcome string) {
	m.mu.Lock()
	m.budgets[[2]string{name, outcome}]++
	m.mu.Unlock()
}

// budgetResponse counts one metered response (metered, unpriced or estimated) and its spend.
func (m *metrics) budgetResponse(outcome string, usd float64, u budget.Usage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.budgetRes[outcome]++
	m.budgetUSD += usd
	m.budgetTok.Input += u.Input
	m.budgetTok.Output += u.Output
	m.budgetTok.CacheRead += u.CacheRead
	m.budgetTok.CacheWrite += u.CacheWrite
}

// writeBudget renders the budget families; reported/failed/dropped come from the BudgetClient.
func (m *metrics) writeBudget(w io.Writer, reported, failed, dropped int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP halo_proxy_budget_checks_total Budget check outcomes per budget: ok, alert (soft threshold crossed), exceeded (warn budget used up), refused (enforce budget, 429), unknown (no verdict).")
	fmt.Fprintln(w, "# TYPE halo_proxy_budget_checks_total counter")
	bk := make([][2]string, 0, len(m.budgets))
	for k := range m.budgets {
		bk = append(bk, k)
	}
	sort.Slice(bk, func(i, j int) bool { return bk[i][0]+"\x00"+bk[i][1] < bk[j][0]+"\x00"+bk[j][1] })
	for _, k := range bk {
		fmt.Fprintf(w, "halo_proxy_budget_checks_total{budget=\"%s\",outcome=\"%s\"} %d\n", esc(k[0]), esc(k[1]), m.budgets[k])
	}
	fmt.Fprintln(w, "# HELP halo_proxy_budget_responses_total Metered model responses: metered, unpriced (model has no price: tokens only), estimated (final usage not read: client hung up, upstream cut, no usage object or an undecodable encoding; charged a pessimistic estimate).")
	fmt.Fprintln(w, "# TYPE halo_proxy_budget_responses_total counter")
	for _, o := range []string{"estimated", "metered", "unpriced"} {
		fmt.Fprintf(w, "halo_proxy_budget_responses_total{outcome=\"%s\"} %d\n", o, m.budgetRes[o])
	}
	fmt.Fprintf(w, "# HELP halo_proxy_budget_spend_usd_total Spend charged to budgets, priced from policy gateway.pricing.\n# TYPE halo_proxy_budget_spend_usd_total counter\nhalo_proxy_budget_spend_usd_total %g\n", m.budgetUSD)
	fmt.Fprintln(w, "# HELP halo_proxy_budget_tokens_total Tokens charged to budgets, by kind.")
	fmt.Fprintln(w, "# TYPE halo_proxy_budget_tokens_total counter")
	for _, kv := range []struct {
		k string
		v int64
	}{{"cache_read", m.budgetTok.CacheRead}, {"cache_write", m.budgetTok.CacheWrite}, {"input", m.budgetTok.Input}, {"output", m.budgetTok.Output}} {
		fmt.Fprintf(w, "halo_proxy_budget_tokens_total{kind=\"%s\"} %d\n", kv.k, kv.v)
	}
	fmt.Fprintf(w, "# HELP halo_proxy_budget_reports_total Usage reports to halo-server, by outcome.\n# TYPE halo_proxy_budget_reports_total counter\nhalo_proxy_budget_reports_total{outcome=\"ok\"} %d\nhalo_proxy_budget_reports_total{outcome=\"failed\"} %d\n", reported, failed)
	fmt.Fprintf(w, "# HELP halo_proxy_budget_dropped_total Usage records dropped because too much was waiting to be reported.\n# TYPE halo_proxy_budget_dropped_total counter\nhalo_proxy_budget_dropped_total %d\n", dropped)
}

// attempt counts one upstream target try; outcome is ok | failed | circuit_open | skipped.
func (m *metrics) attempt(provider, outcome string) {
	m.mu.Lock()
	m.attempts[[2]string{provider, outcome}]++
	m.mu.Unlock()
}

// observe records one finished request. ttfb < 0 means no upstream response
// headers were ever received (rejected locally or upstream error).
func (m *metrics) observe(ring, variant string, status int, ttfb, total float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reqs[reqKey{ring, variant, status}]++
	if ttfb >= 0 {
		m.ttfb.observe(ttfb)
	}
	m.total.observe(total)
}

// gate counts one gate outcome: warn | enforce (the check failed under that
// mode) or unknown (posture gate on, no verdict available).
func (m *metrics) gate(gate, ring, outcome string) {
	m.mu.Lock()
	m.gates[[3]string{gate, ring, outcome}]++
	m.mu.Unlock()
}

func (m *metrics) authFailed() {
	m.mu.Lock()
	m.authFailures++
	m.mu.Unlock()
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// write renders the exposition; the shadow counters come from the mirrorer.
func (m *metrics) write(w io.Writer, shadowDropped, shadowFailed int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP halo_proxy_requests_total Requests handled, by ring, experiment variant and response status.")
	fmt.Fprintln(w, "# TYPE halo_proxy_requests_total counter")
	keys := make([]reqKey, 0, len(m.reqs))
	for k := range m.reqs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.ring != b.ring {
			return a.ring < b.ring
		}
		if a.variant != b.variant {
			return a.variant < b.variant
		}
		return a.status < b.status
	})
	for _, k := range keys {
		fmt.Fprintf(w, "halo_proxy_requests_total{ring=\"%s\",variant=\"%s\",status=\"%d\"} %d\n", esc(k.ring), esc(k.variant), k.status, m.reqs[k])
	}
	writeHist(w, "halo_proxy_upstream_ttfb_seconds", "Time from request start to upstream response headers.", &m.ttfb)
	writeHist(w, "halo_proxy_request_duration_seconds", "Total request time including the full response stream.", &m.total)
	fmt.Fprintln(w, "# HELP halo_proxy_upstream_attempts_total Upstream target tries, by provider kind and outcome (ok, failed, circuit_open, skipped).")
	fmt.Fprintln(w, "# TYPE halo_proxy_upstream_attempts_total counter")
	ak := make([][2]string, 0, len(m.attempts))
	for k := range m.attempts {
		ak = append(ak, k)
	}
	sort.Slice(ak, func(i, j int) bool { return ak[i][0]+"\x00"+ak[i][1] < ak[j][0]+"\x00"+ak[j][1] })
	for _, k := range ak {
		fmt.Fprintf(w, "halo_proxy_upstream_attempts_total{provider=\"%s\",outcome=\"%s\"} %d\n", esc(k[0]), esc(k[1]), m.attempts[k])
	}
	fmt.Fprintln(w, "# HELP halo_proxy_gate_total Posture and version gate outcomes by ring: warn or enforce (check failed under that mode), unknown (no posture verdict).")
	fmt.Fprintln(w, "# TYPE halo_proxy_gate_total counter")
	gk := make([][3]string, 0, len(m.gates))
	for k := range m.gates {
		gk = append(gk, k)
	}
	sort.Slice(gk, func(i, j int) bool { return strings.Join(gk[i][:], "\x00") < strings.Join(gk[j][:], "\x00") })
	for _, k := range gk {
		fmt.Fprintf(w, "halo_proxy_gate_total{gate=\"%s\",ring=\"%s\",outcome=\"%s\"} %d\n", esc(k[0]), esc(k[1]), esc(k[2]), m.gates[k])
	}
	fmt.Fprintf(w, "# HELP halo_proxy_auth_failures_total Requests whose caller identity could not be verified.\n# TYPE halo_proxy_auth_failures_total counter\nhalo_proxy_auth_failures_total %d\n", m.authFailures)
	fmt.Fprintf(w, "# HELP halo_proxy_shadow_dropped_total Shadow jobs dropped because the mirror queue was full.\n# TYPE halo_proxy_shadow_dropped_total counter\nhalo_proxy_shadow_dropped_total %d\n", shadowDropped)
	fmt.Fprintf(w, "# HELP halo_proxy_shadow_failed_total Shadow jobs halo-shadow rejected or that failed to send.\n# TYPE halo_proxy_shadow_failed_total counter\nhalo_proxy_shadow_failed_total %d\n", shadowFailed)
}

func writeHist(w io.Writer, name, help string, h *hist) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	var cum uint64
	for i, le := range latencyBuckets {
		if h.counts != nil {
			cum += h.counts[i]
		}
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, le, cum)
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %g\n%s_count %d\n", name, h.n, name, h.sum, name, h.n)
}
