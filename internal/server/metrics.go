package server

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Request and security metrics, hand-written Prometheus text like the rest of
// WriteMetrics (no client library). Every label is bounded: route is the
// mux pattern that matched ("GET /api/v1/devices/{id}"), never a raw path,
// or "unmatched"; status is a class (2xx..5xx); flow, reason, kind and
// outcome come from fixed sets in this package.

// apiLatencyBuckets (seconds) span a cached read to a slow PR or registry call.
var apiLatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

type latencyHist struct {
	counts []uint64 // per bucket, non-cumulative; last slot is +Inf
	sum    float64
	n      uint64
}

func (h *latencyHist) observe(v float64) {
	if h.counts == nil {
		h.counts = make([]uint64, len(apiLatencyBuckets)+1)
	}
	i := 0
	for i < len(apiLatencyBuckets) && v > apiLatencyBuckets[i] {
		i++
	}
	h.counts[i]++
	h.sum += v
	h.n++
}

type serverMetrics struct {
	mu        sync.Mutex
	reqs      map[[2]string]*latencyHist // {route, status class}
	denies    map[string]uint64          // authz denies by route
	authFails map[[2]string]uint64       // {flow, reason}
	limited   map[string]uint64          // failed-auth limiter blocks (429) by route
	lookups   map[[2]string]uint64       // {kind, outcome}
	cloud     map[[2]string]uint64       // cloud agent alerts {vendor, kind}
}

func (m *serverMetrics) init() {
	if m.reqs == nil {
		m.reqs, m.denies, m.authFails = map[[2]string]*latencyHist{}, map[string]uint64{}, map[[2]string]uint64{}
		m.limited, m.lookups, m.cloud = map[string]uint64{}, map[[2]string]uint64{}, map[[2]string]uint64{}
	}
}

// request records one finished request. Every 429 halo-server answers is a
// failed-auth limiter block, so it is also counted as one.
func (m *serverMetrics) request(pattern string, code int, d time.Duration) {
	route := pattern
	if route == "" {
		route = "unmatched"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	k := [2]string{route, fmt.Sprintf("%dxx", code/100)}
	h := m.reqs[k]
	if h == nil {
		h = &latencyHist{}
		m.reqs[k] = h
	}
	h.observe(d.Seconds())
	if code == http.StatusTooManyRequests {
		m.limited[route]++
	}
}

func (m *serverMetrics) deny(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.denies[route]++
}

// authFailure counts one failed login, enrollment, token exchange or
// delegation (flow) for reason.
func (m *serverMetrics) authFailure(flow, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.authFails[[2]string{flow, reason}]++
}

// lookup counts one gateway directory, revocation-list or posture lookup by outcome.
func (m *serverMetrics) lookup(kind, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.lookups[[2]string{kind, outcome}]++
}

// cloudAlert counts one cloud agent alert (vendor and kind are fixed sets).
func (m *serverMetrics) cloudAlert(vendor, kind string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.cloud[[2]string{vendor, kind}]++
}

func sortedKeys[K comparable](m map[K]uint64, less func(a, b K) int) []K {
	ks := make([]K, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.SortFunc(ks, less)
	return ks
}

func cmpPair(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) }

func (m *serverMetrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	fmt.Fprint(w, "# HELP halo_server_requests_total HTTP requests by route pattern and status class.\n# TYPE halo_server_requests_total counter\n")
	keys := make([][2]string, 0, len(m.reqs))
	for k := range m.reqs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, cmpPair)
	for _, k := range keys {
		fmt.Fprintf(w, "halo_server_requests_total{route=%q,status=%q} %d\n", k[0], k[1], m.reqs[k].n)
	}
	fmt.Fprint(w, "# HELP halo_server_request_duration_seconds HTTP request latency by route pattern and status class.\n# TYPE halo_server_request_duration_seconds histogram\n")
	for _, k := range keys {
		h, lbl := m.reqs[k], fmt.Sprintf("route=%q,status=%q", k[0], k[1])
		var cum uint64
		for i, le := range apiLatencyBuckets {
			cum += h.counts[i]
			fmt.Fprintf(w, "halo_server_request_duration_seconds_bucket{%s,le=\"%g\"} %d\n", lbl, le, cum)
		}
		fmt.Fprintf(w, "halo_server_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\nhalo_server_request_duration_seconds_sum{%s} %g\nhalo_server_request_duration_seconds_count{%s} %d\n", lbl, h.n, lbl, h.sum, lbl, h.n)
	}
	fmt.Fprint(w, "# HELP halo_server_authz_denied_total Console/API requests refused for a missing permission (403), by route.\n# TYPE halo_server_authz_denied_total counter\n")
	for _, k := range sortedKeys(m.denies, strings.Compare) {
		fmt.Fprintf(w, "halo_server_authz_denied_total{route=%q} %d\n", k, m.denies[k])
	}
	fmt.Fprint(w, "# HELP halo_server_auth_failures_total Failed logins, enrollments, workload token exchanges and agent delegations, by flow and reason.\n# TYPE halo_server_auth_failures_total counter\n")
	for _, k := range sortedKeys(m.authFails, cmpPair) {
		fmt.Fprintf(w, "halo_server_auth_failures_total{flow=%q,reason=%q} %d\n", k[0], k[1], m.authFails[k])
	}
	fmt.Fprint(w, "# HELP halo_server_auth_limited_total Requests refused by a failed-authentication rate limiter (429), by route.\n# TYPE halo_server_auth_limited_total counter\n")
	for _, k := range sortedKeys(m.limited, strings.Compare) {
		fmt.Fprintf(w, "halo_server_auth_limited_total{route=%q} %d\n", k, m.limited[k])
	}
	fmt.Fprint(w, "# HELP halo_server_gateway_lookups_total Gateway directory, revocation-list and posture lookups, by kind and outcome.\n# TYPE halo_server_gateway_lookups_total counter\n")
	for _, k := range sortedKeys(m.lookups, cmpPair) {
		fmt.Fprintf(w, "halo_server_gateway_lookups_total{kind=%q,outcome=%q} %d\n", k[0], k[1], m.lookups[k])
	}
	fmt.Fprint(w, "# HELP halo_server_cloud_agent_alerts_total Cloud agent policy violations and over-limits seen on webhook deliveries, by vendor and kind (ADR-0034).\n# TYPE halo_server_cloud_agent_alerts_total counter\n")
	for _, k := range sortedKeys(m.cloud, cmpPair) {
		fmt.Fprintf(w, "halo_server_cloud_agent_alerts_total{vendor=%q,kind=%q} %d\n", k[0], k[1], m.cloud[k])
	}
}
