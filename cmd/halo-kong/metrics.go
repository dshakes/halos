package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Hand-written Prometheus text exposition, as halo-proxy's /metrics: Kong
// gives a Go plugin server no metrics hook, so halo-kong serves its own on
// $HALO_KONG_METRICS_LISTEN (e.g. 127.0.0.1:9542; unset disables). One plugin
// server process serves every route, so the counters are process-wide.

// metricsListenEnv names the listen address of the /metrics endpoint.
const metricsListenEnv = "HALO_KONG_METRICS_LISTEN"

type kongMetrics struct {
	mu        sync.Mutex
	directory map[string]uint64    // outcome
	posture   map[[2]string]uint64 // {ring, outcome}
	headerCap uint64
	agentDeny uint64
	dlp       map[[3]string]uint64 // {kind, detector, action}
}

var kmetrics = &kongMetrics{directory: map[string]uint64{}, posture: map[[2]string]uint64{}, dlp: map[[3]string]uint64{}}

// dlpFinding counts one DLP finding on a request (ADR-0033).
func (m *kongMetrics) dlpFinding(kind, detector, action string) {
	m.mu.Lock()
	m.dlp[[3]string{kind, detector, action}]++
	m.mu.Unlock()
}

// directoryOutcome counts one directory resolution: ok, stale, failopen,
// unavailable or not_provisioned (gateway.DirectoryClient.Observe), and
// invalid_config_failopen / invalid_config_refused for an invalid config.
func (m *kongMetrics) directoryOutcome(outcome string) {
	m.mu.Lock()
	m.directory[outcome]++
	m.mu.Unlock()
}

// postureOutcome counts one posture gate decision on ring: pass, fail (warn
// mode, let through), deny (enforce mode, 403) or unknown (no verdict).
func (m *kongMetrics) postureOutcome(ring, outcome string) {
	m.mu.Lock()
	m.posture[[2]string{ring, outcome}]++
	m.mu.Unlock()
}

func (m *kongMetrics) headerCapRejected() {
	m.mu.Lock()
	m.headerCap++
	m.mu.Unlock()
}

func (m *kongMetrics) agentDenied() {
	m.mu.Lock()
	m.agentDeny++
	m.mu.Unlock()
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func (m *kongMetrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP halo_kong_directory_resolutions_total Directory lookups of verified callers by outcome: ok, stale (cached entry served through an outage), failopen (kept with no groups), unavailable (503, failMode closed), not_provisioned (403), invalid_config_failopen, invalid_config_refused.")
	fmt.Fprintln(w, "# TYPE halo_kong_directory_resolutions_total counter")
	dk := make([]string, 0, len(m.directory))
	for k := range m.directory {
		dk = append(dk, k)
	}
	sort.Strings(dk)
	for _, k := range dk {
		fmt.Fprintf(w, "halo_kong_directory_resolutions_total{outcome=\"%s\"} %d\n", esc(k), m.directory[k])
	}
	fmt.Fprintln(w, "# HELP halo_kong_posture_total Posture gate decisions by ring: pass, fail (warn mode, let through), deny (enforce mode, 403), unknown (no verdict).")
	fmt.Fprintln(w, "# TYPE halo_kong_posture_total counter")
	pk := make([][2]string, 0, len(m.posture))
	for k := range m.posture {
		pk = append(pk, k)
	}
	sort.Slice(pk, func(i, j int) bool { return pk[i][0]+"\x00"+pk[i][1] < pk[j][0]+"\x00"+pk[j][1] })
	for _, k := range pk {
		fmt.Fprintf(w, "halo_kong_posture_total{ring=\"%s\",outcome=\"%s\"} %d\n", esc(k[0]), esc(k[1]), m.posture[k])
	}
	fmt.Fprintf(w, "# HELP halo_kong_header_cap_rejections_total Requests answered 431 because they reached the %d-header cap.\n# TYPE halo_kong_header_cap_rejections_total counter\nhalo_kong_header_cap_rejections_total %d\n", maxHeaders, m.headerCap)
	fmt.Fprintln(w, "# HELP halo_kong_dlp_findings_total Secrets and prompt-injection signals found in model-call requests, by detector and the action taken (ADR-0033).")
	fmt.Fprintln(w, "# TYPE halo_kong_dlp_findings_total counter")
	fk := make([][3]string, 0, len(m.dlp))
	for k := range m.dlp {
		fk = append(fk, k)
	}
	sort.Slice(fk, func(i, j int) bool { return strings.Join(fk[i][:], "\x00") < strings.Join(fk[j][:], "\x00") })
	for _, k := range fk {
		fmt.Fprintf(w, "halo_kong_dlp_findings_total{kind=\"%s\",detector=\"%s\",action=\"%s\"} %d\n", esc(k[0]), esc(k[1]), esc(k[2]), m.dlp[k])
	}
	fmt.Fprintf(w, "# HELP halo_kong_agent_denials_total Delegated agent model calls refused by the agent policy.\n# TYPE halo_kong_agent_denials_total counter\nhalo_kong_agent_denials_total %d\n", m.agentDeny)
}

// serveMetrics serves GET /metrics on addr in the background. A listen error
// is reported on stderr (Kong's error log) and never stops the plugin server.
func serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		kmetrics.write(w)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintln(os.Stderr, "halo-kong: metrics listener on", addr+":", err)
		}
	}()
}
