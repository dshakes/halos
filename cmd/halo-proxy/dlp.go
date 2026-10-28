package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// DLPConfig points at halo-server's DLP audit endpoint (ADR-0033). The scan
// itself is policy (gateway.dlp) and runs without it; findings are then only
// counted and logged.
type DLPConfig struct {
	URL       string `yaml:"url"`       // https://halo-server/api/v1/gateway/dlp; empty = findings are not audited
	TokenFile string `yaml:"tokenFile"` // halo-server --gateway-dlp-token-file (else --gateway-token-file) value
	// FlushInterval is how often findings are posted (default 5s).
	FlushInterval time.Duration `yaml:"flushInterval"`
	// AllowInsecureInCluster permits plain http to a non-loopback host.
	AllowInsecureInCluster bool `yaml:"allowInsecureInCluster"`
}

// build returns nil when DLP audit is not configured.
func (c DLPConfig) build(log *slog.Logger) (*gateway.DLPReporter, error) {
	if c.URL == "" {
		if c.TokenFile != "" {
			return nil, fmt.Errorf("halo-proxy: dlp.url is required when dlp.tokenFile is set")
		}
		return nil, nil
	}
	if c.TokenFile == "" {
		return nil, fmt.Errorf("halo-proxy: dlp needs tokenFile")
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: dlp.tokenFile: %w", err)
	}
	r, err := gateway.NewDLPReporter(c.URL, strings.TrimSpace(string(tok)), c.FlushInterval, log, c.AllowInsecureInCluster)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: %w", err)
	}
	return r, nil
}

// dlpMetrics counts scans and findings for /metrics. Labels are bounded:
// detector ids come from code or policy, never from the request.
type dlpMetrics struct {
	mu       sync.Mutex
	scans    map[[2]string]uint64 // {direction, outcome}
	findings map[[4]string]uint64 // {kind, detector, action, direction}
	seconds  float64              // total request scan time
}

func newDLPMetrics() *dlpMetrics {
	return &dlpMetrics{scans: map[[2]string]uint64{}, findings: map[[4]string]uint64{}}
}

func (m *dlpMetrics) observe(dir string, rep *gateway.DLPReport, evs []gateway.DLPEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	outcome := "clean"
	switch {
	case rep != nil && rep.Blocked != "":
		outcome = "blocked"
	case rep != nil && rep.Redacted != nil:
		outcome = "redacted"
	case len(evs) > 0:
		outcome = "finding"
	}
	m.scans[[2]string{dir, outcome}]++
	if rep != nil {
		if rep.Truncated {
			m.scans[[2]string{dir, "truncated"}]++
		}
		m.seconds += rep.Took.Seconds()
	}
	for _, e := range evs {
		m.findings[[4]string{e.Kind, e.Detector, e.Action, e.Direction}]++
	}
}

func (m *dlpMetrics) write(w io.Writer, sent, failed, dropped, deduped int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP halo_proxy_dlp_scans_total DLP scans of model-call requests and responses, by outcome: clean, finding, redacted, blocked; truncated counts scans cut at the size cap or time budget (ADR-0033).")
	fmt.Fprintln(w, "# TYPE halo_proxy_dlp_scans_total counter")
	sk := make([][2]string, 0, len(m.scans))
	for k := range m.scans {
		sk = append(sk, k)
	}
	sort.Slice(sk, func(i, j int) bool { return sk[i][0]+"\x00"+sk[i][1] < sk[j][0]+"\x00"+sk[j][1] })
	for _, k := range sk {
		fmt.Fprintf(w, "halo_proxy_dlp_scans_total{direction=\"%s\",outcome=\"%s\"} %d\n", esc(k[0]), esc(k[1]), m.scans[k])
	}
	fmt.Fprintln(w, "# HELP halo_proxy_dlp_findings_total Secrets and prompt-injection signals found, by detector and the action taken.")
	fmt.Fprintln(w, "# TYPE halo_proxy_dlp_findings_total counter")
	fk := make([][4]string, 0, len(m.findings))
	for k := range m.findings {
		fk = append(fk, k)
	}
	sort.Slice(fk, func(i, j int) bool { return strings.Join(fk[i][:], "\x00") < strings.Join(fk[j][:], "\x00") })
	for _, k := range fk {
		fmt.Fprintf(w, "halo_proxy_dlp_findings_total{kind=\"%s\",detector=\"%s\",action=\"%s\",direction=\"%s\"} %d\n", esc(k[0]), esc(k[1]), esc(k[2]), esc(k[3]), m.findings[k])
	}
	fmt.Fprintf(w, "# HELP halo_proxy_dlp_scan_seconds_total Time spent scanning request bodies (divide by request scans for the mean).\n# TYPE halo_proxy_dlp_scan_seconds_total counter\nhalo_proxy_dlp_scan_seconds_total %g\n", m.seconds)
	fmt.Fprintf(w, "# HELP halo_proxy_dlp_audit_events_total DLP audit events posted to halo-server, by outcome (sent, dropped: queue full or refused, deduped: same finding within an hour).\n# TYPE halo_proxy_dlp_audit_events_total counter\n")
	fmt.Fprintf(w, "halo_proxy_dlp_audit_events_total{outcome=\"sent\"} %d\nhalo_proxy_dlp_audit_events_total{outcome=\"dropped\"} %d\nhalo_proxy_dlp_audit_events_total{outcome=\"deduped\"} %d\n", sent, dropped, deduped)
	fmt.Fprintf(w, "# HELP halo_proxy_dlp_audit_failures_total Failed DLP audit posts (retried).\n# TYPE halo_proxy_dlp_audit_failures_total counter\nhalo_proxy_dlp_audit_failures_total %d\n", failed)
}

// dlpBase is the audit event every finding of this request starts from.
func dlpBase(sub *policy.Subject, ring string, units []string, proto, harness string) gateway.DLPEvent {
	e := gateway.DLPEvent{At: time.Now().UTC(), Gateway: "halo-proxy", Ring: ring, Protocol: proto, Harness: harness}
	if sub != nil {
		e.Subject = sub.ID
		if sub.Delegation.Depth() > 0 {
			e.Chain = sub.Delegation.Chain()
		}
	}
	if len(units) > 0 {
		e.Unit = units[0]
	}
	return e
}

// dlpRequest records a request scan: metrics, audit events, and the note for
// the request log (detector ids, hashes and locations only).
func (p *Proxy) dlpRequest(rep *gateway.DLPReport, base gateway.DLPEvent) string {
	if rep == nil {
		return ""
	}
	evs := gateway.DLPEvents(rep, base)
	p.dm.observe(gateway.DLPRequest, rep, evs)
	p.dlpAudit.Report(evs...)
	return dlpNote(evs)
}

func dlpNote(evs []gateway.DLPEvent) string {
	var notes []string
	for _, e := range evs {
		n := e.Kind + " " + e.Detector + " " + e.Action + " at " + e.Location
		if e.Hash != "" {
			n += " #" + e.Hash
		}
		if e.Score > 0 {
			n += fmt.Sprintf(" score %d (%s)", e.Score, strings.Join(e.Signals, ","))
		}
		notes = append(notes, n)
		if len(notes) == 8 {
			notes = append(notes, fmt.Sprintf("+%d more", len(evs)-8))
			break
		}
	}
	return strings.Join(notes, "; ")
}

// dlpResponse is a response scan in flight; done runs once the body ended.
type dlpResponse struct {
	s    *gateway.DLPResponseScanner
	base gateway.DLPEvent
}

func (p *Proxy) dlpResponseDone(d *dlpResponse, path string) func(gateway.UsageResult) {
	return func(gateway.UsageResult) {
		fs := d.s.Findings()
		evs := make([]gateway.DLPEvent, 0, len(fs))
		for _, f := range fs {
			e := d.base
			e.At, e.Direction, e.Action, e.DLPFinding = time.Now().UTC(), gateway.DLPResponse, policy.DLPMonitor, f
			evs = append(evs, e)
		}
		p.dm.observe(gateway.DLPResponse, nil, evs)
		p.dlpAudit.Report(evs...)
		if len(evs) > 0 {
			p.log.Warn("dlp: secret in model response", "path", path, "ring", d.base.Ring, "dlp", dlpNote(evs))
		}
	}
}
