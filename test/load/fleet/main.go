//go:build loadfleet

// Command fleet simulates a fleet of halod devices against a running
// halo-server and reports per-endpoint latency percentiles, error rates and the
// server's CPU and memory.
//
// Every simulated device speaks the real device protocol, in the order
// cmd/halod's loop does: enroll once (POST /api/v1/launch/laptop for a
// single-use token as the --dev-insecure-user, then POST /api/v1/enroll for the
// device token), then run a cycle at startup and every -interval (signed kill
// list, ring pointer, status report) with the signed kill list polled every
// -kill-interval in between. The kill-list client is gateway.KillSwitch, the
// code halod runs; ring and report bodies are the halod wire shapes
// (server.Report). The OCI registry pull a real cycle also does is not
// simulated: it never touches halo-server (see test/load/fleet/README.md).
//
// The build tag loadfleet keeps it out of the default test run. Use make
// load-fleet, or build with -tags loadfleet.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/server"
)

// Endpoint names, in report order.
const (
	epLaunch = "enroll.launch"
	epEnroll = "enroll"
	epKill   = "fleet.killswitch"
	epRing   = "fleet.ring"
	epReport = "fleet.report"
	epFleet  = "operator.fleet"
	epDevs   = "operator.devices"
)

var endpoints = []string{epLaunch, epEnroll, epKill, epRing, epReport, epFleet, epDevs}

type epStats struct {
	lat  hist
	ok   atomic.Uint64
	fail atomic.Uint64
}

// stats is one phase's (ramp or steady) per-endpoint results.
type stats struct {
	ep   map[string]*epStats
	mu   sync.Mutex
	errs map[string]int // "endpoint status|error" -> count
}

func newStats() *stats {
	s := &stats{ep: map[string]*epStats{}, errs: map[string]int{}}
	for _, e := range endpoints {
		s.ep[e] = &epStats{}
	}
	return s
}

// recorder is the http.RoundTripper every device and operator uses: it times
// each request and files it under its endpoint in the current phase.
type recorder struct {
	next  http.RoundTripper
	phase *atomic.Int32
	st    [2]*stats
}

func classify(r *http.Request) string {
	switch r.URL.Path {
	case "/api/v1/launch/laptop":
		return epLaunch
	case "/api/v1/enroll":
		return epEnroll
	case "/api/v1/fleet/killswitch":
		return epKill
	case "/api/v1/fleet/ring":
		return epRing
	case "/api/v1/fleet/report":
		return epReport
	case "/api/v1/fleet":
		return epFleet
	case "/api/v1/devices":
		return epDevs
	}
	return ""
}

func (rc *recorder) RoundTrip(r *http.Request) (*http.Response, error) {
	ep, s := classify(r), rc.st[rc.phase.Load()]
	t0 := time.Now()
	resp, err := rc.next.RoundTrip(r)
	d := time.Since(t0)
	if ep == "" || errors.Is(err, context.Canceled) { // canceled: the run ended with the request in flight
		return resp, err
	}
	e := s.ep[ep]
	e.lat.add(d)
	switch {
	case err != nil:
		e.fail.Add(1)
		s.mu.Lock()
		s.errs[ep+" "+errKind(err)]++
		s.mu.Unlock()
	case resp.StatusCode/100 != 2:
		e.fail.Add(1)
		s.mu.Lock()
		s.errs[fmt.Sprintf("%s HTTP %d", ep, resp.StatusCode)]++
		s.mu.Unlock()
	default:
		e.ok.Add(1)
	}
	return resp, err
}

func errKind(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(err.Error(), "Client.Timeout"):
		return "timeout"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	m := err.Error()
	if i := strings.LastIndex(m, ": "); i >= 0 {
		m = m[i+2:]
	}
	return m
}

type config struct {
	server                       string
	devices, operators           int
	ramp, duration               time.Duration
	interval, killEvery, opEvery time.Duration
	scale                        float64
	enrollConc                   int
	connPerDevice                bool
	jitter                       float64
	label, out                   string
	serverPID                    int
	metricsURL                   string
	killPub                      ed25519.PublicKey
	timeout                      time.Duration
}

func main() {
	var c config
	flag.StringVar(&c.server, "server", "http://127.0.0.1:8080", "halo-server base URL (started with --dev-insecure-user, a laptop portal config and --killswitch-key-file)")
	flag.IntVar(&c.devices, "devices", 1000, "simulated halod devices")
	flag.DurationVar(&c.ramp, "ramp", 60*time.Second, "devices enroll and start at random times across this window (a morning rush)")
	flag.DurationVar(&c.duration, "duration", 120*time.Second, "steady-state window after the ramp")
	flag.DurationVar(&c.interval, "interval", 15*time.Minute, "halod cycle interval (halod default 15m)")
	flag.DurationVar(&c.killEvery, "kill-interval", time.Minute, "halod kill-list poll interval (halod default 1m)")
	flag.Float64Var(&c.scale, "scale", 1, "divide -interval and -kill-interval by this: 10 offers 10x the real request rate from the same fleet")
	flag.Float64Var(&c.jitter, "jitter", 0.05, "random +/- fraction applied to each wait (halod itself has none; devices drift apart by network and cycle time)")
	flag.IntVar(&c.enrollConc, "enroll-conc", 256, "max concurrent enrollments")
	flag.BoolVar(&c.connPerDevice, "conn-per-device", false, "one connection pool per device (as real halod processes; needs ~2 file descriptors per device, raise ulimit -n)")
	flag.IntVar(&c.operators, "operators", 0, "console operators polling GET /api/v1/fleet and /devices (admin dashboards)")
	flag.DurationVar(&c.opEvery, "operator-interval", 10*time.Second, "operator poll interval")
	flag.DurationVar(&c.timeout, "timeout", 10*time.Second, "per-request timeout (halod: 10s class)")
	flag.StringVar(&c.label, "label", "", "free-text run label for the report")
	flag.StringVar(&c.out, "out", "", "write report.json and report.md to this directory")
	flag.IntVar(&c.serverPID, "server-pid", 0, "halo-server pid: sample its RSS and CPU")
	flag.StringVar(&c.metricsURL, "metrics", "", "halo-server --metrics-listen URL (http://host:port/metrics): report server-side latency per route")
	flag.Parse()
	if c.devices < 1 || c.scale <= 0 {
		fmt.Fprintln(os.Stderr, "fleet: -devices must be >= 1 and -scale > 0")
		os.Exit(2)
	}
	if err := run(c); err != nil {
		fmt.Fprintln(os.Stderr, "fleet:", err)
		os.Exit(1)
	}
}

func run(c config) error {
	base, err := url.Parse(c.server)
	if err != nil || base.Host == "" {
		return fmt.Errorf("bad -server %q", c.server)
	}
	c.server = strings.TrimRight(c.server, "/")
	phase := new(atomic.Int32)
	rc := &recorder{phase: phase, st: [2]*stats{newStats(), newStats()}}
	tr := &http.Transport{
		Proxy: nil, MaxIdleConnsPerHost: max(c.devices, 64), IdleConnTimeout: 90 * time.Second,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	rc.next = tr
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	shared := &http.Client{Transport: rc, Timeout: c.timeout, CheckRedirect: noRedirect}

	pub, err := fetchKillPub(shared, c.server)
	if err != nil {
		return fmt.Errorf("kill-list public key: %w (start halo-server with --killswitch-key-file and a gateway token)", err)
	}
	c.killPub = pub

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.enrollConc)
	var enrolled, enrollFailed atomic.Int64
	wait := func(rng *rand.Rand, d time.Duration) bool {
		return sleep(ctx, time.Duration(float64(d)*(1+c.jitter*(2*rng.Float64()-1))))
	}
	interval, killEvery := time.Duration(float64(c.interval)/c.scale), time.Duration(float64(c.killEvery)/c.scale)

	start := time.Now()
	samp := startSampler(ctx, c.serverPID, phase)
	for i := range c.devices {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(i), 0x6861))
			// Arrive uniformly across the ramp.
			if !sleep(ctx, time.Duration(rng.Float64()*float64(c.ramp))) {
				return
			}
			hc := shared
			if c.connPerDevice {
				t2 := tr.Clone()
				t2.MaxIdleConnsPerHost = 2
				hc = &http.Client{Transport: &recorder{next: t2, phase: phase, st: rc.st}, Timeout: c.timeout, CheckRedirect: noRedirect}
				defer t2.CloseIdleConnections()
			}
			d := &device{c: c, hc: hc, host: fmt.Sprintf("load-%06d", i), rng: rng}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			err := d.enroll(ctx)
			<-sem
			if err != nil {
				if ctx.Err() == nil {
					enrollFailed.Add(1)
				}
				return
			}
			enrolled.Add(1)
			ks, err := gateway.NewKillSwitch(c.server+"/api/v1/fleet/killswitch", d.token, c.killPub, 0,
				slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			if err != nil {
				enrollFailed.Add(1)
				return
			}
			ks.Client = hc
			d.kill = ks
			// halod.loop: a full cycle at start, then a kill poll every killEvery
			// and a full cycle every interval.
			d.cycle(ctx)
			next := time.Now().Add(interval)
			for {
				if !wait(rng, killEvery) {
					return
				}
				if time.Now().Add(killEvery / 2).After(next) {
					d.cycle(ctx)
					next = time.Now().Add(interval)
					continue
				}
				_ = d.kill.Refresh(ctx)
			}
		}()
	}
	for range c.operators {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 1))
			for sleep(ctx, time.Duration(rng.Float64()*float64(c.opEvery))) {
				for _, p := range []string{"/api/v1/fleet", "/api/v1/devices"} {
					if resp, err := shared.Get(c.server + p); err == nil {
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
				}
			}
		}()
	}

	fmt.Fprintf(os.Stderr, "fleet: %d devices, ramp %s, steady %s, cycle %s (kill poll %s), scale x%g\n", c.devices, c.ramp, c.duration, interval, killEvery, c.scale)
	sleep(ctx, c.ramp)
	phase.Store(1)
	samp.mark()
	steadyStart := time.Now()
	fmt.Fprintf(os.Stderr, "fleet: ramp done: %d enrolled, %d failed; measuring steady state\n", enrolled.Load(), enrollFailed.Load())
	sleep(ctx, c.duration)
	steadyEnd := time.Now()
	scrape := scrapeMetrics(shared, c.metricsURL)
	stop()
	wg.Wait()
	sres := samp.stop()

	rep := buildReport(c, rc.st, enrolled.Load(), enrollFailed.Load(), start, steadyStart, steadyEnd, sres, scrape, interval, killEvery)
	md := rep.markdown()
	fmt.Print(md)
	if c.out != "" {
		if err := os.MkdirAll(c.out, 0o755); err != nil {
			return err
		}
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(filepath.Join(c.out, "report.json"), b, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(c.out, "report.md"), []byte(md), 0o644); err != nil {
			return err
		}
	}
	if rep.Failed {
		return errors.New("run had enrollment failures or steady-state errors above 0.1%")
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func fetchKillPub(hc *http.Client, base string) (ed25519.PublicKey, error) {
	resp, err := hc.Get(base + "/enroll/killswitch.pub")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 key")
	}
	return pub, nil
}

// device is one simulated halod.
type device struct {
	c     config
	hc    *http.Client
	host  string
	user  string
	token string
	rng   *rand.Rand
	kill  *gateway.KillSwitch
	ring  string
	seq   int
}

// enroll runs the laptop enrollment (token issue, then token redemption),
// retrying throttled and failed attempts the way a rerun enroll script would.
func (d *device) enroll(ctx context.Context) error {
	var last error
	for attempt := range 6 {
		if attempt > 0 && !sleep(ctx, time.Duration(attempt)*time.Second+time.Duration(d.rng.IntN(1000))*time.Millisecond) {
			return ctx.Err()
		}
		var launch struct {
			Token string `json:"token"`
		}
		if last = d.do(ctx, http.MethodPost, d.c.server+"/api/v1/launch/laptop", nil, "", &launch); last != nil || launch.Token == "" {
			continue
		}
		body, _ := json.Marshal(map[string]string{"token": launch.Token, "os": "linux"})
		var yml []byte
		if last = d.do(ctx, http.MethodPost, d.c.server+"/api/v1/enroll", body, "", &yml); last != nil {
			continue
		}
		var cfg struct {
			DeviceToken string `yaml:"deviceToken"`
		}
		if last = yaml.Unmarshal(yml, &cfg); last != nil || cfg.DeviceToken == "" {
			last = fmt.Errorf("enroll response without deviceToken: %v", last)
			continue
		}
		d.token = cfg.DeviceToken
		return nil
	}
	return last
}

// cycle is halod.Once without the registry pull: refreshKill, resolveRing, report.
func (d *device) cycle(ctx context.Context) {
	_ = d.kill.Refresh(ctx)
	var r struct {
		Ring    string   `json:"ring"`
		Subject string   `json:"subject"`
		Groups  []string `json:"groups"`
	}
	q := "?" + url.Values{"user": {d.user}, "host": {d.host}}.Encode()
	if err := d.do(ctx, http.MethodGet, d.c.server+"/api/v1/fleet/ring"+q, nil, d.token, &r); err == nil {
		d.ring, d.user = r.Ring, r.Subject
	}
	d.seq++
	rep := server.Report{
		Time: time.Now().UTC(), Hostname: d.host, User: d.user, Ring: d.ring,
		Digest:    fmt.Sprintf("sha256:%064x", uint64(d.seq)*0x9e3779b97f4a7c15),
		Harnesses: map[string]server.HarnessStatus{"claude-code": {Want: "2.1.0", Installed: "2.1.0"}, "codex": {Want: "0.9.0", Installed: "0.9.0"}},
		Drift:     []string{},
	}
	if d.rng.IntN(20) == 0 { // ~5% of devices report drift
		rep.Drift = []string{"settings.json"}
	}
	b, _ := json.Marshal(rep)
	_ = d.do(ctx, http.MethodPost, d.c.server+"/api/v1/fleet/report", b, d.token, nil)
}

// do issues one request; out is a struct (JSON) or *[]byte (raw body).
func (d *device) do(ctx context.Context, method, u string, body []byte, token string, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	switch o := out.(type) {
	case nil:
	case *[]byte:
		*o = b
	default:
		return json.Unmarshal(b, o)
	}
	return nil
}

// ---- report ----

type epReportRow struct {
	Endpoint                    string
	Requests, Errors            uint64
	ErrorRate                   float64
	RPS                         float64
	MeanMs, P50Ms, P90Ms, P99Ms float64
	MaxMs                       float64
}

type phaseReport struct {
	Seconds   float64
	Endpoints []epReportRow
	Errors    map[string]int `json:",omitempty"`
}

type report struct {
	Label        string
	Time         time.Time
	Devices      int
	Enrolled     int64
	EnrollFailed int64
	Ramp, Steady string
	CycleEvery   string
	KillEvery    string
	Scale        float64
	Operators    int
	GoVersion    string
	ClientCPUs   int
	RampPhase    phaseReport
	SteadyPhase  phaseReport
	Server       *sampleResult `json:",omitempty"`
	ServerSide   []routeStat   `json:",omitempty"`
	Failed       bool
}

func buildReport(c config, st [2]*stats, enrolled, failed int64, start, ss, se time.Time, sr *sampleResult, sc []routeStat, interval, killEvery time.Duration) *report {
	r := &report{Label: c.label, Time: start.UTC(), Devices: c.devices, Enrolled: enrolled, EnrollFailed: failed,
		Ramp: c.ramp.String(), Steady: c.duration.String(), CycleEvery: interval.String(), KillEvery: killEvery.String(),
		Scale: c.scale, Operators: c.operators, GoVersion: runtime.Version(), ClientCPUs: runtime.NumCPU(), Server: sr, ServerSide: sc}
	r.RampPhase = phaseOf(st[0], ss.Sub(start).Seconds())
	r.SteadyPhase = phaseOf(st[1], se.Sub(ss).Seconds())
	r.Failed = failed > 0
	for _, e := range r.SteadyPhase.Endpoints {
		r.Failed = r.Failed || e.ErrorRate > 0.001
	}
	return r
}

func phaseOf(s *stats, secs float64) phaseReport {
	p := phaseReport{Seconds: secs, Errors: map[string]int{}}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	for _, name := range endpoints {
		e := s.ep[name]
		ok, bad := e.ok.Load(), e.fail.Load()
		if ok+bad == 0 {
			continue
		}
		p.Endpoints = append(p.Endpoints, epReportRow{Endpoint: name, Requests: ok + bad, Errors: bad,
			ErrorRate: float64(bad) / float64(ok+bad), RPS: float64(ok+bad) / max(secs, 1e-9),
			MeanMs: ms(e.lat.mean()), P50Ms: ms(e.lat.quantile(.5)), P90Ms: ms(e.lat.quantile(.9)),
			P99Ms: ms(e.lat.quantile(.99)), MaxMs: ms(time.Duration(e.lat.maxNs.Load()))})
	}
	s.mu.Lock()
	for k, v := range s.errs {
		p.Errors[k] = v
	}
	s.mu.Unlock()
	return p
}

func (r *report) markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## fleet load: %s\n\n", r.Label)
	fmt.Fprintf(&b, "%d devices (%d enrolled, %d failed), ramp %s, steady %s; cycle every %s, kill poll every %s (scale x%g), %d operators; client %s on %d CPUs\n\n",
		r.Devices, r.Enrolled, r.EnrollFailed, r.Ramp, r.Steady, r.CycleEvery, r.KillEvery, r.Scale, r.Operators, r.GoVersion, r.ClientCPUs)
	for _, p := range []struct {
		name string
		ph   phaseReport
	}{{"ramp (enrollment rush)", r.RampPhase}, {"steady state", r.SteadyPhase}} {
		fmt.Fprintf(&b, "### %s, %.0fs\n\n| endpoint | requests | rps | errors | err %% | mean ms | p50 ms | p90 ms | p99 ms | max ms |\n|---|---|---|---|---|---|---|---|---|---|\n", p.name, p.ph.Seconds)
		for _, e := range p.ph.Endpoints {
			fmt.Fprintf(&b, "| %s | %d | %.1f | %d | %.3f | %.2f | %.2f | %.2f | %.2f | %.1f |\n", e.Endpoint, e.Requests, e.RPS, e.Errors, e.ErrorRate*100, e.MeanMs, e.P50Ms, e.P90Ms, e.P99Ms, e.MaxMs)
		}
		if len(p.ph.Errors) > 0 {
			keys := make([]string, 0, len(p.ph.Errors))
			for k := range p.ph.Errors {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteString("\nerrors: ")
			for i, k := range keys {
				if i > 0 {
					b.WriteString("; ")
				}
				fmt.Fprintf(&b, "%s x%d", k, p.ph.Errors[k])
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if s := r.Server; s != nil {
		fmt.Fprintf(&b, "### halo-server process (pid %d)\n\n| phase | RSS start MB | RSS end MB | RSS max MB | CPU avg %% of one core | CPU max %% |\n|---|---|---|---|---|---|\n", s.PID)
		for _, p := range []struct {
			n string
			v phaseSample
		}{{"ramp", s.Ramp}, {"steady", s.Steady}} {
			fmt.Fprintf(&b, "| %s | %.0f | %.0f | %.0f | %.0f | %.0f |\n", p.n, p.v.RSSStartMB, p.v.RSSEndMB, p.v.RSSMaxMB, p.v.CPUAvgPct, p.v.CPUMaxPct)
		}
		b.WriteString("\n")
	}
	if len(r.ServerSide) > 0 {
		b.WriteString("### server-side request latency (halo-server /metrics, whole run)\n\n| route | requests | mean ms |\n|---|---|---|\n")
		for _, s := range r.ServerSide {
			fmt.Fprintf(&b, "| %s | %d | %.3f |\n", s.Route, s.Count, s.MeanMs)
		}
		b.WriteString("\n")
	}
	if r.Failed {
		b.WriteString("RESULT: FAIL (enrollment failures or steady-state error rate above 0.1% on an endpoint)\n")
	} else {
		b.WriteString("RESULT: PASS\n")
	}
	return b.String()
}
