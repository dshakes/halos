// Command load drives a real halo-proxy binary against mock upstreams and
// reports added latency, throughput, errors, memory/goroutine growth over a
// soak, failover + circuit-breaker behaviour, and long-lived SSE integrity.
//
//	go build -o bin/halo-proxy ./cmd/halo-proxy && go run ./test/load -bin bin/halo-proxy
//
// Gating (nightly soak): -json-out writes a summary, -baseline compares p99 against a stored
// summary, and the soak fails on heap / goroutine growth slopes (see the flag docs).
//
// Target mode (-target URL) drives an already-running proxy instead (scripts/uat-k8s.sh uses it
// to prove zero client-visible errors across pod kills and rolling upgrades).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
)

var (
	bin         = flag.String("bin", "bin/halo-proxy", "halo-proxy binary")
	conc        = flag.Int("c", 32, "concurrent workers per phase")
	latency     = flag.Duration("latency", 50*time.Millisecond, "fixed mock upstream latency")
	phase       = flag.Duration("phase", 20*time.Second, "duration of the latency and failover phases")
	soak        = flag.Duration("soak", 3*time.Minute, "soak duration (memory / goroutine growth)")
	sseDur      = flag.Duration("sse", 60*time.Second, "length of each long SSE stream (events every 1s)")
	sseN        = flag.Int("sse-streams", 4, "concurrent long SSE streams, run during the soak")
	readTO      = flag.String("read-timeout", "", "override halo-proxy readTimeout (e.g. 20s) to test stream survival past it")
	cooldown    = flag.Duration("breaker-cooldown", 5*time.Second, "breaker cooldown for the failover phase")
	sampleEvery = flag.Duration("sample", 10*time.Second, "soak sampling interval (heap / goroutines)")
	jsonOut     = flag.String("json-out", "", "write the run summary (latency, leak slopes) as JSON to this file")
	baseline    = flag.String("baseline", "", "baseline summary JSON: fail if p99 regresses beyond -p99-tolerance (missing file = record only)")
	p99Tol      = flag.Float64("p99-tolerance", 0.5, "allowed fractional p99 increase over the baseline (0.5 = +50%)")
	p99Floor    = flag.Duration("p99-floor", 5*time.Millisecond, "ignore p99 regressions smaller than this absolute amount (runner noise)")
	maxHeap     = flag.Float64("max-heap-growth-mb-per-hour", 10, "fail if the steady-state heap_inuse slope exceeds this (needs >= 20 steady samples)")
	maxGor      = flag.Float64("max-goroutine-growth-per-hour", 20, "fail if the steady-state goroutine slope exceeds this (needs >= 20 steady samples)")
	target      = flag.String("target", "", "target mode: drive this full URL (e.g. http://127.0.0.1:30088/v1/messages) instead of a local proxy")
	model       = flag.String("model", "sonnet", "target mode: model alias to request")
	token       = flag.String("token", "", "target mode: bearer token (or env LOAD_TOKEN)")
	duration    = flag.Duration("duration", 30*time.Second, "target mode: how long to drive load")
	rps         = flag.Int("rps", 0, "target mode: cap total request rate (0 = unthrottled closed loop)")
	reqBody     = `{"model":"sonnet","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`
	foBody      = `{"model":"fo","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`
	failedAny   atomic.Bool
)

type result struct {
	lat     []time.Duration
	errs    int
	dur     time.Duration
	samples []string // first few distinct error strings
}

func (r result) pct(p float64) time.Duration {
	if len(r.lat) == 0 {
		return 0
	}
	return r.lat[int(float64(len(r.lat)-1)*p)]
}

func (r result) String() string {
	return fmt.Sprintf("n=%d rps=%.0f err=%d (%.3f%%) p50=%v p95=%v p99=%v", len(r.lat)+r.errs,
		float64(len(r.lat)+r.errs)/r.dur.Seconds(), r.errs, 100*float64(r.errs)/float64(max(1, len(r.lat)+r.errs)),
		r.pct(.5).Round(10*time.Microsecond), r.pct(.95).Round(10*time.Microsecond), r.pct(.99).Round(10*time.Microsecond))
}

func newClient() *http.Client {
	return &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256, MaxConnsPerHost: 0}}
}

// driveRPS paces drive's workers to about this many requests/s in total (0 = closed loop).
var driveRPS int

// drive runs n closed-loop workers for d and returns sorted latencies.
func drive(ctx context.Context, url, tok, body string, n int, d time.Duration) result {
	cl := newClient()
	defer cl.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var mu sync.Mutex
	var res result
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lat []time.Duration
			var errSamples []string
			errs := 0
			for ctx.Err() == nil {
				t0 := time.Now()
				req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("anthropic-version", "2023-06-01")
				if tok != "" {
					req.Header.Set("Authorization", "Bearer "+tok)
				}
				resp, err := cl.Do(req)
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if err == nil && resp.StatusCode != 200 {
						err = fmt.Errorf("status %d", resp.StatusCode)
					}
				}
				if ctx.Err() != nil {
					break // phase over; in-flight request is not an error
				}
				if err != nil {
					errs++
					if len(errSamples) < 3 {
						errSamples = append(errSamples, fmt.Sprintf("t+%v: %v", time.Since(start).Round(100*time.Millisecond), err))
					}
					continue
				}
				lat = append(lat, time.Since(t0))
			}
			mu.Lock()
			res.lat, res.errs = append(res.lat, lat...), res.errs+errs
			if len(res.samples) < 5 {
				res.samples = append(res.samples, errSamples...)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	res.dur = time.Since(start)
	sort.Slice(res.lat, func(i, j int) bool { return res.lat[i] < res.lat[j] })
	return res
}

// mock is an upstream with fixed latency; /v1/messages?sse=N streams N seconds of 1/s events.
type mock struct {
	*httptest.Server
	hits    atomic.Int64
	failing atomic.Bool
	name    string
}

func newMock(name string, lat time.Duration) *mock {
	m := &mock{name: name}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if m.failing.Load() {
			http.Error(w, `{"error":"overloaded"}`, http.StatusServiceUnavailable)
			return
		}
		if s := r.URL.Query().Get("sse"); s != "" {
			secs, _ := strconv.Atoi(s)
			w.Header().Set("Content-Type", "text/event-stream")
			f := w.(http.Flusher)
			for i := 0; i < secs; i++ {
				fmt.Fprintf(w, "event: ping\ndata: %d\n\n", i)
				f.Flush()
				select {
				case <-time.After(time.Second):
				case <-r.Context().Done():
					return
				}
			}
			fmt.Fprint(w, "event: message_stop\ndata: {}\n\n")
			return
		}
		time.Sleep(lat)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"msg_1","from":%q,"content":[{"type":"text","text":"hello"}]}`, m.name)
	}))
	return m
}

// longSSE opens one stream through the proxy and verifies every event and the terminator arrive.
func longSSE(url, tok string, secs int) (string, bool) {
	req, _ := http.NewRequest("POST", url+"/v1/messages?sse="+strconv.Itoa(secs), strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	t0 := time.Now()
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "request: " + err.Error(), false
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	n := strings.Count(string(b), "event: ping")
	ok := err == nil && n == secs && strings.Contains(string(b), "message_stop")
	return fmt.Sprintf("status=%d events=%d/%d terminated=%v after=%v err=%v", resp.StatusCode, n, secs,
		strings.Contains(string(b), "message_stop"), time.Since(t0).Round(time.Millisecond), err), ok
}

type sample struct {
	t         time.Duration
	goroutine int
	heapMB    float64
	rssMB     float64
}

func scrape(admin string, pid int) sample {
	var s sample
	resp, err := http.Get("http://" + admin + "/metrics")
	if err == nil {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 2 && f[0] == "go_goroutines" {
				s.goroutine, _ = strconv.Atoi(f[1])
			}
			if len(f) == 2 && f[0] == "go_memstats_heap_inuse_bytes" {
				v, _ := strconv.ParseFloat(f[1], 64)
				s.heapMB = v / 1e6
			}
		}
	}
	out, _ := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	kb, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	s.rssMB = kb / 1024
	return s
}

func metric(admin, prefix string) string {
	resp, err := http.Get("http://" + admin + "/metrics")
	if err != nil {
		return err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return strings.Join(out, " | ")
}

func freeAddr() string {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func main() {
	flag.Parse()
	run := run
	if *target != "" {
		run = runTarget
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	if failedAny.Load() {
		os.Exit(1)
	}
}

func check(ok bool, format string, a ...any) {
	st := "PASS"
	if !ok {
		st, _ = "FAIL", failedAny.Swap(true)
	}
	fmt.Printf("  [%s] %s\n", st, fmt.Sprintf(format, a...))
}

func run() error {
	ctx := context.Background()
	fmt.Printf("# machine: %s/%s, %d CPUs, %s; upstream latency %v, workers %d\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version(), *latency, *conc)

	up, pri, sec := newMock("up", *latency), newMock("primary", *latency), newMock("secondary", *latency)
	defer up.Close()
	defer pri.Close()
	defer sec.Close()

	iss, err := identitytest.NewIssuer("k1")
	if err != nil {
		return err
	}
	isrv := iss.Serve()
	defer isrv.Close()
	const aud = "halo-gateway"
	tok, err := iss.Mint(map[string]any{"aud": aud, "email": "load@acme.com", "groups": []string{"ai-platform"}})
	if err != nil {
		return err
	}
	rt := func(u, m string) policy.ModelRoute { return policy.ModelRoute{Upstream: u, Model: m} }
	org := &policy.Org{
		Name:     "acme",
		Identity: policy.Identity{Issuer: iss.URL, Audience: aud},
		Gateway: &policy.Gateway{
			Models: map[string]policy.ModelRoute{"sonnet": rt("up", "real"), "fo": {Targets: []policy.RouteTarget{
				{Upstream: "pri", Model: "real", Priority: 0}, {Upstream: "sec", Model: "real", Priority: 1}}}},
			Upstreams: map[string]policy.Upstream{"up": {URL: up.URL, Kind: "anthropic"}, "pri": {URL: pri.URL, Kind: "anthropic"}, "sec": {URL: sec.URL, Kind: "anthropic"}},
		},
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "ring0"}, Order: 0, Membership: policy.Membership{Groups: []string{"ai-platform"}}},
			{Meta: policy.Meta{Name: "ga"}, Order: 1, Membership: policy.Membership{Default: true}},
		},
	}
	dir, err := os.MkdirTemp("", "haloload")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	pol, err := policy.Compile(org)
	if err != nil {
		return err
	}
	polPath, cfgPath := filepath.Join(dir, "policy.json"), filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(polPath, pol, 0o600); err != nil {
		return err
	}
	listen, admin := freeAddr(), freeAddr()
	cfg := fmt.Sprintf("listen: %s\nadminListen: %s\npolicy: %s\nroute:\n  maxAttempts: 3\n  breakerFailures: 5\n  breakerCooldown: %s\n", listen, admin, polPath, *cooldown)
	if *readTO != "" {
		cfg += "readTimeout: " + *readTO + "\n"
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return err
	}
	cmd := exec.Command(*bin, "--config", cfgPath)
	cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr // per-request JSON logs go to stdout; discard
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	for i := 0; ; i++ {
		if resp, err := http.Get("http://" + admin + "/healthz"); err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			break
		}
		if i > 100 {
			return fmt.Errorf("halo-proxy did not become healthy")
		}
		time.Sleep(100 * time.Millisecond)
	}
	px := "http://" + listen + "/v1/messages"
	drive(ctx, px, tok, reqBody, 8, 2*time.Second) // warm-up (JWKS fetch, conn pools)

	fmt.Println("\n## 1. added latency + throughput (same closed-loop load, direct vs via proxy)")
	direct := drive(ctx, up.URL+"/v1/messages", "", reqBody, *conc, *phase)
	via := drive(ctx, px, tok, reqBody, *conc, *phase)
	fmt.Println("  direct:", direct)
	fmt.Println("  proxy: ", via)
	fmt.Printf("  added latency: p50=%v p95=%v p99=%v\n", (via.pct(.5) - direct.pct(.5)).Round(10*time.Microsecond),
		(via.pct(.95) - direct.pct(.95)).Round(10*time.Microsecond), (via.pct(.99) - direct.pct(.99)).Round(10*time.Microsecond))
	check(via.errs == 0, "proxy error rate %d", via.errs)

	fmt.Println("\n## 2. failover + circuit breaker (primary fails, secondary healthy)")
	fpx := px
	h0 := drive(ctx, fpx, tok, foBody, *conc, *phase/2)
	fmt.Println("  healthy:        ", h0, "primary hits", pri.hits.Load(), "secondary hits", sec.hits.Load())
	pri.failing.Store(true)
	p1, s1 := pri.hits.Load(), sec.hits.Load()
	f := drive(ctx, fpx, tok, foBody, *conc, *phase)
	pf, sf := pri.hits.Load()-p1, sec.hits.Load()-s1
	fmt.Println("  primary failing:", f, "primary hits", pf, "secondary hits", sf)
	fmt.Println("  proxy:", metric(admin, "halo_proxy_upstream_attempts_total"))
	check(f.errs == 0, "client-visible errors during primary outage: %d", f.errs)
	// Breaker open: primary sees ~threshold + one probe per cooldown, not every request.
	maxPri := int64(5+*conc) + int64(phase.Seconds()/cooldown.Seconds()+1)
	check(pf <= maxPri, "primary received %d of %d requests (breaker cap %d)", pf, pf+sf, maxPri)
	pri.failing.Store(false)
	time.Sleep(*cooldown + time.Second)
	p2 := pri.hits.Load()
	r := drive(ctx, fpx, tok, foBody, *conc, *phase/2)
	fmt.Println("  recovered:      ", r, "primary hits", pri.hits.Load()-p2)
	check(r.errs == 0 && pri.hits.Load()-p2 > 0, "primary back in rotation after cooldown")

	fmt.Printf("\n## 3. soak %v + %d concurrent %v SSE streams (re-opened back to back)\n", *soak, *sseN, *sseDur)
	var wg sync.WaitGroup
	var sseMu sync.Mutex
	var sseOK, sseTotal int
	soakEnd := time.Now().Add(*soak)
	runSSE := func() {
		for i := 0; i < *sseN; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for first := true; first || time.Now().Add(*sseDur).Before(soakEnd); first = false {
					msg, ok := longSSE("http://"+listen, tok, int(sseDur.Seconds()))
					sseMu.Lock()
					fmt.Println("  sse stream:", msg)
					sseTotal++
					if ok {
						sseOK++
					}
					sseMu.Unlock()
				}
			}()
		}
	}
	runSSE()
	base := scrape(admin, cmd.Process.Pid)
	fmt.Printf("  t=0s    goroutines=%d heap=%.1fMB rss=%.1fMB (with %d SSE open)\n", base.goroutine, base.heapMB, base.rssMB, *sseN)
	stop := make(chan struct{})
	var samples []sample
	var smu sync.WaitGroup
	smu.Add(1)
	go func() {
		defer smu.Done()
		t0 := time.Now()
		tk := time.NewTicker(*sampleEvery)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				s := scrape(admin, cmd.Process.Pid)
				s.t = time.Since(t0)
				samples = append(samples, s)
				fmt.Printf("  t=%-6v goroutines=%d heap=%.1fMB rss=%.1fMB\n", s.t.Round(time.Second), s.goroutine, s.heapMB, s.rssMB)
			}
		}
	}()
	sr := drive(ctx, px, tok, reqBody, *conc, *soak)
	close(stop)
	smu.Wait()
	fmt.Println("  soak load:", sr)
	for _, e := range sr.samples {
		fmt.Println("  soak error:", e)
	}
	wg.Wait()
	check(sr.errs == 0, "soak errors %d", sr.errs)
	check(sseOK == sseTotal && sseTotal >= *sseN, "%d/%d long SSE streams of %v completed uncut", sseOK, sseTotal, *sseDur)
	time.Sleep(3 * time.Second) // let idle conns settle
	end := scrape(admin, cmd.Process.Pid)
	fmt.Printf("  idle after soak: goroutines=%d heap=%.1fMB rss=%.1fMB (baseline %d / %.1f / %.1f)\n", end.goroutine, end.heapMB, end.rssMB, base.goroutine, base.heapMB, base.rssMB)
	// Leak signal: goroutines after load stops should fall back near the baseline (idle keep-alive conns excepted).
	check(end.goroutine < base.goroutine+2**conc+10, "goroutines return to baseline after load (%d -> %d)", base.goroutine, end.goroutine)

	// Leak slopes over the steady state (first third discarded as warm-up): a leak is growth that
	// does not stop, which an end-vs-start comparison cannot tell from a still-filling cache.
	hs, gs, n := steadySlopes(samples)
	if n >= 20 {
		check(hs <= *maxHeap, "heap_inuse steady-state slope %+.2f MB/h <= %.0f (%d samples)", hs, *maxHeap, n)
		check(gs <= *maxGor, "goroutine steady-state slope %+.2f /h <= %.0f (%d samples)", gs, *maxGor, n)
	} else {
		fmt.Printf("  [SKIP] leak slopes need >= 20 steady samples, have %d (use a longer -soak or a smaller -sample)\n", n)
	}

	sum := summary{
		Version: 1, Machine: fmt.Sprintf("%s/%s %d CPUs %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version()),
		Workers: *conc, UpstreamLatencyMS: ms(*latency), Soak: soak.String(),
		ProxyP50MS: ms(via.pct(.5)), ProxyP99MS: ms(via.pct(.99)), AddedP99MS: ms(via.pct(.99) - direct.pct(.99)),
		SoakP50MS: ms(sr.pct(.5)), SoakP99MS: ms(sr.pct(.99)), SoakRPS: float64(len(sr.lat)+sr.errs) / sr.dur.Seconds(), SoakErrors: sr.errs,
		HeapSlopeMBPerHour: hs, GoroutineSlopePerHour: gs, SteadySamples: n,
		HeapBaseMB: base.heapMB, HeapEndMB: end.heapMB, GoroutinesBase: base.goroutine, GoroutinesEnd: end.goroutine,
		SSEOK: sseOK, SSETotal: sseTotal,
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(sum, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o600); err != nil {
			return err
		}
	}
	if *baseline != "" {
		compareBaseline(*baseline, sum)
	}
	return nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// summary is the machine-readable result (-json-out) and the baseline file format (-baseline).
type summary struct {
	Version               int     `json:"version"`
	Machine               string  `json:"machine"`
	Workers               int     `json:"workers"`
	UpstreamLatencyMS     float64 `json:"upstream_latency_ms"`
	Soak                  string  `json:"soak"`
	ProxyP50MS            float64 `json:"proxy_p50_ms"`
	ProxyP99MS            float64 `json:"proxy_p99_ms"`
	AddedP99MS            float64 `json:"added_p99_ms"`
	SoakP50MS             float64 `json:"soak_p50_ms"`
	SoakP99MS             float64 `json:"soak_p99_ms"`
	SoakRPS               float64 `json:"soak_rps"`
	SoakErrors            int     `json:"soak_errors"`
	HeapSlopeMBPerHour    float64 `json:"heap_slope_mb_per_hour"`
	GoroutineSlopePerHour float64 `json:"goroutine_slope_per_hour"`
	SteadySamples         int     `json:"steady_samples"`
	HeapBaseMB            float64 `json:"heap_base_mb"`
	HeapEndMB             float64 `json:"heap_end_mb"`
	GoroutinesBase        int     `json:"goroutines_base"`
	GoroutinesEnd         int     `json:"goroutines_end"`
	SSEOK                 int     `json:"sse_ok"`
	SSETotal              int     `json:"sse_total"`
}

// compareBaseline fails a p99 only when it is worse by BOTH the relative tolerance and the
// absolute floor, so sub-millisecond jitter on a shared runner is not a regression.
func compareBaseline(path string, cur summary) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		fmt.Printf("  [SKIP] no baseline at %s: recording only (commit this run's -json-out as the baseline once reviewed)\n", path)
		return
	}
	var base summary
	if err == nil {
		err = json.Unmarshal(b, &base)
	}
	if err != nil {
		check(false, "baseline %s unreadable: %v", path, err)
		return
	}
	for _, c := range []struct {
		name      string
		now, then float64
	}{{"proxy p99", cur.ProxyP99MS, base.ProxyP99MS}, {"soak p99", cur.SoakP99MS, base.SoakP99MS}} {
		limit := c.then * (1 + *p99Tol)
		bad := c.now > limit && c.now-c.then > ms(*p99Floor)
		check(!bad, "%s %.2fms vs baseline %.2fms (limit %.2fms = +%.0f%%, floor %v)", c.name, c.now, c.then, limit, 100**p99Tol, *p99Floor)
	}
}

// steadySlopes returns the least-squares slopes of heap_inuse (MB/h) and goroutines (/h) over the
// samples after the first third, and how many samples that used.
func steadySlopes(all []sample) (heapMBh, gorH float64, n int) {
	s := all[len(all)/3:]
	if len(s) < 2 {
		return 0, 0, len(s)
	}
	slope := func(y func(sample) float64) float64 {
		var sx, sy, sxx, sxy float64
		for _, p := range s {
			x := p.t.Hours()
			sx, sy, sxx, sxy = sx+x, sy+y(p), sxx+x*x, sxy+x*y(p)
		}
		k := float64(len(s))
		if d := k*sxx - sx*sx; d != 0 {
			return (k*sxy - sx*sy) / d
		}
		return 0
	}
	return slope(func(p sample) float64 { return p.heapMB }), slope(func(p sample) float64 { return float64(p.goroutine) }), len(s)
}

// runTarget drives an already-running proxy and fails on any client-visible error.
func runTarget() error {
	tok := *token
	if tok == "" {
		tok = os.Getenv("LOAD_TOKEN")
	}
	// SIGINT/SIGTERM end the run early and still report (scripts/uat-k8s.sh stops the load once its disruption is over).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_tokens":8}`, *model)
	driveRPS = *rps
	res := drive(ctx, *target, tok, body, *conc, *duration)
	fmt.Println("  target load:", res)
	for _, e := range res.samples {
		fmt.Println("  error:", e)
	}
	check(res.errs == 0, "client-visible errors: %d of %d requests", res.errs, len(res.lat)+res.errs)
	check(len(res.lat) > 0, "requests completed: %d", len(res.lat))
	return nil
}
