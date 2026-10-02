// Command load drives a real halo-proxy binary against mock upstreams and
// reports added latency, throughput, errors, memory/goroutine growth over a
// soak, failover + circuit-breaker behaviour, and long-lived SSE integrity.
//
//	go build -o bin/halo-proxy ./cmd/halo-proxy && go run ./test/load -bin bin/halo-proxy
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
)

var (
	bin       = flag.String("bin", "bin/halo-proxy", "halo-proxy binary")
	conc      = flag.Int("c", 32, "concurrent workers per phase")
	latency   = flag.Duration("latency", 50*time.Millisecond, "fixed mock upstream latency")
	phase     = flag.Duration("phase", 20*time.Second, "duration of the latency and failover phases")
	soak      = flag.Duration("soak", 3*time.Minute, "soak duration (memory / goroutine growth)")
	sseDur    = flag.Duration("sse", 60*time.Second, "length of each long SSE stream (events every 1s)")
	sseN      = flag.Int("sse-streams", 4, "concurrent long SSE streams, run during the soak")
	readTO    = flag.String("read-timeout", "", "override halo-proxy readTimeout (e.g. 20s) to test stream survival past it")
	cooldown  = flag.Duration("breaker-cooldown", 5*time.Second, "breaker cooldown for the failover phase")
	reqBody   = `{"model":"sonnet","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`
	foBody    = `{"model":"fo","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`
	failedAny atomic.Bool
)

type result struct {
	lat  []time.Duration
	errs int
	dur  time.Duration
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
			errs := 0
			for ctx.Err() == nil {
				t0 := time.Now()
				req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
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
					continue
				}
				lat = append(lat, time.Since(t0))
			}
			mu.Lock()
			res.lat, res.errs = append(res.lat, lat...), res.errs+errs
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

	fmt.Printf("\n## 3. soak %v + %d concurrent %v SSE streams\n", *soak, *sseN, *sseDur)
	var wg sync.WaitGroup
	var sseMu sync.Mutex
	var sseOK int
	runSSE := func() {
		for i := 0; i < *sseN; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				msg, ok := longSSE("http://"+listen, tok, int(sseDur.Seconds()))
				sseMu.Lock()
				defer sseMu.Unlock()
				fmt.Println("  sse stream:", msg)
				if ok {
					sseOK++
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
		tk := time.NewTicker(10 * time.Second)
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
	wg.Wait()
	check(sr.errs == 0, "soak errors %d", sr.errs)
	check(sseOK == *sseN, "%d/%d long SSE streams of %v completed uncut", sseOK, *sseN, *sseDur)
	time.Sleep(3 * time.Second) // let idle conns settle
	end := scrape(admin, cmd.Process.Pid)
	fmt.Printf("  idle after soak: goroutines=%d heap=%.1fMB rss=%.1fMB (baseline %d / %.1f / %.1f)\n", end.goroutine, end.heapMB, end.rssMB, base.goroutine, base.heapMB, base.rssMB)
	// Leak signal: goroutines after load stops should fall back near the baseline (idle keep-alive conns excepted).
	check(end.goroutine < base.goroutine+2**conc+10, "goroutines return to baseline after load (%d -> %d)", base.goroutine, end.goroutine)
	return nil
}
