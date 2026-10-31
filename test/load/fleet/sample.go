//go:build loadfleet

package main

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// phaseSample is the server process's resource use over one phase.
type phaseSample struct {
	RSSStartMB, RSSEndMB, RSSMaxMB float64
	CPUAvgPct, CPUMaxPct           float64 // percent of one core
}

type sampleResult struct {
	PID    int
	Ramp   phaseSample
	Steady phaseSample
}

type point struct {
	t   time.Time
	rss float64 // MB
	cpu float64 // cumulative CPU seconds
}

// sampler polls ps for the server's RSS and cumulative CPU time (portable
// between macOS and Linux; the server has no pprof or process metrics).
type sampler struct {
	pid   int
	phase *atomic.Int32
	mu    sync.Mutex
	pts   [2][]point
	done  chan struct{}
}

func startSampler(ctx context.Context, pid int, phase *atomic.Int32) *sampler {
	s := &sampler{pid: pid, phase: phase, done: make(chan struct{})}
	if pid == 0 {
		close(s.done)
		return s
	}
	s.take()
	go func() {
		defer close(s.done)
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.take()
			}
		}
	}()
	return s
}

// mark takes a sample at the ramp/steady boundary so both phases have
// a start point.
func (s *sampler) mark() {
	if s.pid == 0 {
		return
	}
	p, ok := readProc(s.pid)
	if !ok {
		return
	}
	s.mu.Lock()
	s.pts[0] = append(s.pts[0], p)
	s.pts[1] = append(s.pts[1], p)
	s.mu.Unlock()
}

func (s *sampler) take() {
	p, ok := readProc(s.pid)
	if !ok {
		return
	}
	s.mu.Lock()
	i := s.phase.Load()
	s.pts[i] = append(s.pts[i], p)
	s.mu.Unlock()
}

func (s *sampler) stop() *sampleResult {
	if s.pid == 0 {
		return nil
	}
	<-s.done
	s.take()
	s.mu.Lock()
	defer s.mu.Unlock()
	return &sampleResult{PID: s.pid, Ramp: summarize(s.pts[0]), Steady: summarize(s.pts[1])}
}

func summarize(p []point) phaseSample {
	var o phaseSample
	if len(p) == 0 {
		return o
	}
	o.RSSStartMB, o.RSSEndMB = p[0].rss, p[len(p)-1].rss
	for i, x := range p {
		o.RSSMaxMB = max(o.RSSMaxMB, x.rss)
		if i > 0 {
			if dt := x.t.Sub(p[i-1].t).Seconds(); dt >= 1 {
				o.CPUMaxPct = max(o.CPUMaxPct, 100*(x.cpu-p[i-1].cpu)/dt)
			}
		}
	}
	if dt := p[len(p)-1].t.Sub(p[0].t).Seconds(); dt > 0 {
		o.CPUAvgPct = 100 * (p[len(p)-1].cpu - p[0].cpu) / dt
	}
	return o
}

// readProc reads RSS (KB) and cputime from ps. cputime is [[dd-]hh:]mm:ss[.ff].
func readProc(pid int) (point, bool) {
	out, err := exec.Command("ps", "-o", "rss=,cputime=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return point{}, false
	}
	f := strings.Fields(string(out))
	if len(f) != 2 {
		return point{}, false
	}
	kb, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return point{}, false
	}
	return point{t: time.Now(), rss: kb / 1024, cpu: parseCPUTime(f[1])}, true
}

func parseCPUTime(s string) float64 {
	days := 0.0
	if d, rest, ok := strings.Cut(s, "-"); ok {
		days, _ = strconv.ParseFloat(d, 64)
		s = rest
	}
	sec := 0.0
	for _, part := range strings.Split(s, ":") {
		v, _ := strconv.ParseFloat(part, 64)
		sec = sec*60 + v
	}
	return days*86400 + sec
}

// routeStat is the server's own view of one route's latency.
type routeStat struct {
	Route  string
	Count  uint64
	MeanMs float64
}

// fleetRoute reports whether route is one the generator exercises.
func fleetRoute(route string) bool {
	for _, p := range []string{"POST /api/v1/fleet", "GET /api/v1/fleet", "POST /api/v1/enroll", "POST /api/v1/launch", "GET /api/v1/devices"} {
		if strings.HasPrefix(route, p) {
			return true
		}
	}
	return false
}

// scrapeMetrics reads halo_server_request_duration_seconds sum and count per route.
func scrapeMetrics(hc *http.Client, url string) []routeStat {
	if url == "" {
		return nil
	}
	resp, err := hc.Get(url)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	type acc struct {
		sum float64
		n   uint64
	}
	by := map[string]*acc{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20))
	for sc.Scan() {
		line := sc.Text()
		var isSum bool
		switch {
		case strings.HasPrefix(line, "halo_server_request_duration_seconds_sum{"):
			isSum = true
		case strings.HasPrefix(line, "halo_server_request_duration_seconds_count{"):
		default:
			continue
		}
		i, j := strings.Index(line, `route="`), strings.LastIndex(line, "} ")
		if i < 0 || j < 0 {
			continue
		}
		route, _, _ := strings.Cut(line[i+len(`route="`):], `"`)
		v, err := strconv.ParseFloat(line[j+2:], 64)
		if err != nil || !fleetRoute(route) {
			continue
		}
		a := by[route]
		if a == nil {
			a = &acc{}
			by[route] = a
		}
		if isSum {
			a.sum += v
		} else {
			a.n += uint64(v)
		}
	}
	var out []routeStat
	for r, a := range by {
		if a.n > 0 {
			out = append(out, routeStat{Route: r, Count: a.n, MeanMs: 1000 * a.sum / float64(a.n)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Route < out[j].Route })
	return out
}
