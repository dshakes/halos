//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
)

// Closed loop, every hop real: synthetic users -> halo-proxy (JWT identity,
// variant routing) -> mock upstreams; halo-proxy's gwmetrics -> the collector's
// authenticated gateway receiver -> ClickHouse; halo-server --controller reads
// ClickHouse, decides, signs the kill list; halo-proxy polls it and stops
// routing to the candidate. Nothing is faked between the upstream and the kill.
const (
	loopUsersPerArm = 60
	loopMinSamples  = 50
	loopWorkers     = 8
	// loopKillPoll is halo-proxy's documented default kill-list poll
	// (cmd/halo-proxy/README.md#kill-switch); the proxy runs with the default.
	loopKillPoll = 10 * time.Second
	// loopSlack: one in-flight request plus the kill-list fetch itself.
	loopSlack = 2 * time.Second
	// loopDetectWithin bounds detection: halo-server's minimum --interval is 1m, and
	// data must land before a tick can decide (tick at 0s, 60s, 120s, ...).
	loopDetectWithin = 3*time.Minute + 30*time.Second
)

// loopExperiment mirrors what `halo model switch --canary` generates for the
// traffic axis (internal/intent/rollout.go trafficGuardrails), standalone (no
// Rollout), so the controller's own experiment verdicts act on it; primary is
// p50 latency so a faster candidate has something to win on.
const loopExperiment = `apiVersion: halos.dev/v1
kind: Experiment
name: %s
type: ab
axis: traffic
status: running
rings: [ring0-canary, ring1-ga]
variants:
  - {name: control, weight: 50, control: true}
  - name: candidate
    weight: 50
    routes:
      sonnet: {upstream: candidate, model: claude-sonnet-next}
metrics:
  primary: {metric: halo.latency.p50_ms, direction: decrease}
  guardrails:
    - {metric: halo.api.error_rate, direction: decrease, maxRegression: 0.05}
    - {metric: halo.latency.p95_ms, direction: decrease, maxRegression: 0.15}
stopping: {method: msprt, alpha: 0.05, minSamples: %d, maxDays: 14}
`

// upstream is a mock Anthropic Messages endpoint: base latency (lognormal,
// sigma 0.15) and a fraction of fast 529 "overloaded" answers. It logs the
// arrival time of every request it serves: the ground truth for "routed to".
type upstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	rng     *rand.Rand
	hits    []time.Time
	latency time.Duration
	errRate float64
}

func newUpstream(t *testing.T, seed int64, latency time.Duration, errRate float64) *upstream {
	u := &upstream{rng: rand.New(rand.NewSource(seed)), latency: latency, errRate: errRate}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		u.mu.Lock()
		u.hits = append(u.hits, time.Now())
		fail := u.rng.Float64() < u.errRate
		d := time.Duration(float64(u.latency) * math.Exp(0.15*u.rng.NormFloat64()))
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if fail {
			time.Sleep(5 * time.Millisecond)
			w.WriteHeader(529)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`)
			return
		}
		time.Sleep(d)
		_, _ = io.WriteString(w, `{"id":"msg_e2e","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// served returns the hits in [from, to).
func (u *upstream) served(from, to time.Time) (n int, last time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, h := range u.hits {
		if !h.Before(from) && h.Before(to) {
			n++
			if h.After(last) {
				last = h
			}
		}
	}
	return n, last
}

type loopRig struct {
	exp, dir, data, keys, base, proxy string
	repo                              rolloutRepo
	control, cand                     *upstream
	tokens                            []string // one JWT per user, both arms
	verdicts                          string
}

// newLoopRig brings up the policy repo, halo-server --controller (real
// ClickHouse) and halo-proxy (gateway telemetry to the collector, kill list
// from halo-server, both at their default intervals).
func newLoopRig(t *testing.T, exp string, cand *upstream) *loopRig {
	t.Helper()
	ch := "http://127.0.0.1:" + obsPort(t, "HALO_OBS_CH_HTTP_PORT")
	gwOTLP := "http://127.0.0.1:" + obsPort(t, "HALO_OBS_OTLP_GATEWAY_PORT")
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iss.Serve().Close)

	r := &loopRig{exp: exp, dir: t.TempDir(), cand: cand, control: newUpstream(t, 1, 30*time.Millisecond, 0)}
	pol := filepath.Join(r.dir, "policy")
	gatewayPolicy(t, pol, iss.URL, r.control.srv.URL, cand.srv.URL)
	if err := os.Remove(filepath.Join(pol, "experiments/shadow.yaml")); err != nil { // this experiment only
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(pol, "experiments", exp+".yaml"), fmt.Sprintf(loopExperiment, exp, loopMinSamples))
	if res := run(t, nil, "", "halo", "validate", pol); res.code != 0 {
		t.Fatalf("policy invalid: %s", res)
	}
	org, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	var e *policy.Experiment
	for _, x := range org.Experiments {
		if x.Name == exp {
			e = x
		}
	}
	// loopUsersPerArm users per variant, by the gateway's own assignment.
	per := map[string]int{}
	for i := 0; i < 5000 && len(r.tokens) < 2*loopUsersPerArm; i++ {
		u := fmt.Sprintf("%s-dev%d@acme.com", exp, i)
		ring := org.ResolveRing(policy.Subject{ID: u})
		if ring == nil {
			continue
		}
		v := e.ResolveVariant(policy.Subject{ID: u}, ring.Name)
		if v == nil || per[v.Name] >= loopUsersPerArm {
			continue
		}
		per[v.Name]++
		r.tokens = append(r.tokens, mint(t, iss, u))
	}
	if per["control"] != loopUsersPerArm || per["candidate"] != loopUsersPerArm {
		t.Fatalf("users per variant %v, want %d each", per, loopUsersPerArm)
	}

	r.repo = gitRepo(t, r.dir, pol)
	clone := filepath.Join(r.dir, "clone") // the controller's PR clone: never the served dir
	if out, err := exec.Command("git", "clone", "-q", r.repo.origin, clone).CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v %s", err, out)
	}
	git(t, clone, "config", "user.name", "halo-controller")
	git(t, clone, "config", "user.email", "halo-controller@example.com")

	r.data, r.keys, r.verdicts = filepath.Join(r.dir, "data"), filepath.Join(r.dir, "keys"), filepath.Join(r.dir, "verdicts.json")
	must(t, nil, "halo", "keys", "generate", "--name", "killswitch", "--out", r.keys)
	writeFile(t, filepath.Join(r.dir, "fleet.token"), "e2e-fleet-token\n")
	writeFile(t, filepath.Join(r.dir, "gateway.token"), "e2e-gateway-token-0123456789\n")
	writeFile(t, filepath.Join(r.dir, "ch.pass"), chPass+"\n")
	writeFile(t, filepath.Join(r.dir, "otlp.token"), gatewayToken+"\n")
	writeFile(t, filepath.Join(r.dir, "unit.salt"), "closed-loop-e2e\n")
	writeFile(t, filepath.Join(r.dir, "session.key"), "e2e-session-key-0123456789abcdef0123456789abcdef\n")
	addr := freeAddr(t)
	r.base = "http://" + addr
	pc, _ := json.Marshal(map[string]any{"baseURL": r.base, "sessionKeyFile": filepath.Join(r.dir, "session.key")})
	writeFile(t, filepath.Join(r.dir, "portal.json"), string(pc))
	start(t, r.repo.env, "halo-server", "--listen", addr, "--policy-dir", pol, "--token-file", filepath.Join(r.dir, "fleet.token"),
		"--portal-config", filepath.Join(r.dir, "portal.json"),
		"--data-dir", r.data, "--killswitch-key-file", filepath.Join(r.keys, "killswitch.key"),
		"--gateway-token-file", filepath.Join(r.dir, "gateway.token"), "--verdicts-file", r.verdicts,
		"--controller", "--interval", "1m", "--clickhouse-url", ch, "--clickhouse-database", "halo",
		"--clickhouse-user", chUser, "--clickhouse-password-file", filepath.Join(r.dir, "ch.pass"),
		"--policy-repo-dir", clone, "--policy-repo-base", "main")
	waitUp(t, r.base+"/healthz", 200)

	snap := filepath.Join(r.dir, "policy.json")
	must(t, nil, "halo", "gateway", "compile", pol, "-o", snap)
	proxyAddr, adminAddr := freeAddr(t), freeAddr(t)
	r.proxy = "http://" + proxyAddr
	start(t, nil, "halo-proxy", "--listen", proxyAddr, "--admin-listen", adminAddr, "--policy", snap,
		"--killswitch-url", r.base+"/api/v1/gateway/killswitch", "--killswitch-token-file", filepath.Join(r.dir, "gateway.token"),
		"--killswitch-pubkey-file", filepath.Join(r.keys, "killswitch.pub"),
		"--telemetry-otlp-endpoint", gwOTLP, "--telemetry-token-file", filepath.Join(r.dir, "otlp.token"),
		"--telemetry-unit-salt-file", filepath.Join(r.dir, "unit.salt"))
	waitUp(t, "http://"+adminAddr+"/healthz", 200)
	return r
}

// drive sends model calls round-robin over every user until ctx ends. Returns
// the time of the first request and a wait for the workers.
func (r *loopRig) drive(ctx context.Context, t *testing.T) (t0 time.Time, wait func() (sent, failed int)) {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: loopWorkers}}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var sent, failed int
	body := `{"model":"sonnet","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`
	t0 = time.Now()
	for w := 0; w < loopWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; ctx.Err() == nil; i += loopWorkers {
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.proxy+"/v1/messages", strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+r.tokens[i%len(r.tokens)])
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("anthropic-version", "2023-06-01")
				req.Header.Set("User-Agent", "claude-cli/2.1.300 (external, cli)")
				resp, err := client.Do(req)
				if err != nil && ctx.Err() != nil {
					return // stopped mid-request
				}
				ok := err == nil && resp.StatusCode == http.StatusOK
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				mu.Lock()
				sent++
				if !ok { // a dead proxy shows up as failures, not a silent spin
					failed++
				}
				mu.Unlock()
			}
		}()
	}
	return t0, func() (int, int) { wg.Wait(); return sent, failed }
}

// verdict is the experiment's row in the controller's verdicts file.
func (r *loopRig) verdict(t *testing.T) (v struct {
	Verdict, Reason, Source string
	EvaluatedAt             time.Time
}) {
	t.Helper()
	b, err := os.ReadFile(r.verdicts)
	if os.IsNotExist(err) {
		return v
	} else if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Experiment, Verdict, Reason, Source string
		EvaluatedAt                         time.Time
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		return v // mid-write is impossible (atomic rename), but never fail on a torn read
	}
	for _, x := range rows {
		if x.Experiment == r.exp {
			v.Verdict, v.Reason, v.Source, v.EvaluatedAt = x.Verdict, x.Reason, x.Source, x.EvaluatedAt
		}
	}
	return v
}

// killedAt is when halo-server recorded the kill (killswitch.jsonl).
func (r *loopRig) killedAt(t *testing.T) (at time.Time, by, reason string) {
	t.Helper()
	f, err := os.Open(filepath.Join(r.data, "killswitch.jsonl"))
	if os.IsNotExist(err) {
		return
	} else if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var k struct {
			Experiment, By, Reason string
			Killed                 bool
			At                     time.Time
		}
		if json.Unmarshal(sc.Bytes(), &k) == nil && k.Experiment == r.exp && k.Killed {
			at, by, reason = k.At, k.By, k.Reason
		}
	}
	return
}

// TestObsClosedLoop: one traffic-axis experiment per case, decided only from
// metrics halo-proxy recorded for real traffic. Regressed candidate: the
// controller rolls back on gateway evidence, the signed kill lands, the proxy
// stops routing to the candidate within one documented poll, a pause PR opens
// and nothing is promoted or merged. Healthy candidate: no kill, a promotion PR
// (never merged). Logs time-to-detect, time-to-kill and post-kill requests.
func TestObsClosedLoop(t *testing.T) {
	obsPort(t, "HALO_OBS_CH_HTTP_PORT")                 // skip outside scripts/obs-e2e.sh
	suffix := fmt.Sprint(time.Now().Unix() % 1_000_000) // ClickHouse outlives a run when the stack is reused

	t.Run("regressed candidate is killed", func(t *testing.T) {
		t.Parallel()
		// Overloaded new model: 30% fast 529s, successes 50% slower.
		r := newLoopRig(t, "loop-bad-"+suffix, newUpstream(t, 2, 45*time.Millisecond, 0.30))
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		t0, wait := r.drive(ctx, t)

		var killAt time.Time
		var by, reason string
		waitFor(t, loopDetectWithin, "the controller's kill of "+r.exp, func() bool {
			killAt, by, reason = r.killedAt(t)
			return !killAt.IsZero()
		})
		// Keep traffic flowing for a full poll window past the bound, so a
		// gateway that never converges is caught.
		time.Sleep(time.Until(killAt.Add(loopKillPoll + loopSlack + loopKillPoll)))
		stop()
		sent, failed := wait()
		end := time.Now()

		v := r.verdict(t)
		before, _ := r.cand.served(t0, killAt)
		after, last := r.cand.served(killAt, end)
		ctlAfter, _ := r.control.served(killAt.Add(loopKillPoll+loopSlack), end)
		converged := time.Duration(0) // kill recorded -> last request the candidate served
		if after > 0 {
			converged = last.Sub(killAt)
		}
		ms := func(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
		// time-to-detect: first request -> rollback verdict; time-to-kill: first
		// request -> the candidate's last request (the gateway has converged).
		t.Logf("closed-loop regression: time-to-detect=%s time-to-kill=%s (kill recorded +%s, gateway converged %s later) "+
			"bad-variant requests after the kill=%d (before: %d); sent=%d non-2xx=%d",
			ms(v.EvaluatedAt.Sub(t0)), ms(killAt.Sub(t0)+converged), ms(killAt.Sub(t0)), ms(converged), after, before, sent, failed)

		if v.Verdict != "rollback" || v.Source != "gateway" || !strings.HasPrefix(v.Reason, "guardrail halo.api.error_rate regressed") {
			t.Errorf("verdict %+v, want a gateway-sourced rollback on the halo.api.error_rate guardrail", v)
		}
		if by != "halo-controller" || !strings.Contains(reason, "halo.api.error_rate") {
			t.Errorf("kill by %q (%q), want the controller on the error-rate guardrail", by, reason)
		}
		if got := killList(t, r.base, r.keys); len(got) != 1 || got[0] != r.exp {
			t.Errorf("signed kill list %v, want [%s]", got, r.exp)
		}
		if before == 0 {
			t.Fatal("the candidate served nothing before the kill: the scenario measured nothing")
		}
		if bound := loopKillPoll + loopSlack; converged > bound {
			t.Errorf("candidate still served requests %s after the kill; documented poll window is %s", converged, loopKillPoll)
		}
		if ctlAfter == 0 {
			t.Error("control served nothing after the gateway converged: killed users were dropped, not routed to control")
		}
		// Rollback opens a pause PR; nothing is promoted, nothing merges.
		waitFor(t, 30*time.Second, "the pause PR", func() bool { return len(r.repo.prs(t)) > 0 })
		prs := strings.Join(r.repo.prs(t), "\n")
		if !strings.Contains(prs, "Pause experiment "+r.exp) || strings.Contains(prs, "Promote") {
			t.Errorf("gh calls: %s", prs)
		}
		r.repo.neverMerged(t)
		if exp := readFile(t, filepath.Join(r.repo.pol, "experiments", r.exp+".yaml")); !strings.Contains(exp, "status: running") {
			t.Errorf("served experiment changed without a merge:\n%s", exp)
		}
	})

	t.Run("healthy candidate gets a promotion proposal", func(t *testing.T) {
		t.Parallel()
		// Faster new model, no errors.
		r := newLoopRig(t, "loop-good-"+suffix, newUpstream(t, 3, 18*time.Millisecond, 0))
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		t0, wait := r.drive(ctx, t)

		waitFor(t, loopDetectWithin, "the promotion PR for "+r.exp, func() bool {
			return strings.Contains(strings.Join(r.repo.prs(t), "\n"), "Promote "+r.exp)
		})
		decided := time.Now()
		time.Sleep(loopKillPoll + loopSlack) // a kill, if any, would reach the proxy by now
		stop()
		sent, failed := wait()
		v := r.verdict(t)
		after, _ := r.cand.served(decided, time.Now())
		t.Logf("closed-loop healthy: time-to-promotion-proposal=%s (verdict at +%s) total sent=%d non-2xx=%d candidate requests after the verdict=%d",
			decided.Sub(t0).Round(time.Millisecond), v.EvaluatedAt.Sub(t0).Round(time.Millisecond), sent, failed, after)

		if v.Verdict != "promote" || !strings.HasPrefix(v.Reason, "primary halo.latency.p50_ms improved") {
			t.Errorf("verdict %+v, want promote on halo.latency.p50_ms", v)
		}
		if at, _, _ := r.killedAt(t); !at.IsZero() {
			t.Errorf("healthy candidate was killed at %s", at)
		}
		if got := killList(t, r.base, r.keys); len(got) != 0 {
			t.Errorf("signed kill list %v, want empty", got)
		}
		if after == 0 {
			t.Error("candidate stopped receiving traffic without a kill")
		}
		if failed != 0 {
			t.Errorf("%d non-2xx answers on a healthy route", failed)
		}
		// The proposal concludes the experiment on a branch; a human merges.
		prs := r.repo.prs(t)
		if len(prs) != 1 || !strings.Contains(prs[0], "--base main") || strings.Contains(prs[0], "Pause") {
			t.Errorf("gh calls: %q", prs)
		}
		var branch string
		for _, b := range strings.Fields(git(t, r.repo.origin, "for-each-ref", "--format=%(refname:short)", "refs/heads/")) {
			if b != "main" {
				branch = b
			}
		}
		if branch == "" || !strings.Contains(git(t, r.repo.origin, "show", branch+":experiments/"+r.exp+".yaml"), "status: concluded") {
			t.Errorf("no promotion branch concluding %s (branch %q)", r.exp, branch)
		}
		r.repo.neverMerged(t)
		if exp := readFile(t, filepath.Join(r.repo.pol, "experiments", r.exp+".yaml")); !strings.Contains(exp, "status: running") {
			t.Errorf("auto-promoted: served experiment changed without a merge:\n%s", exp)
		}
	})
}
