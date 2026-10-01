package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/promote"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func normals(rng *rand.Rand, n int, mu, sd float64) []float64 {
	x := make([]float64, n)
	for i := range x {
		x[i] = mu + sd*rng.NormFloat64()
	}
	return x
}

func testExp(name string) *policy.Experiment {
	return &policy.Experiment{
		Meta: policy.Meta{Name: name, Kind: policy.KindExperiment}, Axis: policy.AxisTraffic, Status: "running",
		Variants: []policy.Variant{{Name: "control", Control: true}, {Name: "candidate"}},
		Metrics: policy.Metrics{
			Primary:    policy.MetricGoal{Metric: "halo.task.success", Direction: "increase"},
			Guardrails: []policy.MetricGoal{{Metric: "halo.cost.usd_per_session", Direction: "decrease", MaxRegression: 0.10}},
		},
		Stopping: policy.Stopping{Method: "msprt", Alpha: 0.05, MinSamples: 100, MaxDays: 14},
	}
}

// source builds evidence yielding the wanted verdict (see promote's TestEvaluate).
func source(v promote.Verdict) *promote.MemorySource {
	rng := rand.New(rand.NewPCG(1, 1))
	mk := func(succC, succT, costC, costT float64, n int) map[string]map[string][]float64 {
		return map[string]map[string][]float64{
			"halo.task.success":         {"control": normals(rng, n, succC, 0.3), "candidate": normals(rng, n, succT, 0.3)},
			"halo.cost.usd_per_session": {"control": normals(rng, n, costC, 1), "candidate": normals(rng, n, costT, 1)},
		}
	}
	switch v {
	case promote.Promote:
		return &promote.MemorySource{Source: promote.SourceGateway, Start: start, Data: mk(0.6, 0.7, 5, 5, 1000)}
	case promote.Rollback:
		return &promote.MemorySource{Source: promote.SourceGateway, Start: start, Data: mk(0.6, 0.7, 5, 6, 1000)}
	case promote.Expired:
		return &promote.MemorySource{Source: promote.SourceGateway, Start: start.Add(-30 * 24 * time.Hour), Data: mk(0.6, 0.6, 5, 5, 300)}
	}
	return &promote.MemorySource{Source: promote.SourceGateway, Start: start, Data: mk(0.6, 0.6, 5, 5, 20)}
}

type call struct{ exp, status, title, body string }

type fakeWriter struct {
	mu    sync.Mutex
	calls []call
	err   error
}

func (w *fakeWriter) ProposeStatus(_ context.Context, exp, status, title, body string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return "", w.err
	}
	w.calls = append(w.calls, call{exp, status, title, body})
	return "https://github.test/pr/" + exp + "-" + status, nil
}

type fakeNotifier struct {
	mu     sync.Mutex
	events []Event
	err    error
}

func (n *fakeNotifier) Notify(_ context.Context, e Event) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.events = append(n.events, e)
	return nil
}

type failKill struct{}

func (failKill) Kill(context.Context, string, string, string) (bool, error) {
	return false, errors.New("disk full")
}

type rig struct {
	c     *Controller
	w     *fakeWriter
	n     *fakeNotifier
	kills *KillStore
	org   *policy.Org
	dir   string
}

func newRig(t *testing.T, v promote.Verdict) *rig {
	t.Helper()
	dir := t.TempDir()
	state, err := OpenStateLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	kills, err := OpenKillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close(); _ = kills.Close() })
	r := &rig{w: &fakeWriter{}, n: &fakeNotifier{}, kills: kills, org: &policy.Org{Experiments: []*policy.Experiment{testExp("exp-a")}}, dir: dir}
	r.c = &Controller{
		Org:     func() (*policy.Org, error) { return r.org, nil },
		Metrics: source(v), Writer: r.w, Kill: kills, Kills: kills, Notifier: r.n, State: state,
		VerdictsPath: filepath.Join(dir, "verdicts.json"),
		Clock:        func() time.Time { return start.Add(48 * time.Hour) },
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return r
}

func (r *rig) killed(t *testing.T) []string {
	t.Helper()
	recs, _, err := r.kills.Killed()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range recs {
		out = append(out, k.Experiment)
	}
	return out
}

func TestTickActsOncePerVerdict(t *testing.T) {
	for _, tc := range []struct {
		verdict    promote.Verdict
		wantStatus string // "" = no PR
		wantKilled bool
	}{
		{promote.Continue, "", false},
		{promote.Rollback, "paused", true},
		{promote.Promote, "concluded", false},
		{promote.Expired, "concluded", false},
	} {
		t.Run(string(tc.verdict), func(t *testing.T) {
			r := newRig(t, tc.verdict)
			for i := 0; i < 3; i++ { // repeated ticks must not duplicate anything
				if err := r.c.Tick(context.Background()); err != nil {
					t.Fatalf("tick %d: %v", i, err)
				}
			}
			wantPRs, wantEvents := 0, 0
			if tc.wantStatus != "" {
				wantPRs, wantEvents = 1, 1
			}
			if len(r.w.calls) != wantPRs || len(r.n.events) != wantEvents {
				t.Fatalf("PRs=%d events=%d, want %d/%d", len(r.w.calls), len(r.n.events), wantPRs, wantEvents)
			}
			if wantPRs == 1 {
				c := r.w.calls[0]
				if c.exp != "exp-a" || c.status != tc.wantStatus || !strings.Contains(c.body, "Guardrail `halo.cost.usd_per_session`") {
					t.Fatalf("PR = %+v", c)
				}
				ev := r.n.events[0]
				if ev.Verdict != tc.verdict || ev.PRURL == "" || ev.Killed != tc.wantKilled {
					t.Fatalf("event = %+v", ev)
				}
			}
			if got := r.killed(t); (len(got) == 1) != tc.wantKilled {
				t.Fatalf("killed = %v, want killed=%v", got, tc.wantKilled)
			}
			// The verdict is persisted in halo-server's format.
			b, err := os.ReadFile(r.c.VerdictsPath)
			if err != nil {
				t.Fatal(err)
			}
			var rows []struct {
				Experiment, Verdict string
				EvaluatedAt         time.Time
			}
			if err := json.Unmarshal(b, &rows); err != nil || len(rows) != 1 || rows[0].Verdict != string(tc.verdict) || rows[0].EvaluatedAt.IsZero() {
				t.Fatalf("verdicts file: %v %s", err, b)
			}
			var m bytes.Buffer
			r.c.WriteMetrics(&m)
			evals := "3"
			if tc.verdict == promote.Rollback {
				evals = "1" // rolled back: never re-evaluated in this run
			}
			for _, want := range []string{"halo_controller_ticks_total 3", "halo_controller_errors_total 0", `halo_controller_verdicts_total{verdict="` + string(tc.verdict) + `"} ` + evals} {
				if !strings.Contains(m.String(), want) {
					t.Fatalf("metrics missing %q:\n%s", want, m.String())
				}
			}
		})
	}
}

func TestRollbackSurvivesRestartAndFailures(t *testing.T) {
	r := newRig(t, promote.Rollback)
	r.w.err = errors.New("gh down")
	err := r.c.Tick(context.Background())
	if err == nil || !strings.Contains(err.Error(), "gh down") {
		t.Fatalf("want PR error, got %v", err)
	}
	// The kill and the notification do not wait for the PR.
	if got := r.killed(t); len(got) != 1 {
		t.Fatalf("not killed: %v", got)
	}
	if len(r.n.events) != 1 || r.n.events[0].PRError == "" || !r.n.events[0].Killed {
		t.Fatalf("events = %+v", r.n.events)
	}

	// Restart: reopen the state log from disk; the PR is retried, nothing else repeats.
	if err := r.c.State.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-append: a torn trailing line must not lose later records.
	f, err := os.OpenFile(filepath.Join(r.dir, "controller-state.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"experiment":"exp-a","verd`)
	_ = f.Close()
	state, err := OpenStateLog(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	r.c.State = state
	r.w.err = nil
	for i := 0; i < 2; i++ {
		if err := r.c.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.w.calls) != 1 || len(r.n.events) != 1 {
		t.Fatalf("after restart: PRs=%d events=%d, want 1/1", len(r.w.calls), len(r.n.events))
	}
	if !strings.Contains(r.w.calls[0].body, "kill switch was tripped") {
		t.Fatalf("PR body: %s", r.w.calls[0].body)
	}

	// An admin unkill sticks: the controller already did its kill for this run.
	if _, err := r.kills.Unkill(context.Background(), "exp-a", "alice", "false alarm"); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.killed(t); len(got) != 0 {
		t.Fatalf("controller re-killed after admin unkill: %v", got)
	}

	// The pause PR merged (not running) -> reset; a later restart acts again.
	r.org.Experiments[0].Status = "paused"
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.org.Experiments[0].Status = "running"
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.w.calls) != 2 || len(r.n.events) != 2 || len(r.killed(t)) != 1 {
		t.Fatalf("after restart of experiment: PRs=%d events=%d killed=%v", len(r.w.calls), len(r.n.events), r.killed(t))
	}
}

// Only gateway-sourced evidence may auto-kill: CLI (client-controlled) or
// unknown-source rollbacks still open the pause PR and notify, but never trip the kill switch.
func TestRollbackOnNonGatewayEvidenceDoesNotKill(t *testing.T) {
	for _, src := range []string{promote.SourceCLI, ""} {
		t.Run("source="+src, func(t *testing.T) {
			r := newRig(t, promote.Rollback)
			r.c.Metrics.(*promote.MemorySource).Source = src
			for i := 0; i < 2; i++ {
				if err := r.c.Tick(context.Background()); err != nil {
					t.Fatalf("tick %d: %v", i, err)
				}
			}
			if got := r.killed(t); len(got) != 0 {
				t.Fatalf("killed %v on %q evidence", got, src)
			}
			if len(r.w.calls) != 1 || r.w.calls[0].status != "paused" || !strings.Contains(r.w.calls[0].body, "only gateway-sourced evidence") {
				t.Fatalf("PR = %+v", r.w.calls)
			}
			if len(r.n.events) != 1 || r.n.events[0].Killed || r.n.events[0].Report.Source != src {
				t.Fatalf("events = %+v", r.n.events)
			}
		})
	}
}

func TestRollbackKillFailureStillNotifies(t *testing.T) {
	r := newRig(t, promote.Rollback)
	r.c.Kill = failKill{}
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("want kill error, got %v", err)
	}
	if len(r.n.events) != 1 || r.n.events[0].Killed || !strings.Contains(r.n.events[0].Text(), "KILL SWITCH FAILED") {
		t.Fatalf("events = %+v", r.n.events)
	}
	if len(r.w.calls) != 1 || !strings.Contains(r.w.calls[0].body, "could NOT be tripped") {
		t.Fatalf("PR = %+v", r.w.calls)
	}
	var m bytes.Buffer
	r.c.WriteMetrics(&m)
	if !strings.Contains(m.String(), "halo_controller_errors_total 1") {
		t.Fatalf("metrics:\n%s", m.String())
	}
}

func TestPromoteNotifyWaitsForPR(t *testing.T) {
	r := newRig(t, promote.Promote)
	r.w.err = errors.New("gh down")
	if err := r.c.Tick(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if len(r.n.events) != 0 {
		t.Fatalf("notified before the PR existed: %+v", r.n.events)
	}
	r.w.err = nil
	r.n.err = errors.New("slack down")
	if err := r.c.Tick(context.Background()); err == nil {
		t.Fatal("want notify error")
	}
	r.n.err = nil
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.w.calls) != 1 || len(r.n.events) != 1 {
		t.Fatalf("PRs=%d events=%d, want 1/1", len(r.w.calls), len(r.n.events))
	}
}

func TestTickErrors(t *testing.T) {
	r := newRig(t, promote.Continue)
	r.c.Org = func() (*policy.Org, error) { return nil, errors.New("bad yaml") }
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "bad yaml") {
		t.Fatalf("got %v", err)
	}
	// One bad experiment doesn't stop the others.
	bad := testExp("bad")
	bad.Variants = bad.Variants[:1]
	r.org.Experiments = []*policy.Experiment{bad, testExp("good")}
	r.c.Org = func() (*policy.Org, error) { return r.org, nil }
	r.c.Metrics = source(promote.Rollback)
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("got %v", err)
	}
	if got := r.killed(t); len(got) != 1 || got[0] != "good" {
		t.Fatalf("killed = %v", got)
	}
	// Cancelled context: the tick stops.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.c.Tick(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	r := newRig(t, promote.Continue)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.c.Run(ctx, time.Hour); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit")
	}
	if r.c.ticks.Load() == 0 {
		t.Fatal("Run never ticked")
	}
}

func TestRollbackKillNotEnforced(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(r *rig)
		killed  int
		want    string // in the PR body
		outcome KillOutcome
		text    string // in the notification
	}{
		{"no kill switch", func(r *rig) { r.c.Kill = nil }, 0, "kill switch not configured — rollback requires merging the pause PR", KillNotConfigured, "Kill switch not configured"},
		{"kill recorded, not served", func(r *rig) {
			r.c.KillCaveat = "recorded in x/killswitch.jsonl; gateways enforce only if halo-server serves this data dir with a kill key"
		}, 1, "gateways enforce only if", KillRecorded, "Kill recorded only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, promote.Rollback)
			tc.setup(r)
			for i := 0; i < 2; i++ {
				if err := r.c.Tick(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if got := r.killed(t); len(got) != tc.killed {
				t.Fatalf("killed = %v", got)
			}
			if len(r.w.calls) != 1 || !strings.Contains(r.w.calls[0].body, tc.want) || !strings.Contains(r.w.calls[0].body, "merge urgently") ||
				strings.Contains(r.w.calls[0].body, "already route everyone") {
				t.Fatalf("PR = %+v", r.w.calls)
			}
			if len(r.n.events) != 1 || r.n.events[0].Killed || r.n.events[0].KillOutcome != tc.outcome || !strings.Contains(r.n.events[0].Text(), tc.text) {
				t.Fatalf("events = %+v", r.n.events)
			}
		})
	}
}

// After a rollback the controller stops evaluating: evidence flipping to
// promote must not conclude the killed experiment.
func TestNoEvaluationAfterRollback(t *testing.T) {
	r := newRig(t, promote.Rollback)
	r.w.err = errors.New("gh down")
	if err := r.c.Tick(context.Background()); err == nil {
		t.Fatal("want PR error")
	}
	r.w.err = nil
	r.c.Metrics = source(promote.Promote)
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The pending pause PR was retried from the recorded evidence; no conclude PR.
	if len(r.w.calls) != 1 || r.w.calls[0].status != "paused" || !strings.Contains(r.w.calls[0].body, "Guardrail `halo.cost.usd_per_session`") {
		t.Fatalf("PRs = %+v", r.w.calls)
	}
	var m bytes.Buffer
	r.c.WriteMetrics(&m)
	if !strings.Contains(m.String(), `halo_controller_verdicts_total{verdict="promote"} 0`) {
		t.Fatalf("re-evaluated after rollback:\n%s", m.String())
	}
}

// A kill left in force (admin kill, or from an earlier run) holds evaluation
// and is announced once per run.
func TestKilledExperimentIsHeld(t *testing.T) {
	r := newRig(t, promote.Promote)
	if _, err := r.kills.Kill(context.Background(), "exp-a", "alice", "incident"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := r.c.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.w.calls) != 0 || len(r.n.events) != 1 || r.n.events[0].Verdict != VerdictKilled ||
		!strings.Contains(r.n.events[0].Reason, "exp-a is killed; unkill before resuming") {
		t.Fatalf("PRs=%+v events=%+v", r.w.calls, r.n.events)
	}
	if _, err := r.kills.Unkill(context.Background(), "exp-a", "alice", "fixed"); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.w.calls) != 1 || r.w.calls[0].status != "concluded" {
		t.Fatalf("not resumed after unkill: %+v", r.w.calls)
	}
	// Unreadable kill state is an error, not a silent evaluation.
	if err := os.Remove(filepath.Join(r.dir, "killswitch.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "read kill switch") {
		t.Fatalf("got %v", err)
	}
}

type namedNotifier struct {
	fakeNotifier
	name string
}

func (n *namedNotifier) Name() string { return n.name }

// A failing channel is retried alone; the others are not re-posted.
func TestNotifyPerChannel(t *testing.T) {
	r := newRig(t, promote.Promote)
	slack, hook := &namedNotifier{name: "slack"}, &namedNotifier{name: "webhook"}
	hook.err = errors.New("webhook down")
	r.c.Notifier = Notifiers{slack, hook}
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "via webhook") {
		t.Fatalf("got %v", err)
	}
	hook.err = nil
	for i := 0; i < 2; i++ {
		if err := r.c.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(slack.events) != 1 || len(hook.events) != 1 {
		t.Fatalf("slack=%d webhook=%d, want 1/1", len(slack.events), len(hook.events))
	}
	if _, done := r.c.State.Done("exp-a", "promote", ActionNotify+":slack"); !done {
		t.Fatal("per-channel action not recorded")
	}
}

func TestChannelNames(t *testing.T) {
	for _, tc := range []struct {
		n    Notifier
		want string
	}{
		{nil, ""},
		{&fakeNotifier{}, "0"},
		{Notifiers{Slack{}, Webhook{}, Webhook{}, &fakeNotifier{}}, "slack|webhook|webhook#2|3"},
	} {
		names, ns := channels(tc.n)
		if strings.Join(names, "|") != tc.want || len(ns) != len(names) {
			t.Errorf("channels(%T) = %v", tc.n, names)
		}
	}
}

func TestReportRoundTrip(t *testing.T) {
	rep := promote.Report{Verdict: promote.Rollback, Reason: "guardrail", Control: "c", NControl: 3, Effect: 0.5}
	if got := decodeReport(encodeReport(rep)); got.Reason != "guardrail" || got.Effect != 0.5 || got.NControl != 3 {
		t.Fatalf("%+v", got)
	}
	nan := rep
	nan.PValue = math.NaN()
	if got := decodeReport(encodeReport(nan)); got.Reason != "guardrail" || got.Control != "c" {
		t.Fatalf("NaN: %+v", got)
	}
	if got := decodeReport("garbage"); got.Verdict != promote.Rollback || got.Reason == "" {
		t.Fatalf("garbage: %+v", got)
	}
}
