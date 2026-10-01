package rollout

import (
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/stats"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

var errRate = policy.MetricGoal{Metric: "halo.api.error_rate", Direction: "decrease", MaxRegression: 0.05}

// testRollout has one step per strategy, in a plausible order.
func testRollout() *policy.Rollout {
	return &policy.Rollout{
		Meta: policy.Meta{Name: "r"}, Axis: policy.AxisClient, Status: policy.RolloutActive, Experiment: "e",
		Change: policy.RolloutChange{Release: "sha256:new"}, Baseline: policy.RolloutBaseline{Release: "sha256:old"},
		Steps: []policy.RolloutStep{
			{Name: "shadow", Strategy: policy.StrategyDarkLaunch, Percent: 10, Bake: "1h", MinSamples: 10, Gates: policy.RolloutGates{Guardrails: []policy.MetricGoal{errRate}}, OnFailure: "pause"},
			{Name: "canary-5", Strategy: policy.StrategyCanary, Percent: 5, Bake: "2h", MinSamples: 100, Gates: policy.RolloutGates{Guardrails: []policy.MetricGoal{errRate},
				Scorecard: &policy.ScorecardGate{File: "sc.json", Variant: "new", MinPass1: 0.7, MaxRegression: 0.02}}},
			{Name: "ring1", Strategy: policy.StrategyProgressive, Ring: "ring1", Bake: "1d", Gates: policy.RolloutGates{Approval: true}},
			{Name: "ga", Strategy: policy.StrategyBlueGreen, Ring: "ga", Bake: "30m"},
			{Name: "holdout", Strategy: policy.StrategyHoldout, Percent: 5, Bake: "14d", MinSamples: 1000, Gates: policy.RolloutGates{Guardrails: []policy.MetricGoal{errRate}}},
		},
	}
}

func at(step int, entered time.Time) State {
	st := NewState("r")
	st.Record(EventEnter, step, testRollout().Steps[step].Name, "", entered)
	return st
}

func rep(n int, status stats.GuardrailStatus, source string) *promote.Report {
	return &promote.Report{NControl: n, NTreatment: n, Guardrails: []promote.GuardrailReport{
		{Metric: errRate.Metric, Source: source, Result: stats.GuardrailResult{Status: status, Regression: 0.01, Upper: 0.03}}}}
}

func card(pass1, delta float64, verdict string) *eval.Scorecard {
	return &eval.Scorecard{Variants: []eval.VariantScore{{Name: "new", Pass1: pass1}},
		Comparisons: []eval.Comparison{{Variant: "new", Control: "ctl", Delta: delta, Verdict: verdict}}}
}

func gated(verdict string) *eval.Scorecard {
	c := card(0.8, 0.01, eval.VerdictNoDiff)
	c.Comparisons[0].Gate = &eval.Gate{Verdict: verdict, Reasons: []string{"rerun with more trials"}}
	return c
}

func TestEvaluate(t *testing.T) {
	good := card(0.8, 0.01, eval.VerdictNoDiff)
	tests := []struct {
		name     string
		mut      func(*policy.Rollout)
		st       State
		ev       Evidence
		now      time.Time
		want     Action
		next     int
		reason   string // substring of the joined reasons
		approval bool
		source   string
	}{
		{name: "draft holds", mut: func(r *policy.Rollout) { r.Status = "" }, st: NewState("r"), now: t0, want: Hold, next: -1, reason: "rollout is draft"},
		{name: "paused in policy holds", mut: func(r *policy.Rollout) { r.Status = policy.RolloutPaused }, st: at(1, t0), now: t0, want: Hold, next: -1, reason: "paused"},
		{name: "halted holds", st: func() State { s := at(1, t0); s.Record(EventHalt, 1, "canary-5", "rollback", t0); return s }(), now: t0.Add(time.Hour), want: Hold, next: -1, reason: "halted by rollback"},
		{name: "not started advances to step 0", st: NewState("r"), now: t0, want: Advance, next: 0},

		// dark-launch
		{name: "dark-launch baking", st: at(0, t0), ev: Evidence{Report: rep(50, stats.Pass, "gateway")}, now: t0.Add(30 * time.Minute), want: Hold, next: -1, reason: "baking, 30m left"},
		{name: "dark-launch passes", st: at(0, t0), ev: Evidence{Report: rep(50, stats.Pass, "gateway")}, now: t0.Add(time.Hour), want: Advance, next: 1},
		{name: "dark-launch breach pauses (onFailure pause)", st: at(0, t0), ev: Evidence{Report: rep(50, stats.Fail, "gateway")}, now: t0.Add(time.Minute), want: Pause, next: -1, reason: "guardrail:halo.api.error_rate failed", source: "gateway"},

		// canary
		{name: "canary bake unknown without state", st: func() State { s := at(1, t0); s.EnteredAt = time.Time{}; return s }(), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: good}, now: t0, want: Hold, next: -1, reason: "entry time unknown"},
		{name: "canary insufficient samples", st: at(1, t0), ev: Evidence{Report: rep(99, stats.Pass, "gateway"), Scorecard: good}, now: t0.Add(3 * time.Hour), want: Hold, next: -1, reason: "99/99 of 100 per arm"},
		{name: "canary no metric evidence", st: at(1, t0), ev: Evidence{Scorecard: good}, now: t0.Add(3 * time.Hour), want: Hold, next: -1, reason: "no metric evidence"},
		{name: "canary guardrail inconclusive", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Inconclusive, "gateway"), Scorecard: good}, now: t0.Add(3 * time.Hour), want: Hold, next: -1, reason: "inconclusive"},
		{name: "canary breach during bake rolls back", st: at(1, t0), ev: Evidence{Report: rep(20, stats.Fail, "cli"), Scorecard: good}, now: t0.Add(time.Minute), want: Rollback, next: -1, source: "cli"},
		{name: "canary scorecard missing holds", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), ScorecardErr: "scorecard: no such file"}, now: t0.Add(3 * time.Hour), want: Hold, next: -1, reason: "no such file"},
		{name: "canary scorecard below floor rolls back", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: card(0.6, 0, eval.VerdictNoDiff)}, now: t0.Add(3 * time.Hour), want: Rollback, next: -1, reason: "scorecard failed", source: "scorecard"},
		{name: "canary scorecard regression rolls back", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: card(0.8, -0.03, eval.VerdictNoDiff)}, now: t0.Add(3 * time.Hour), want: Rollback, next: -1, source: "scorecard"},
		{name: "canary scorecard significantly worse rolls back", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: card(0.8, -0.01, eval.VerdictWorse)}, now: t0.Add(3 * time.Hour), want: Rollback, next: -1},
		{name: "canary eval gate block rolls back", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: gated(eval.GateBlock)}, now: t0.Add(3 * time.Hour), want: Rollback, next: -1, reason: "eval gate block", source: "scorecard"},
		{name: "canary eval gate hold holds", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: gated(eval.GateHold)}, now: t0.Add(3 * time.Hour), want: Hold, next: -1, reason: "eval gate hold: rerun"},
		{name: "canary eval gate ship passes", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: gated(eval.GateShip)}, now: t0.Add(3 * time.Hour), want: Advance, next: 2},
		{name: "canary all gates pass", st: at(1, t0), ev: Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: good}, now: t0.Add(3 * time.Hour), want: Advance, next: 2},

		// progressive with approval
		{name: "progressive awaits approval", st: at(2, t0), now: t0.Add(25 * time.Hour), want: Hold, next: -1, approval: true, reason: "awaiting a human"},
		{name: "progressive baking is not only approval", st: at(2, t0), now: t0.Add(time.Hour), want: Hold, next: -1, reason: "baking"},
		{name: "progressive approved advances", st: at(2, t0), ev: Evidence{Approved: true}, now: t0.Add(25 * time.Hour), want: Advance, next: 3},

		// blue-green: bake only
		{name: "blue-green baking", st: at(3, t0), now: t0.Add(10 * time.Minute), want: Hold, next: -1},
		{name: "blue-green switches on", st: at(3, t0), now: t0.Add(31 * time.Minute), want: Advance, next: 4},

		// holdout: last step
		{name: "holdout holds for its 14 days", st: at(4, t0), ev: Evidence{Report: rep(5000, stats.Pass, "gateway")}, now: t0.Add(13 * 24 * time.Hour), want: Hold, next: -1, reason: "baking, 1d left"},
		{name: "holdout long-term regression rolls back", st: at(4, t0), ev: Evidence{Report: rep(5000, stats.Fail, "gateway")}, now: t0.Add(10 * 24 * time.Hour), want: Rollback, next: -1, source: "gateway"},
		{name: "holdout done completes", st: at(4, t0), ev: Evidence{Report: rep(5000, stats.Pass, "gateway")}, now: t0.Add(14 * 24 * time.Hour), want: Complete, next: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := testRollout()
			if tc.mut != nil {
				tc.mut(r)
			}
			d := Evaluate(r, tc.st, tc.ev, tc.now)
			if d.Action != tc.want || d.Next != tc.next {
				t.Fatalf("got %s next=%d (%v), want %s next=%d", d.Action, d.Next, d.Reasons, tc.want, tc.next)
			}
			if got := strings.Join(d.Reasons, "; "); !strings.Contains(got, tc.reason) {
				t.Fatalf("reasons %q lack %q", got, tc.reason)
			}
			if d.AwaitingApproval != tc.approval {
				t.Fatalf("AwaitingApproval = %v", d.AwaitingApproval)
			}
			if tc.source != "" && d.Source != tc.source {
				t.Fatalf("source = %q, want %q", d.Source, tc.source)
			}
			if d2 := Evaluate(r, tc.st, tc.ev, tc.now); strings.Join(d2.Reasons, "|") != strings.Join(d.Reasons, "|") {
				t.Fatal("Evaluate is not deterministic")
			}
		})
	}
}

func TestStateChain(t *testing.T) {
	dir := t.TempDir()
	r := testRollout()
	st, err := LoadState(dir, "r")
	if err != nil || st.Step != -1 {
		t.Fatalf("new state: %+v %v", st, err)
	}
	r.Step = "canary-5"
	if !st.Sync(r, t0) || st.Step != 1 || !st.EnteredAt.Equal(t0) {
		t.Fatalf("sync did not enter: %+v", st)
	}
	if st.Sync(r, t0.Add(time.Hour)) {
		t.Fatal("second sync changed state")
	}
	reset := *r
	reset.Step = ""
	if c := st; !c.Sync(&reset, t0) || c.Step != -1 {
		t.Fatalf("reset not followed: %+v", c)
	}
	st.Mark("pr:advance", "https://pr/1", t0)
	st.Record(EventHalt, st.Step, st.StepName, "rollback", t0)
	if err := st.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir, "r")
	if err != nil {
		t.Fatal(err)
	}
	if got.Step != 1 || got.Halted != "rollback" || len(got.History) != 3 {
		t.Fatalf("reloaded: %+v", got)
	}
	if u, ok := got.Did("pr:advance"); !ok || u != "https://pr/1" {
		t.Fatalf("Did = %q %v", u, ok)
	}
	// The halt is acknowledged once the policy leaves active.
	r.Status = policy.RolloutAborted
	if !got.Sync(r, t0) || got.Halted != "" {
		t.Fatalf("halt not acknowledged: %+v", got)
	}

	for name, tamper := range map[string]func(string) string{
		"edited entry":   func(s string) string { return strings.Replace(s, `"step": "canary-5"`, `"step": "ring1"`, 1) },
		"dropped halt":   func(s string) string { return strings.Replace(s, `"halted": "rollback",`, ``, 1) },
		"moved pointer":  func(s string) string { return strings.Replace(s, `"step": 1,`, `"step": 3,`, 1) },
		"rewritten seq":  func(s string) string { return strings.Replace(s, `"seq": 2,`, `"seq": 7,`, 1) },
		"other rollout":  func(s string) string { return strings.Replace(s, `"rollout": "r"`, `"rollout": "x"`, 1) },
		"not json":       func(string) string { return "{" },
		"cleared hashes": func(s string) string { return strings.ReplaceAll(s, `"prev": "`, `"prev": "0`) },
	} {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			if err := st.Save(d); err != nil {
				t.Fatal(err)
			}
			b := mustRead(t, StatePath(d, "r"))
			out := tamper(b)
			if out == b {
				t.Fatal("tamper did not change the file")
			}
			mustWrite(t, StatePath(d, "r"), out)
			if _, err := LoadState(d, "r"); err == nil {
				t.Fatal("tampered state loaded")
			}
		})
	}
	if _, err := LoadState(dir, "../x"); err == nil {
		t.Fatal("path-like rollout name accepted")
	}
}
