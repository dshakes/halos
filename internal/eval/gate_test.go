package eval

import (
	"math"
	"strings"
	"testing"
)

// arm appends one trial per outcome for variant/task.
func arm(variant, task string, cost float64, wallMs int64, outcomes ...bool) []Trial {
	var out []Trial
	for i, p := range outcomes {
		out = append(out, Trial{Task: task, Variant: variant, Repeat: i, Pass: p, CostUSD: cost, WallMs: wallMs, Tokens: 1000, ToolCalls: 10})
	}
	return out
}

func gateSuite(t *testing.T, th Thresholds) *Suite {
	t.Helper()
	s := &Suite{Name: "g", Tasks: []string{"t"}, Repeats: 3, Gate: th,
		Variants: []Variant{{Name: "base", Harness: "claude"}, {Name: "cand", Harness: "claude"}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func f(v float64) *float64 { return &v }

func TestGateVerdicts(t *testing.T) {
	yes, no := true, false
	allPass := func(v, task string, cost float64) []Trial { return arm(v, task, cost, 1000, yes, yes, yes) }
	allFail := func(v, task string, cost float64) []Trial { return arm(v, task, cost, 1000, no, no, no) }
	tasks := []string{"a", "b", "c", "d"}
	build := func(cand func(task string) []Trial, base func(task string) []Trial) []Trial {
		var out []Trial
		for _, task := range tasks {
			out = append(out, base(task)...)
			out = append(out, cand(task)...)
		}
		return out
	}
	basePass := func(task string) []Trial { return allPass("base", task, 0.10) }
	tests := []struct {
		name      string
		th        Thresholds
		trials    []Trial
		verdict   string
		reason    string
		regressed int
		flaky     int
	}{
		{"identical arms ship", Thresholds{}, build(func(task string) []Trial { return allPass("cand", task, 0.10) }, basePass), GateShip, "non-inferior on 4 tasks", 0, 0},
		{"total collapse blocks", Thresholds{}, build(func(task string) []Trial { return allFail("cand", task, 0.10) }, basePass), GateBlock, "significantly worse", 4, 0},
		{"one regressed task blocks at max 0", Thresholds{}, build(func(task string) []Trial {
			if task == "d" {
				return allFail("cand", task, 0.10)
			}
			return allPass("cand", task, 0.10)
		}, basePass), GateBlock, "1 tasks regressed (max 0)", 1, 0},
		{"one regressed task holds at max 1", Thresholds{MaxRegressedTasks: 1}, build(func(task string) []Trial {
			if task == "d" {
				return allFail("cand", task, 0.10)
			}
			return allPass("cand", task, 0.10)
		}, basePass), GateHold, "inconclusive", 1, 0},
		{"wide margin ships the same data", Thresholds{MaxRegressedTasks: 1, MaxPassDrop: f(0.8)}, build(func(task string) []Trial {
			if task == "d" {
				return allFail("cand", task, 0.10)
			}
			return allPass("cand", task, 0.10)
		}, basePass), GateShip, "non-inferior", 1, 0},
		{"cost doubling blocks when gated", Thresholds{MaxCostIncrease: f(0.2)}, build(func(task string) []Trial { return allPass("cand", task, 0.20) }, basePass), GateBlock, "cost_usd up +100%", 0, 0},
		{"cost doubling ignored when ungated", Thresholds{}, build(func(task string) []Trial { return allPass("cand", task, 0.20) }, basePass), GateShip, "", 0, 0},
		{"zero baseline cost is reported, not gated", Thresholds{MaxCostIncrease: f(0.2)}, build(func(task string) []Trial { return allPass("cand", task, 0.20) }, func(task string) []Trial { return allPass("base", task, 0) }), GateShip, "cost_usd not gated", 0, 0},
		{"flaky baseline task is excluded", Thresholds{}, build(func(task string) []Trial { return allFail("cand", task, 0.10)[:3] }, func(task string) []Trial {
			if task == "a" {
				return arm("base", task, 0.10, 1000, yes, no, yes)
			}
			return allFail("base", task, 0.10)
		}), GateShip, "non-inferior on 3 tasks", 0, 1},
		{"all flaky holds", Thresholds{}, build(func(task string) []Trial { return allPass("cand", task, 0.10) }, func(task string) []Trial {
			return arm("base", task, 0.10, 1000, yes, no, yes)
		}), GateHold, "only 0 non-flaky tasks (4 flaky)", 0, 4},
		{"min tasks holds", Thresholds{MinTasks: 5}, build(func(task string) []Trial { return allPass("cand", task, 0.10) }, basePass), GateHold, "need 5", 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := gateSuite(t, tc.th)
			sc, err := BuildScorecard(s, tc.trials, 1)
			if err != nil {
				t.Fatal(err)
			}
			g := sc.Comparisons[0].Gate
			if g.Verdict != tc.verdict || sc.Gate.Verdict != tc.verdict {
				t.Fatalf("verdict %s (scorecard %s), want %s; reasons %v", g.Verdict, sc.Gate.Verdict, tc.verdict, g.Reasons)
			}
			if !strings.Contains(strings.Join(g.Reasons, "|"), tc.reason) {
				t.Errorf("reasons %v missing %q", g.Reasons, tc.reason)
			}
			if len(g.Regressed) != tc.regressed || len(g.Flaky) != tc.flaky {
				t.Errorf("regressed %d flaky %d, want %d %d", len(g.Regressed), len(g.Flaky), tc.regressed, tc.flaky)
			}
			for _, fl := range g.Flaky {
				if fl.Reason == "" || fl.Status != "flaky" {
					t.Errorf("flaky task without reason: %+v", fl)
				}
			}
		})
	}
}

func TestGraderErrorsHold(t *testing.T) {
	s := gateSuite(t, Thresholds{})
	var trials []Trial
	for _, task := range []string{"a", "b"} {
		trials = append(trials, arm("base", task, 0.1, 100, true, true, true)...)
		c := arm("cand", task, 0.1, 100, true, true, true)
		c[0].Pass, c[0].GraderError = false, "judge: judge reply failed schema validation"
		trials = append(trials, c...)
	}
	sc, err := BuildScorecard(s, trials, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Gate.Verdict != GateHold || !strings.Contains(strings.Join(sc.Gate.Reasons, "|"), "grader errors") {
		t.Fatalf("gate %+v", sc.Gate)
	}
	if sc.Variants[1].GradeErrors != 2 {
		t.Fatalf("grade errors %d", sc.Variants[1].GradeErrors)
	}
}

func TestScorecardPassK(t *testing.T) {
	s := &Suite{Name: "k", Tasks: []string{"t"}, Repeats: 5, K: 2, Variants: []Variant{{Name: "v", Harness: "codex"}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	// task a: 2/5 passes -> pass@2 0.7, pass^2 0.1; task b: 5/5 -> 1, 1.
	trials := append(arm("v", "a", 0, 0, true, true, false, false, false), arm("v", "b", 0, 0, true, true, true, true, true)...)
	sc, err := BuildScorecard(s, trials, 1)
	if err != nil {
		t.Fatal(err)
	}
	v := sc.Variants[0]
	if math.Abs(v.PassAtK-0.85) > 1e-9 || math.Abs(v.PassHatK-0.55) > 1e-9 || v.K != 2 {
		t.Fatalf("pass@2 %v pass^2 %v k %d", v.PassAtK, v.PassHatK, v.K)
	}
	if sc.Gate != nil || v.ToolCalls != 100 {
		t.Fatalf("single variant: gate %+v toolCalls %d", sc.Gate, v.ToolCalls)
	}
}

func TestThresholdValidation(t *testing.T) {
	for i, th := range []Thresholds{{MaxPassDrop: f(-1)}, {MaxCostIncrease: f(-0.1)}, {TaskRegression: 2}, {MaxRegressedTasks: -1}} {
		s := &Suite{Name: "x", Tasks: []string{"t"}, Gate: th, Variants: []Variant{{Name: "v", Harness: "claude"}}}
		if err := s.Validate(); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
	s := &Suite{Name: "x", Tasks: []string{"t"}, Repeats: 2, K: 3, Variants: []Variant{{Name: "v", Harness: "claude"}}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "k must be") {
		t.Errorf("k > repeats: %v", err)
	}
}

// TestEfficiencyGates covers turns, cost per turn and cost-of-pass.
func TestEfficiencyGates(t *testing.T) {
	tasks := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	// run: cost and turns per trial, and how many of 3 trials pass (0 or 3, so no task is flaky).
	run := func(v string, cost float64, turns int, pass bool) []Trial {
		var out []Trial
		for _, task := range tasks {
			for i, tr := range arm(v, task, cost, 1000, pass, pass, pass) {
				tr.Turns, tr.Repeat = turns, i
				out = append(out, tr)
			}
		}
		return out
	}
	tests := []struct {
		name    string
		th      Thresholds
		base    []Trial
		cand    []Trial
		verdict string
		reason  string
	}{
		{"twice the turns blocks", Thresholds{MaxTurnsIncrease: f(0.25)}, run("base", 0.1, 10, true), run("cand", 0.1, 20, true), GateBlock, "turns up +100%"},
		{"same cost in half the turns doubles cost per turn", Thresholds{MaxCostPerTurnIncrease: f(0.5)}, run("base", 0.1, 10, true), run("cand", 0.1, 5, true), GateBlock, "cost_per_turn up +100%"},
		{"unchanged turns and cost ship", Thresholds{MaxTurnsIncrease: f(0.1), MaxCostPerTurnIncrease: f(0.1)}, run("base", 0.1, 10, true), run("cand", 0.1, 10, true), GateShip, "non-inferior"},
		{"unreported turns are not gated", Thresholds{MaxTurnsIncrease: f(0.1), MaxCostPerTurnIncrease: f(0.1)}, run("base", 0.1, 0, true), run("cand", 0.1, 0, true), GateShip, "cost_per_turn not gated: turns are 0"},
		{"nothing solved: cost-of-pass holds", Thresholds{MaxCostOfPassIncrease: f(0.2), MaxPassDrop: f(1)}, run("base", 0.1, 10, false), run("cand", 0.1, 10, false), GateHold, "cost_of_pass not measurable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc, err := BuildScorecard(gateSuite(t, tc.th), append(tc.base, tc.cand...), 1)
			if err != nil {
				t.Fatal(err)
			}
			g := sc.Comparisons[0].Gate
			if g.Verdict != tc.verdict || !strings.Contains(strings.Join(g.Reasons, "|"), tc.reason) {
				t.Fatalf("verdict %s, want %s with %q; reasons %v", g.Verdict, tc.verdict, tc.reason, g.Reasons)
			}
		})
	}

	// Cost-of-pass catches a cheaper candidate that solves less: $0.10 for 8/8
	// vs $0.08 for 4/8 is $0.10 vs $0.16 per solve.
	base := run("base", 0.10, 10, true)
	var cand []Trial
	for _, tr := range run("cand", 0.08, 10, true) {
		tr.Pass = tr.Task <= "d"
		cand = append(cand, tr)
	}
	sc, err := BuildScorecard(gateSuite(t, Thresholds{MaxPassDrop: f(1), MaxRegressedTasks: 8, MaxCostIncrease: f(0.1), MaxCostOfPassIncrease: f(0.2)}), append(base, cand...), 1)
	if err != nil {
		t.Fatal(err)
	}
	c := sc.Comparisons[0]
	if d := c.Deltas[MetricCostOfPass]; math.Abs(d.Baseline-0.10) > 1e-9 || math.Abs(d.Mean-0.06) > 1e-9 {
		t.Fatalf("cost_of_pass delta %+v, want baseline 0.10 and +0.06", d)
	}
	if !strings.Contains(strings.Join(c.Gate.Reasons, "|"), "cost_of_pass") || strings.Contains(strings.Join(c.Gate.Reasons, "|"), "cost_usd up") {
		t.Fatalf("want a cost_of_pass reason and no cost_usd one: %v", c.Gate.Reasons)
	}
	v := sc.Variants[1]
	if v.CostOfPass == nil || math.Abs(*v.CostOfPass-0.16) > 1e-9 || v.TurnsPerTask != 10 || math.Abs(v.CostPerTurn-0.008) > 1e-12 {
		t.Fatalf("candidate efficiency %+v", v)
	}
}

func TestPricingEstimate(t *testing.T) {
	s := &Suite{Name: "p", Tasks: []string{"t"}, Repeats: 1, Variants: []Variant{{Name: "codex", Harness: "codex", Model: "gpt-x"}, {Name: "claude", Harness: "claude", Model: "sonnet"}},
		Pricing: map[string]Price{"gpt-x": {Input: 2, Output: 8, CachedInput: f(0.5)}, "sonnet": {Input: 100, Output: 100}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	trials := []Trial{
		{Task: "t", Variant: "codex", Pass: true, InputTokens: 1_000_000, CachedTokens: 600_000, OutputTokens: 100_000, Turns: 0},
		{Task: "t", Variant: "claude", Pass: true, CostUSD: 0.5, InputTokens: 1_000_000, OutputTokens: 1},
		{Task: "t", Variant: "claude", Repeat: 1, Pass: false, CostUSD: 0, InputTokens: 1_000, OutputTokens: 1},
	}
	sc, err := BuildScorecard(s, trials, 1)
	if err != nil {
		t.Fatal(err)
	}
	// 400k*2 + 600k*0.5 + 100k*8 per million = 0.8 + 0.3 + 0.8.
	if got := sc.Variants[0]; !got.CostEstimated || math.Abs(got.CostPerTask-1.9) > 1e-9 || math.Abs(got.CacheHitRate-0.6) > 1e-9 {
		t.Fatalf("codex %+v", got)
	}
	if got := sc.Variants[1]; got.CostEstimated || got.CostPerTask != 0.25 { // the $0 Claude trial stays $0
		t.Fatalf("harness-reported cost was overridden: %+v", got)
	}
	if trials[0].CostUSD != 0 {
		t.Fatal("caller's trials were mutated")
	}
	if !strings.Contains(sc.Markdown(), "~$1.9000") {
		t.Fatalf("estimated cost not marked:\n%s", sc.Markdown())
	}
	s.Pricing = map[string]Price{"m": {Input: -1}}
	if err := s.Validate(); err == nil {
		t.Fatal("want error on negative price")
	}
}
