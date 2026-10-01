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
