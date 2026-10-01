package policy

import (
	"strings"
	"testing"
)

// halo.eval.judge.score: registered, higher is better, usable where halo-shadow
// pairs exist (shadow experiments, rollout dark-launch steps), rejected elsewhere.
func TestJudgeScoreMetric(t *testing.T) {
	m, ok := LookupMetric("halo.eval.judge.score")
	if !ok || m.Better != "increase" || !m.ShadowOnly() {
		t.Fatalf("registry entry: %+v", m)
	}
	judge := func(dir string) MetricGoal {
		return MetricGoal{Metric: "halo.eval.judge.score", Direction: dir, MaxRegression: 0.05}
	}
	for _, tc := range []struct {
		name string
		mod  func(*Org)
		want string // "" = valid
	}{
		{"shadow primary + guardrail", func(o *Org) {
			e := o.Experiments[0]
			e.Type, e.SampleRate = ExperimentShadow, 0.1
			e.Metrics.Primary = judge("increase")
			e.Metrics.Guardrails = []MetricGoal{judge("increase")}
		}, ""},
		{"wrong direction", func(o *Org) {
			e := o.Experiments[0]
			e.Type, e.SampleRate = ExperimentShadow, 0.1
			e.Metrics.Guardrails = []MetricGoal{judge("decrease")}
		}, `improves in direction "increase"`},
		{"canary experiment never gets pairs", func(o *Org) {
			o.Experiments[0].Metrics.Guardrails = []MetricGoal{judge("increase")}
		}, "graded on halo-shadow pairs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := validOrg()
			tc.mod(o)
			issues := o.Validate()
			if tc.want == "" {
				if len(issues) != 0 {
					t.Fatalf("unexpected issues: %v", issues)
				}
				return
			}
			if !HasErrors(issues) || !strings.Contains(issues[0].String(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, issues)
			}
		})
	}
}

func TestJudgeScoreRolloutSteps(t *testing.T) {
	for _, tc := range []struct {
		step int // opus-5-5-upgrade: 0 = dark-launch, 1 = canary-1
		ok   bool
	}{{0, true}, {1, false}} {
		o, err := Load(exampleDir)
		if err != nil {
			t.Fatal(err)
		}
		var r *Rollout
		for _, x := range o.Rollouts {
			if x.Name == "opus-5-5-upgrade" {
				r = x
			}
		}
		s := &r.Steps[tc.step]
		s.Gates.Guardrails = append(append([]MetricGoal(nil), s.Gates.Guardrails...), MetricGoal{Metric: "halo.eval.judge.score", Direction: "increase", MaxRegression: 0.05})
		var bad []Issue
		for _, i := range o.Validate() {
			if i.Severity == SeverityError {
				bad = append(bad, i)
			}
		}
		if tc.ok != (len(bad) == 0) || (!tc.ok && !strings.Contains(bad[0].Message, "only a dark-launch step")) {
			t.Fatalf("step %s: errors %v, want ok=%v", s.Name, bad, tc.ok)
		}
	}
}
