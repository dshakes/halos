package policy

import (
	"strings"
	"testing"
)

func TestGuardTrafficOverlap(t *testing.T) {
	exp := func(name string, typ ExperimentType, status string, rings []string, aliases ...string) *Experiment {
		routes := map[string]ModelRoute{}
		for _, a := range aliases {
			routes[a] = ModelRoute{Upstream: "u", Model: "m"}
		}
		return &Experiment{Meta: Meta{Name: name}, Type: typ, Axis: AxisTraffic, Status: status, Rings: rings,
			Variants: []Variant{{Name: "control", Control: true}, {Name: "next", Routes: routes}}}
	}
	for _, tc := range []struct {
		name string
		exps []*Experiment
		want string // "" = no issue
	}{
		{"same alias, shared ring", []*Experiment{exp("zeta", ExperimentCanary, "running", []string{"r1", "r2"}, "opus"), exp("alpha", ExperimentAB, "running", []string{"r2"}, "opus")},
			`running traffic experiments "alpha" and "zeta" both route alias "opus" on ring "r2"`},
		{"same alias, disjoint rings", []*Experiment{exp("a", ExperimentCanary, "running", []string{"r1"}, "opus"), exp("b", ExperimentCanary, "running", []string{"r2"}, "opus")}, ""},
		{"different aliases, shared ring", []*Experiment{exp("a", ExperimentCanary, "running", []string{"r1"}, "opus"), exp("b", ExperimentCanary, "running", []string{"r1"}, "sonnet")}, ""},
		{"one paused", []*Experiment{exp("a", ExperimentCanary, "running", []string{"r1"}, "opus"), exp("b", ExperimentCanary, "paused", []string{"r1"}, "opus")}, ""},
		{"shadow mirrors, does not route", []*Experiment{exp("a", ExperimentCanary, "running", []string{"r1"}, "opus"), exp("b", ExperimentShadow, "running", []string{"r1"}, "opus")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := guardTrafficOverlap(&Org{Experiments: tc.exps})
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected issues: %v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Severity != SeverityError || !strings.Contains(got[0].Message, tc.want) {
				t.Fatalf("issues = %v, want one error containing %q", got, tc.want)
			}
		})
	}
}
