package policy

import (
	"strings"
	"testing"
)

func TestValidateOnlineMetricSources(t *testing.T) {
	clientAxis := func(o *Org) {
		e := o.Experiments[0]
		e.Axis, e.Type = AxisClient, ExperimentAB
		e.Variants = []Variant{{Name: "c", Weight: 1, Profile: "base", Control: true}, {Name: "t", Weight: 1, Profile: "next"}}
	}
	for _, tc := range []struct {
		name       string
		mod        func(*Org)
		primary    string
		guardrails []string
		want       string // "" = valid
	}{
		{"traffic + gateway metrics", nil, "halo.api.error_rate", []string{"halo.latency.p95_ms"}, ""},
		{"eval-only primary", nil, "halo.task.success", nil, "halo.task.success is only measured by `halo eval`"},
		{"eval-only guardrail", clientAxis, "halo.edit.accept_rate", []string{"halo.task.success"}, "guardrails[0].metric: halo.task.success is only measured"},
		{"traffic + cli-only metric", nil, "halo.api.error_rate", []string{"halo.cost.usd_per_session"}, "never see the gateway-assigned variant"},
		{"client + cli metrics", clientAxis, "halo.edit.accept_rate", []string{"halo.cost.usd_per_session", "halo.tool.error_rate", "halo.latency.p95_ms"}, ""},
		{"no online source", clientAxis, "halo.session.duration_s", nil, "has no online metric source"},
		{"shadow is graded offline", func(o *Org) {
			e := o.Experiments[0]
			e.Type, e.SampleRate = ExperimentShadow, 0.1
		}, "halo.task.success", []string{"halo.cost.usd_per_session"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := validOrg()
			if tc.mod != nil {
				tc.mod(o)
			}
			e := o.Experiments[0]
			e.Metrics.Primary.Metric = tc.primary
			for _, g := range tc.guardrails {
				e.Metrics.Guardrails = append(e.Metrics.Guardrails, MetricGoal{Metric: g, Direction: "decrease", MaxRegression: 0.1})
			}
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
