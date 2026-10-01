package policy

import (
	"strings"
	"testing"
	"time"
)

func TestValidateRollouts(t *testing.T) {
	tests := []struct {
		name    string
		rollout string
		mut     func(o *Org, r *Rollout)
		path    string // "" = no issues
		msg     string
	}{
		{name: "examples clean", rollout: "opus-5-5-upgrade", mut: func(*Org, *Rollout) {}},
		{name: "bad status", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Status = "live" }, path: ".status", msg: "invalid"},
		{name: "unknown live step", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Step = "nope" }, path: ".step", msg: "not one of steps"},
		{name: "unknown experiment", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Experiment = "nope" }, path: ".experiment", msg: "not defined"},
		{name: "experiment axis mismatch", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Experiment = "claude-cli-2.1.3xx-ab" }, path: ".experiment", msg: "has axis"},
		{name: "experiment shared", rollout: "claude-code-2.1.300", mut: func(o *Org, r *Rollout) {
			c := *r
			c.Name = "twin"
			o.Rollouts = append(o.Rollouts, &c)
		}, path: "rollouts[twin].experiment", msg: "already backs"},
		{name: "percent steps need an experiment", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Experiment = "" }, path: ".experiment", msg: "required"},
		{name: "traffic alias unknown", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Change.Alias = "nope" }, path: ".change.alias", msg: "not defined in gateway.models"},
		{name: "treatment lacks route", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Change.Alias = "sonnet" }, path: ".change.alias", msg: "has no route"},
		{name: "client needs release", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Change.Release = "" }, path: ".change.release", msg: "release digest"},
		{name: "client needs a ring-wide step", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps = r.Steps[:4] }, path: ".steps", msg: "progressive or blue-green"},
		{name: "ring-wide needs baseline", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Baseline.Release = "" }, path: ".baseline.release", msg: "switch back"},
		{name: "progressive on traffic", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) {
			r.Steps = append(r.Steps, RolloutStep{Name: "x", Strategy: StrategyProgressive, Ring: "ring3-ga"})
		}, path: ".steps[6].strategy", msg: "client axis only"},
		{name: "dark-launch on client", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) {
			r.Steps[0].Strategy = StrategyDarkLaunch
		}, path: ".steps[0].strategy", msg: "traffic axis only"},
		{name: "canary at 100", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Steps[4].Percent = 100 }, path: ".steps[4].percent", msg: "out of range"},
		{name: "canary ramp down", rollout: "opus-5-5-upgrade", mut: func(_ *Org, r *Rollout) { r.Steps[2].Percent = 0.5 }, path: ".steps[2].percent", msg: "flip back"},
		{name: "progressive with partial percent", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[4].Percent = 50 }, path: ".steps[4].percent", msg: "unset or 100"},
		{name: "ring-wide guardrails need a control arm", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) {
			r.Steps[4].MinSamples = 10
		}, path: ".steps[4].gates", msg: "no control arm"},
		{name: "unknown ring", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[5].Ring = "nope" }, path: ".steps[5].ring", msg: "not defined"},
		{name: "ring outside experiment", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[0].Ring = "ring3-ga" }, path: ".steps[0].ring", msg: "not one of experiment"},
		{name: "bad bake", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[0].Bake = "2 weeks" }, path: ".steps[0].bake", msg: "want a duration"},
		{name: "bad onFailure", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[0].OnFailure = "panic" }, path: ".steps[0].onFailure", msg: "invalid"},
		{name: "duplicate step", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[1].Name = r.Steps[0].Name }, path: ".steps[1].name", msg: "duplicate"},
		{name: "unknown guardrail metric", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) {
			r.Steps[0].Gates.Guardrails = []MetricGoal{{Metric: "halo.nope", Direction: "decrease"}}
		}, path: ".steps[0].gates.guardrails[0].metric", msg: "unknown metric"},
		{name: "scorecard escapes the repo", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[2].Gates.Scorecard.File = "../x.json" }, path: ".steps[2].gates.scorecard.file", msg: "inside the policy repo"},
		{name: "scorecard floor out of range", rollout: "claude-code-2.1.300", mut: func(_ *Org, r *Rollout) { r.Steps[2].Gates.Scorecard.MinPass1 = 70 }, path: ".steps[2].gates.scorecard.minPass1", msg: "[0,1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Load(exampleDir)
			if err != nil {
				t.Fatal(err)
			}
			var r *Rollout
			for _, x := range o.Rollouts {
				if x.Name == tc.rollout {
					r = x
				}
			}
			tc.mut(o, r)
			issues := o.Validate()
			if tc.path == "" {
				if len(issues) != 0 {
					t.Fatalf("unexpected issues: %v", issues)
				}
				return
			}
			for _, i := range issues {
				if strings.HasSuffix(i.Path, tc.path) && strings.Contains(i.Message, tc.msg) && i.Severity == SeverityError {
					return
				}
			}
			t.Fatalf("no error at *%s containing %q; got %v", tc.path, tc.msg, issues)
		})
	}
}

func TestParseBake(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "30m": 30 * time.Minute, "1h30m": 90 * time.Minute, "14d": 14 * 24 * time.Hour} {
		if got, err := ParseBake(in); err != nil || got != want {
			t.Errorf("ParseBake(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"-1h", "1.5d", "d", "-2d", "soon"} {
		if _, err := ParseBake(in); err == nil {
			t.Errorf("ParseBake(%q) accepted", in)
		}
	}
}

func TestLoadRolloutStrict(t *testing.T) {
	dir := writeRepo(t, map[string]string{"halos.yaml": "org: x\n", "r.yaml": hdr + "kind: Rollout\nname: r\naxis: client\nchange: {}\nsteps: []\nbogus: 1\n"})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("unknown field not rejected: %v", err)
	}
}
