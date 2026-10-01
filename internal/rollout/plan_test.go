package rollout

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

const exampleDir = "../../examples/acme-corp"

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// exampleCopy copies the example policy repo's YAML and JSON into a temp dir.
func exampleCopy(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(exampleDir, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(exampleDir, p)
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yaml" && filepath.Ext(p) != ".json") || strings.HasPrefix(rel, ".") {
			return err
		}
		mustWrite(t, filepath.Join(dst, rel), mustRead(t, p))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func load(t *testing.T, dir string) *policy.Org {
	t.Helper()
	org, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if issues := org.Validate(); policy.HasErrors(issues) {
		t.Fatalf("invalid policy: %v", issues)
	}
	return org
}

func rolloutOf(t *testing.T, org *policy.Org, name string) *policy.Rollout {
	t.Helper()
	for _, r := range org.Rollouts {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no rollout %s", name)
	return nil
}

// TestPlan applies each planned change and checks the policy still loads,
// validates, and says what the step means.
func TestPlan(t *testing.T) {
	tests := []struct {
		name    string
		rollout string
		step    string // live step before the action ("" = not started)
		act     Action
		next    int
		check   func(t *testing.T, org *policy.Org)
		manual  bool
	}{
		{name: "start canary", rollout: "claude-code-2.1.300", act: Advance, next: 0, check: func(t *testing.T, org *policy.Org) {
			r, e := rolloutOf(t, org, "claude-code-2.1.300"), exp(t, org, "claude-cli-2.1.3xx-ab")
			if r.Status != policy.RolloutActive || r.Step != "canary-1" || e.Type != policy.ExperimentCanary || e.Status != "running" || e.Variants[0].Weight != 99 || e.Variants[1].Weight != 1 {
				t.Fatalf("rollout %+v experiment %+v", r, e)
			}
		}},
		{name: "progressive moves the ring pointer and pauses the canary", rollout: "claude-code-2.1.300", step: "canary-50", act: Advance, next: 4, check: func(t *testing.T, org *policy.Org) {
			if rg := ring(t, org, "ring1-canary"); rg.Release != rolloutOf(t, org, "claude-code-2.1.300").Change.Release {
				t.Fatalf("ring1 release = %q", rg.Release)
			}
			if e := exp(t, org, "claude-cli-2.1.3xx-ab"); e.Status != "paused" {
				t.Fatalf("experiment status %q", e.Status)
			}
		}},
		{name: "rollback re-points every moved ring", rollout: "claude-code-2.1.300", step: "early", act: Rollback, check: func(t *testing.T, org *policy.Org) {
			r := rolloutOf(t, org, "claude-code-2.1.300")
			for _, n := range []string{"ring1-canary", "ring2-early"} {
				if rg := ring(t, org, n); rg.Release != r.Baseline.Release {
					t.Fatalf("%s release = %q", n, rg.Release)
				}
			}
			if ring(t, org, "ring3-ga").Release == r.Baseline.Release || r.Status != policy.RolloutAborted {
				t.Fatal("ga touched or status not aborted")
			}
		}},
		{name: "dark-launch runs a shadow", rollout: "opus-5-5-upgrade", act: Advance, next: 0, check: func(t *testing.T, org *policy.Org) {
			if e := exp(t, org, "opus-5-5-canary"); e.Type != policy.ExperimentShadow || e.SampleRate != 0.1 || e.Status != "running" {
				t.Fatalf("experiment %+v", e)
			}
		}},
		{name: "holdout keeps percent on control", rollout: "opus-5-5-upgrade", step: "canary-50", act: Advance, next: 5, check: func(t *testing.T, org *policy.Org) {
			if e := exp(t, org, "opus-5-5-canary"); e.Variants[0].Weight != 5 || e.Variants[1].Weight != 95 {
				t.Fatalf("weights %v/%v", e.Variants[0].Weight, e.Variants[1].Weight)
			}
		}},
		{name: "complete with multi-target route is manual", rollout: "opus-5-5-upgrade", step: "holdout", act: Complete, manual: true, check: func(t *testing.T, org *policy.Org) {
			if e := exp(t, org, "opus-5-5-canary"); e.Status != "concluded" || len(org.Gateway.Models["opus"].Targets) == 0 {
				t.Fatalf("experiment %q, opus route %+v", e.Status, org.Gateway.Models["opus"])
			}
		}},
		{name: "pause", rollout: "opus-5-5-upgrade", step: "canary-5", act: Pause, check: func(t *testing.T, org *policy.Org) {
			if r := rolloutOf(t, org, "opus-5-5-upgrade"); r.Status != policy.RolloutPaused {
				t.Fatalf("status %q", r.Status)
			}
		}},
		{name: "blue-green without an experiment", rollout: "engineering-settings-2026-10", act: Advance, next: 0, check: func(t *testing.T, org *policy.Org) {
			if rg := ring(t, org, "ring0-harness-team"); rg.Release != rolloutOf(t, org, "engineering-settings-2026-10").Change.Release {
				t.Fatalf("release %q", rg.Release)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := exampleCopy(t)
			org := load(t, dir)
			r := rolloutOf(t, org, tc.rollout)
			r.Step = tc.step
			ch, err := Plan(dir, org, r, tc.act, tc.next)
			if err != nil {
				t.Fatal(err)
			}
			if ch.Patch == "" || !strings.Contains(ch.Patch, "+++ b/") {
				t.Fatalf("empty patch")
			}
			for f, b := range ch.Files {
				mustWrite(t, filepath.Join(dir, f), string(b))
			}
			tc.check(t, load(t, dir))
			if got := ManualSteps(org, r, tc.act) != nil; got != tc.manual {
				t.Fatalf("manual = %v", got)
			}
			// The PR re-applies the same change to whatever HEAD holds.
			again, err := ch.Edit(func(f string) ([]byte, error) { return os.ReadFile(filepath.Join(exampleDir, f)) })
			if err != nil {
				t.Fatal(err)
			}
			for f, b := range ch.Files {
				if string(again[f]) != string(b) {
					t.Fatalf("Edit disagrees with Files for %s", f)
				}
			}
		})
	}
}

func TestPlanCompleteSimpleRoute(t *testing.T) {
	dir := exampleCopy(t)
	mustWrite(t, filepath.Join(dir, "rollouts", "sonnet.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Rollout
name: sonnet-next
axis: traffic
status: active
step: c
experiment: sonnet-next-shadow
change: {alias: sonnet}
steps:
  - {name: c, strategy: canary, percent: 50}
`)
	org := load(t, dir)
	ch, err := Plan(dir, org, rolloutOf(t, org, "sonnet-next"), Complete, -1)
	if err != nil {
		t.Fatal(err)
	}
	for f, b := range ch.Files {
		mustWrite(t, filepath.Join(dir, f), string(b))
	}
	if got := load(t, dir).Gateway.Models["sonnet"]; got.Upstream != "anthropic-direct" || got.Model != "claude-sonnet-next" {
		t.Fatalf("sonnet route = %+v", got)
	}
}

func exp(t *testing.T, org *policy.Org, name string) *policy.Experiment {
	t.Helper()
	if e := findExp(org, name); e != nil {
		return e
	}
	t.Fatalf("no experiment %s", name)
	return nil
}

func ring(t *testing.T, org *policy.Org, name string) *policy.Ring {
	t.Helper()
	for _, r := range org.Rings {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no ring %s", name)
	return nil
}

func TestSimulate(t *testing.T) {
	org := load(t, exampleDir)
	ctx := context.Background()
	tests := []struct {
		rollout, scenario string
		want              Action
	}{
		{"claude-code-2.1.300", ScenarioHealthy, Complete},
		{"claude-code-2.1.300", ScenarioRegression, Rollback},
		{"opus-5-5-upgrade", ScenarioHealthy, Complete},
		{"opus-5-5-upgrade", ScenarioRegression, Rollback},
		{"engineering-settings-2026-10", ScenarioHealthy, Complete},
	}
	for _, tc := range tests {
		t.Run(tc.rollout+"/"+tc.scenario, func(t *testing.T) {
			res, err := Simulate(ctx, exampleDir, org, rolloutOf(t, org, tc.rollout), SimOptions{Scenario: tc.scenario, Seed: 1})
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != tc.want {
				t.Fatalf("outcome %s, want %s; events %+v", res.Outcome, tc.want, res.Events)
			}
			again, _ := Simulate(ctx, exampleDir, org, rolloutOf(t, org, tc.rollout), SimOptions{Scenario: tc.scenario, Seed: 1})
			a, _ := json.Marshal(res)
			b, _ := json.Marshal(again)
			if string(a) != string(b) {
				t.Fatal("simulation is not deterministic")
			}
		})
	}
	// Recorded evidence: one failing report trips the first guardrailed step.
	r := rolloutOf(t, org, "opus-5-5-upgrade")
	var rec []Evidence
	if err := json.Unmarshal([]byte(`[{"report":{"nControl":900,"nTreatment":900,"guardrails":[{"metric":"halo.latency.p95_ms","source":"gateway","result":{"status":"fail","regression":0.4}}]}}]`), &rec); err != nil {
		t.Fatal(err)
	}
	res, err := Simulate(ctx, exampleDir, org, r, SimOptions{Recorded: rec})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Pause || res.Events[len(res.Events)-1].Step != "dark-launch" {
		t.Fatalf("recorded: %s at %+v", res.Outcome, res.Events[len(res.Events)-1])
	}
}

func TestTimeline(t *testing.T) {
	org := load(t, exampleDir)
	tl := BuildTimeline(org, rolloutOf(t, org, "opus-5-5-upgrade"))
	if len(tl.Steps) != 6 || tl.MinDuration != "18d18h" || tl.Steps[1].EarliestStart != "T+2d" || !tl.Steps[2].Live {
		t.Fatalf("timeline %+v", tl)
	}
	if !strings.Contains(tl.Steps[5].Exposure, "5% of ring1-canary held on control") {
		t.Fatalf("holdout exposure %q", tl.Steps[5].Exposure)
	}
}
