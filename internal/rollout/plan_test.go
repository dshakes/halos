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
	mustWrite(t, filepath.Join(dir, "rollouts", "sonnet.yaml"), `apiVersion: halos.dev/v1
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

// Completing a traffic rollout in simple mode leaves the policy clean:
// halos.yaml models.<alias> names the new model and the gateway.yaml override
// generated for the rollout is gone; anything hand-written is kept in step.
func TestPlanCompleteSimpleMode(t *testing.T) {
	const generated = "labels:\n  halos.dev/generated-by: rollout/opus-next\n"
	override := func(labels, extra, route string) string {
		return "apiVersion: halos.dev/v1\nkind: Gateway\nname: acme-gateway\n" + labels + extra + "models:\n  opus:\n" + route
	}
	single := "    upstream: anthropic\n    model: claude-opus-4-1\n"
	tests := []struct {
		name       string
		opus       string // halos.yaml models.opus
		candidate  string // the experiment's treatment route for opus
		gateway    string // gateway.yaml; "" = none
		wantRoot   string // halos.yaml models.opus after; "" = unchanged
		wantGW     string // "deleted", "kept" or "" (no file)
		wantManual bool
	}{
		{name: "generated override is deleted", opus: "claude-opus-4-1", candidate: "{upstream: anthropic, model: claude-opus-5-5}",
			gateway: override(generated, "", single), wantRoot: "opus: claude-opus-5-5", wantGW: "deleted"},
		{name: "no override: halos.yaml only", opus: "claude-opus-4-1", candidate: "{upstream: anthropic, model: claude-opus-5-5}",
			wantRoot: "opus: claude-opus-5-5"},
		{name: "another provider is prefixed", opus: "claude-opus-4-1", candidate: "{upstream: bedrock, model: anthropic.claude-opus-5-5}",
			gateway: override(generated, "", single), wantRoot: "opus: bedrock/anthropic.claude-opus-5-5", wantGW: "deleted"},
		{name: "hand-written override is kept in step", opus: "claude-opus-4-1", candidate: "{upstream: anthropic, model: claude-opus-5-5}",
			gateway: override("", "", single), wantRoot: "opus: claude-opus-5-5", wantGW: "kept"},
		{name: "override generated for another rollout is kept", opus: "claude-opus-4-1", candidate: "{upstream: anthropic, model: claude-opus-5-5}",
			gateway: override("labels:\n  halos.dev/generated-by: rollout/other\n", "", single), wantRoot: "opus: claude-opus-5-5", wantGW: "kept"},
		{name: "generated override with more in it is kept", opus: "claude-opus-4-1", candidate: "{upstream: anthropic, model: claude-opus-5-5}",
			gateway: override(generated, "baseURL: https://ai.acme.example\n", single), wantRoot: "opus: claude-opus-5-5", wantGW: "kept"},
		{name: "failover list is a manual step", opus: "[claude-opus-4-1, bedrock/anthropic.claude-opus-4-1]", candidate: "{upstream: anthropic, model: claude-opus-5-5}",
			gateway: override(generated, "", "    targets:\n      - {upstream: anthropic, model: claude-opus-4-1}\n      - {upstream: bedrock, model: anthropic.claude-opus-4-1, priority: 1}\n"),
			wantGW:  "kept", wantManual: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "halos.yaml"), "org: acme\ntools:\n  claude-code: 2.1.300\nprovider: anthropic\nmodels:\n"+
				"  default: claude-sonnet-4-5\n  opus: "+tc.opus+"\n  haiku: bedrock/anthropic.claude-haiku-4-5\ngateway: https://ai.acme.example\n")
			mustWrite(t, filepath.Join(dir, "experiments/opus-next.yaml"), `apiVersion: halos.dev/v1
kind: Experiment
name: opus-next
type: canary
axis: traffic
status: running
rings: [ring1-canary]
variants:
  - {name: control, weight: 50, control: true}
  - {name: candidate, weight: 50, routes: {opus: `+tc.candidate+`}}
metrics:
  primary: {metric: halo.api.error_rate, direction: decrease}
  guardrails: [{metric: halo.latency.p95_ms, direction: decrease, maxRegression: 0.15}]
stopping: {method: msprt, alpha: 0.05}
`)
			mustWrite(t, filepath.Join(dir, "rollouts/opus-next.yaml"), `apiVersion: halos.dev/v1
kind: Rollout
name: opus-next
axis: traffic
status: active
step: c50
experiment: opus-next
change: {alias: opus}
steps:
  - {name: c50, strategy: canary, percent: 50}
`)
			if tc.gateway != "" {
				mustWrite(t, filepath.Join(dir, "gateway.yaml"), tc.gateway)
			}
			org := load(t, dir)
			r := rolloutOf(t, org, "opus-next")
			if got := ManualSteps(org, r, Complete) != nil; got != tc.wantManual {
				t.Fatalf("manual = %v", got)
			}
			ch, err := Plan(dir, org, r, Complete, -1)
			if err != nil {
				t.Fatal(err)
			}
			again, err := ch.Edit(func(f string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, f)) })
			if err != nil {
				t.Fatal(err)
			}
			for f, b := range ch.Files {
				if (b == nil) != (again[f] == nil) || string(b) != string(again[f]) {
					t.Fatalf("Edit disagrees with Files for %s", f)
				}
				if b == nil {
					if err := os.Remove(filepath.Join(dir, f)); err != nil {
						t.Fatal(err)
					}
					continue
				}
				mustWrite(t, filepath.Join(dir, f), string(b))
			}
			root := mustRead(t, filepath.Join(dir, "halos.yaml"))
			if tc.wantRoot != "" && !strings.Contains(root, "  "+tc.wantRoot+"\n") {
				t.Fatalf("halos.yaml:\n%s", root)
			} else if tc.wantRoot == "" && !strings.Contains(root, "  opus: "+tc.opus+"\n") {
				t.Fatalf("halos.yaml changed:\n%s", root)
			}
			_, statErr := os.Stat(filepath.Join(dir, "gateway.yaml"))
			switch tc.wantGW {
			case "deleted":
				if b, ok := ch.Files["gateway.yaml"]; !ok || b != nil || !os.IsNotExist(statErr) {
					t.Fatalf("override not deleted (%v)", statErr)
				}
			case "kept":
				if statErr != nil {
					t.Fatalf("override removed: %v", statErr)
				}
			}
			after := load(t, dir) // the completed policy still validates
			if !tc.wantManual {
				up, model, _ := strings.Cut(strings.Trim(tc.candidate, "{}"), ", ")
				want := policy.ModelRoute{Upstream: strings.TrimPrefix(up, "upstream: "), Model: strings.TrimPrefix(model, "model: ")}
				if got := after.Gateway.Models["opus"]; got.Upstream != want.Upstream || got.Model != want.Model || len(got.Targets) != 0 {
					t.Fatalf("opus routes to %+v, want %+v", got, want)
				}
			}
			if r := rolloutOf(t, after, "opus-next"); r.Status != policy.RolloutCompleted {
				t.Fatalf("status %q", r.Status)
			}
		})
	}
}
