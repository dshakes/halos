package copilot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/roi"
)

func clientDesign(name string) *Design {
	return &Design{
		Name: name, Axis: policy.AxisClient, Rings: []string{"ring1-canary"},
		Variants: []policy.Variant{
			{Name: "control", Weight: 50, Profile: "engineering", Control: true},
			{Name: "next", Weight: 50, Profile: "engineering-next"},
		},
		Primary:    policy.MetricGoal{Metric: "halo.edit.accept_rate", Direction: "increase"},
		Guardrails: []policy.MetricGoal{{Metric: "halo.api.error_rate", Direction: "decrease", MaxRegression: 0.02}},
		Rationale:  "test",
	}
}

func TestSize(t *testing.T) {
	d := clientDesign("x")
	for _, tc := range []struct {
		name    string
		d       *Design
		s       Sizing
		perArm  int
		days    int
		maxDays int
		derived bool
		wantErr string
	}{
		// p=0.3, +10% relative: sd sqrt(.21), delta .03 -> 3663 per arm; 500/day at 50% -> 15 days
		{"rate derived sd", d, Sizing{Baseline: 0.3, MDE: 0.1, DailyUnits: 500}, 3663, 15, 30, true, ""},
		{"explicit sd", d, Sizing{Baseline: 10, SD: 5, MDE: 0.1, DailyUnits: 100}, 393, 8, 16, false, ""},
		{"no daily units", d, Sizing{Baseline: 0.3, MDE: 0.1}, 3663, 0, 21, true, ""},
		{"short run floors maxDays at 7", d, Sizing{Baseline: 10, SD: 5, MDE: 0.5, DailyUnits: 1000}, 16, 1, 7, false, ""},
		{"uneven weights size the small arm", &Design{Variants: []policy.Variant{{Weight: 90, Control: true}, {Weight: 10}}, Primary: d.Primary}, Sizing{Baseline: 0.3, MDE: 0.1, DailyUnits: 1000}, 3663, 37, 74, true, ""},
		{"non-rate needs sd", &Design{Variants: d.Variants, Primary: policy.MetricGoal{Metric: "halo.latency.p95_ms"}}, Sizing{Baseline: 900, MDE: 0.05}, 0, 0, 0, false, "--sd is required"},
		{"no baseline", d, Sizing{MDE: 0.1}, 0, 0, 0, false, "--baseline"},
		{"no mde", d, Sizing{Baseline: 0.3}, 0, 0, 0, false, "--mde"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := Size(tc.d, tc.s)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st.PerArm != tc.perArm || st.Days != tc.days || st.MaxDays != tc.maxDays || st.SDDerived != tc.derived {
				t.Fatalf("%+v", st)
			}
		})
	}
}

func TestExperimentOffline(t *testing.T) {
	res, err := (&Client{}).Experiment(context.Background(), example, "cli-next raises accept rate", clientDesign("cli-next-accept"),
		Sizing{Baseline: 0.3, MDE: 0.1, DailyUnits: 500})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Stats.PerArm != 3663 || res.File.Path != "experiments/cli-next-accept.yaml" {
		t.Fatalf("ok=%v %+v %+v", res.OK, res.Stats, res.Check)
	}
	for _, want := range []string{"status: draft", "minSamples: 3663", "maxDays: 30", "method: msprt", "kind: Experiment"} {
		if !strings.Contains(res.File.Content, want) {
			t.Fatalf("yaml lacks %q:\n%s", want, res.File.Content)
		}
	}
	// an existing experiment's file is never overwritten
	res, err = (&Client{}).Experiment(context.Background(), example, "h", clientDesign("claude-cli-2.1.3xx-ab"), Sizing{Baseline: 0.3, MDE: 0.1})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !strings.Contains(strings.Join(res.Check.Errors, "\n"), "already exists") {
		t.Fatalf("overwrite allowed: %+v", res.Check)
	}
	bad := clientDesign("two-controls")
	bad.Variants[1].Control = true
	if _, err := (&Client{}).Experiment(context.Background(), example, "h", bad, Sizing{Baseline: 0.3, MDE: 0.1}); err == nil {
		t.Fatal("two controls must fail")
	}
}

func TestExperimentModelDesignRepaired(t *testing.T) {
	unknownRing := clientDesign("cli-next-accept")
	unknownRing.Rings = []string{"ring9"}
	good := clientDesign("cli-next-accept")
	f := &fakeLLM{replies: []string{
		`{"name":"x","axis":"client","sampleSize":99}`, // the model tries to do the math: unknown field, rejected
		reply(t, unknownRing),                          // validation: unknown ring, fed back
		reply(t, good),
	}}
	res, err := f.client(t, Budget{MaxIterations: 3}, nil).Experiment(context.Background(), example, "cli-next raises accept rate", nil, Sizing{Baseline: 0.3, MDE: 0.1})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || f.calls != 3 || res.Stats.PerArm != 3663 {
		t.Fatalf("ok=%v calls=%d stopped=%q %+v", res.OK, f.calls, res.Stopped, res.Check)
	}
	if !strings.Contains(promptOf(f.bodies[2]), "ring9") {
		t.Fatal("validation error not fed back")
	}
}

func TestExplain(t *testing.T) {
	base, err := policy.Load(example)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := ReleaseFacts(nil, base, "ring1-canary")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, f := range facts {
		keys[f.Key] = true
	}
	if !keys["release.digest"] || !keys["release.diff"] {
		t.Fatalf("facts %v", keys)
	}

	t.Run("offline", func(t *testing.T) {
		ex, err := (&Client{}).Explain(context.Background(), "release ring1-canary", facts)
		if err != nil {
			t.Fatal(err)
		}
		if !ex.Offline || len(ex.Points) == 0 || len(ex.Used) == 0 || ex.Spend.Calls != 0 {
			t.Fatalf("%+v", ex)
		}
	})
	t.Run("uncited claims rejected", func(t *testing.T) {
		f := &fakeLLM{replies: []string{
			`{"summary":"s","points":[{"text":"it is safe","cites":["release.safety"]}]}`, // invented key
			`{"summary":"s","points":[{"text":"no citation","cites":[]}]}`,
			`{"summary":"Ring 1 gets a new release.","points":[{"text":"The digest is new.","cites":["release.digest","release.changed"]}]}`,
		}}
		ex, err := f.client(t, Budget{}, nil).Explain(context.Background(), "release ring1-canary", facts)
		if err != nil {
			t.Fatal(err)
		}
		if f.calls != 3 || ex.Summary != "Ring 1 gets a new release." || len(ex.Used) != 2 || ex.Used[0].Key != "release.changed" {
			t.Fatalf("calls=%d %+v", f.calls, ex)
		}
		if !strings.Contains(promptOf(f.bodies[1]), "release.safety") {
			t.Fatal("rejection not fed back")
		}
	})
	t.Run("ceiling", func(t *testing.T) {
		f := &fakeLLM{replies: []string{`{"summary":"s","points":[]}`}}
		ex, err := f.client(t, Budget{MaxIterations: 2}, nil).Explain(context.Background(), "x", facts)
		if err != nil {
			t.Fatal(err)
		}
		if ex.Summary != "" || f.calls != 2 || ex.Stopped == "" {
			t.Fatalf("calls=%d %+v", f.calls, ex)
		}
	})
}

func TestDiffFacts(t *testing.T) {
	dir := gitPolicy(t)
	res, err := (&Client{}).Draft(context.Background(), dir, "set claude-code version 2.1.300 in profile engineering")
	if err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	if err := os.WriteFile(filepath.Join(dir, res.Files[0].Path), []byte(res.Files[0].Content), 0o600); err != nil {
		t.Fatal(err)
	}
	facts, err := DiffFacts(example, dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range facts {
		got[f.Key] = f.Value
	}
	if !strings.Contains(got["files.profiles/engineering.yaml"], "+    version: 2.1.300") || got["plan.ring1-canary.changed"] != "true" || got["impact.sample"] == "" {
		t.Fatalf("facts %v", got)
	}
	same, err := DiffFacts(example, example)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range same {
		if strings.HasPrefix(f.Key, "files.") || f.Value == "true" {
			t.Fatalf("identical policies differ: %+v", f)
		}
	}
	m, _ := Flatten("e", map[string]any{"a": []any{1, "x", ""}, "b": map[string]any{"c": true}})
	if len(m) != 3 || m[0].Key != "e.a[0]" || m[2].Key != "e.b.c" {
		t.Fatalf("%+v", m)
	}
}

func TestNext(t *testing.T) {
	org, err := policy.Load(example)
	if err != nil {
		t.Fatal(err)
	}
	gate := func(v string) *eval.Scorecard {
		return &eval.Scorecard{Suite: "core", Control: "engineering", Gate: &eval.Gate{Verdict: v, Reasons: []string{"pass rate"}},
			Comparisons: []eval.Comparison{{Variant: "engineering-next", Control: "engineering", Tasks: 40, Delta: -0.1}}}
	}
	got, err := Next(NextInput{
		Org: org, PolicyDir: "pol",
		Verdicts: []Verdict{
			{Experiment: "opus-5-5-canary", Report: promote.Report{Verdict: promote.Promote, Reason: "primary improved"}, EvaluatedAt: time.Unix(0, 0)},
		},
		Scorecards: map[string]*eval.Scorecard{"sc.json": gate("block")},
		ROI:        &roi.Report{Status: roi.StatusSRM, Experiment: "claude-cli-2.1.3xx-ab", Design: "randomized"},
		Budgets:    []BudgetState{{Budget: "org-monthly", Key: "org", Utilization: 1.2, Exceeded: true}, {Budget: "b", Key: "k", Utilization: 0.1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"halo exp start sonnet-next-shadow --policy-dir pol": true,
		"halo exp promote opus-5-5-canary --ring " + ringOf(org, "opus-5-5-canary") + " --release '<sha256:treatment-release>' --dry-run --policy-dir pol": true,
		"halo exp analyze claude-cli-2.1.3xx-ab --clickhouse '<clickhouse-url>' --policy-dir pol":                                                          true,
		"halo exp pause claude-cli-2.1.3xx-ab --policy-dir pol":                                                                                            true, // eval blocks its arm
		"halo roi report --experiment claude-cli-2.1.3xx-ab --policy-dir pol":                                                                              true,
		"halo budget status --budget org-monthly --key org":                                                                                                true,
	}
	for _, s := range got {
		if !want[s.Command] {
			t.Errorf("unexpected suggestion %q (%s)", s.Command, s.Title)
		}
		if len(s.Evidence) == 0 {
			t.Errorf("suggestion without evidence: %+v", s)
		}
		delete(want, s.Command)
	}
	for c := range want {
		t.Errorf("missing suggestion %q", c)
	}
	if _, err := Next(NextInput{}); err == nil {
		t.Fatal("nil org must fail")
	}
}

func ringOf(org *policy.Org, exp string) string {
	for _, e := range org.Experiments {
		if e.Name == exp {
			return e.Rings[0]
		}
	}
	return ""
}
