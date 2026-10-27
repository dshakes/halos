package roi

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

var (
	t0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	t1 = t0.Add(6 * 7 * 24 * time.Hour)
)

func testOrg(status string) (*policy.Org, *policy.Experiment) {
	e := &policy.Experiment{Meta: policy.Meta{Name: "cli-next"}, Status: status, Rings: []string{"ring1", "ring3"},
		Variants: []policy.Variant{{Name: "control", Weight: 50, Control: true}, {Name: "next", Weight: 50}}}
	org := &policy.Org{
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "ring0"}, Membership: policy.Membership{Groups: []string{"ai-platform"}}},
			{Meta: policy.Meta{Name: "ring1"}, Membership: policy.Membership{Percent: 50}},
			{Meta: policy.Meta{Name: "ring3"}, Membership: policy.Membership{Default: true}},
		},
		Experiments: []*policy.Experiment{e},
	}
	return org, e
}

// world generates delivery data where the treatment arm's effect is known.
type world struct {
	devs      int
	cycleMult float64 // treatment multiplier on mean cycle time
	rateMult  float64 // treatment multiplier on PRs per developer
	drop      float64 // share of treatment developers who open no PR
	// noveltyUntil: the cycle-time effect applies only to PRs opened before it.
	noveltyUntil time.Time
	seed         uint64
}

func poisson(rng *rand.Rand, lambda float64) int {
	l, k, p := math.Exp(-lambda), 0, 1.0
	for {
		p *= rng.Float64()
		if p <= l {
			return k
		}
		k++
	}
}

// build returns the roster, the PRs (in a FileStore) and each subject's arm.
func (w world) build(t *testing.T, org *policy.Org, e *policy.Experiment) (*Identities, Store) {
	t.Helper()
	rng := rand.New(rand.NewPCG(w.seed, 7)) //nolint:gosec // test data
	var roster strings.Builder
	roster.WriteString("login,subject,groups\n")
	var prs []PR
	span := t1.Add(-7*24*time.Hour).Sub(t0) - time.Hour // leave a week to merge
	for i := range w.devs {
		sub := policy.Subject{ID: fmt.Sprintf("dev%04d@acme.com", i)}
		fmt.Fprintf(&roster, "GH-Dev%04d,%s,\n", i, sub.ID)
		v := e.AssignVariant(sub, org.ResolveRing(sub).Name)
		trt := v != nil && !v.Control
		if trt && rng.Float64() < w.drop {
			continue
		}
		lambda, mu := 8.0, 24*(0.5+rng.Float64()) // developer-level heterogeneity
		if trt {
			lambda *= w.rateMult
		}
		for range poisson(rng, lambda) {
			opened := t0.Add(time.Duration(rng.Float64() * float64(span)))
			m := mu
			if trt && (w.noveltyUntil.IsZero() || opened.Before(w.noveltyUntil)) {
				m *= w.cycleMult
			}
			merged := opened.Add(time.Duration(rng.ExpFloat64() * m * float64(time.Hour)))
			prs = append(prs, PR{Source: "github", Repo: "acme/api", Number: int64(len(prs) + 1), Author: fmt.Sprintf("gh-dev%04d", i),
				OpenedAt: opened, MergedAt: &merged, ReviewRounds: 1 + poisson(rng, 0.5), Additions: 50 + rng.IntN(100),
				ChangeFailure: rng.Float64() < 0.1})
		}
	}
	ids, err := ParseIdentities(strings.NewReader(roster.String()))
	if err != nil {
		t.Fatal(err)
	}
	st := FileStore{Path: t.TempDir() + "/prs.jsonl"}
	if err := st.Put(context.Background(), prs); err != nil {
		t.Fatal(err)
	}
	return ids, st
}

func effect(t *testing.T, rep *Report, metric string) Effect {
	t.Helper()
	for _, e := range rep.Effects {
		if e.Metric == metric {
			return e
		}
	}
	t.Fatalf("no effect for %s", metric)
	return Effect{}
}

func TestAnalyzeRecoversKnownEffect(t *testing.T) {
	org, e := testOrg("concluded") // analysis after the experiment ended
	ids, st := world{devs: 400, cycleMult: 0.8, rateMult: 1.25, seed: 3}.build(t, org, e)
	rep, err := Analyze(context.Background(), st, nil, ids, Options{Org: org, Experiment: e, From: t0, To: t1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Design != DesignRandomized || rep.Status != StatusOK || rep.SRM == nil || rep.SRM.Mismatch {
		t.Fatalf("design %s status %s srm %+v warnings %v", rep.Design, rep.Status, rep.SRM, rep.Warnings)
	}
	for _, tc := range []struct {
		metric  string
		rel     float64
		outcome string
	}{
		{MetricCycleTime, -0.20, "improved"},
		{MetricThroughput, 0.25, "improved"},
	} {
		ef := effect(t, rep, tc.metric)
		if ef.Kind != "causal" || ef.State != StateSignificant || ef.Outcome != tc.outcome {
			t.Errorf("%s: kind %s state %s outcome %s", tc.metric, ef.Kind, ef.State, ef.Outcome)
		}
		if ef.RelCILo > tc.rel || ef.RelCIHi < tc.rel {
			t.Errorf("%s: relative CI [%.3f, %.3f] misses the true %.2f (estimate %.3f)", tc.metric, ef.RelCILo, ef.RelCIHi, tc.rel, ef.Rel)
		}
		if len(ef.Slices) != 3 || ef.Novelty {
			t.Errorf("%s: %d slices, novelty %v: a constant effect is not novelty", tc.metric, len(ef.Slices), ef.Novelty)
		}
	}
	// Change failure has no true effect: never "significant".
	if cf := effect(t, rep, MetricChangeFailure); cf.State == StateSignificant {
		t.Errorf("change failure: null effect reported significant (CI [%.3f, %.3f])", cf.CILo, cf.CIHi)
	}
	md := rep.Markdown()
	for _, want := range []string{"Delivery ROI (randomized", "Randomized:", "intent-to-treat", MetricCycleTime, "never decides a promotion"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
}

func TestAnalyzeSRM(t *testing.T) {
	org, e := testOrg("running")
	ids, st := world{devs: 400, cycleMult: 1, rateMult: 1, drop: 0.4, seed: 5}.build(t, org, e)
	rep, err := Analyze(context.Background(), st, nil, ids, Options{Org: org, Experiment: e, From: t0, To: t1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SRM == nil || !rep.SRM.Mismatch || rep.Status != StatusSRM {
		t.Fatalf("srm %+v status %s: losing 40%% of one arm must be a mismatch", rep.SRM, rep.Status)
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "sample ratio mismatch") || !strings.Contains(rep.Markdown(), "MISMATCH") {
		t.Fatalf("warnings %v", rep.Warnings)
	}
}

func TestAnalyzeNovelty(t *testing.T) {
	org, e := testOrg("running")
	ids, st := world{devs: 600, cycleMult: 0.4, rateMult: 1, noveltyUntil: t0.Add(14 * 24 * time.Hour), seed: 11}.build(t, org, e)
	rep, err := Analyze(context.Background(), st, nil, ids, Options{Org: org, Experiment: e, From: t0, To: t1})
	if err != nil {
		t.Fatal(err)
	}
	if ef := effect(t, rep, MetricCycleTime); !ef.Novelty {
		t.Fatalf("an effect only in the first two weeks must be flagged; slices %+v", ef.Slices)
	}
}

func TestAnalyzePowerStates(t *testing.T) {
	org, e := testOrg("running")
	tests := []struct {
		name  string
		devs  int
		min   int
		state string
	}{
		{"too few developers", 12, 10, StateInsufficientData},
		{"small study", 30, 5, StateInsufficientPower},
		{"large null study", 3000, 10, StateNoDetectableEffect},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ids, st := world{devs: tc.devs, cycleMult: 1, rateMult: 1, seed: 13}.build(t, org, e)
			rep, err := Analyze(context.Background(), st, nil, ids, Options{Org: org, Experiment: e, From: t0, To: t1, MinDevelopers: tc.min, Iters: 500, Slices: 1})
			if err != nil {
				t.Fatal(err)
			}
			ef := effect(t, rep, MetricThroughput)
			if ef.State != tc.state {
				t.Fatalf("state %s (CI [%.3f, %.3f], MDE %.3f), want %s", ef.State, ef.CILo, ef.CIHi, ef.MDERel, tc.state)
			}
			if tc.state == StateInsufficientData && rep.Status != StatusInsufficientData {
				t.Fatalf("status %s", rep.Status)
			}
		})
	}
}

func TestAnalyzeObservationalRings(t *testing.T) {
	org, e := testOrg("running")
	ids, st := world{devs: 300, cycleMult: 0.8, rateMult: 1, seed: 17}.build(t, org, e)
	rep, err := Analyze(context.Background(), st, nil, ids, Options{Org: org, Rings: []string{"ring3", "ring1"}, From: t0, To: t1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Design != DesignObservational || rep.SRM != nil || rep.Control != "ring3" || !strings.HasPrefix(rep.Claim, "Observational") {
		t.Fatalf("design %s control %s srm %v claim %q", rep.Design, rep.Control, rep.SRM, rep.Claim)
	}
	for _, ef := range rep.Effects {
		if ef.Kind != "association" {
			t.Fatalf("%s: kind %s; a ring comparison is never causal", ef.Metric, ef.Kind)
		}
	}
	if md := rep.Markdown(); strings.Contains(md, "| Effect") || !strings.Contains(md, "Difference") {
		t.Fatalf("observational markdown must say difference, not effect:\n%s", md)
	}
}

func TestAnalyzeExclusionsAndErrors(t *testing.T) {
	org, e := testOrg("running")
	ids, err := ParseIdentities(strings.NewReader("login,subject,groups,kind\nalice,Alice@Acme.com,,\nci-bot,ci@acme.com,,workload\nplat,plat@acme.com,ai-platform,\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := t0.Add(time.Hour)
	st := FileStore{Path: t.TempDir() + "/prs.jsonl"}
	if err := st.Put(context.Background(), []PR{
		{Source: "github", Repo: "a/b", Number: 1, Author: "ALICE", OpenedAt: t0, MergedAt: &m},
		{Source: "github", Repo: "a/b", Number: 2, Author: "dependabot", Bot: true, OpenedAt: t0},
		{Source: "github", Repo: "a/b", Number: 3, Author: "ci-bot", OpenedAt: t0},
		{Source: "github", Repo: "a/b", Number: 4, Author: "stranger", OpenedAt: t0},
		{Source: "github", Repo: "a/b", Number: 5, Author: "plat", OpenedAt: t0},          // ring0: not enrolled
		{Source: "file", Repo: "a/b", Number: 6, Subject: "alice@acme.com", OpenedAt: t0}, // subject wins
		{Source: "github", Repo: "a/b", Number: 7, Author: "alice", OpenedAt: t1},         // outside the window
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := Analyze(context.Background(), st, nil, ids, Options{Org: org, Experiment: e, From: t0, To: t1})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"bot_or_workload": 2, "unmapped_author": 1, "outside_arms": 1}
	for k, v := range want {
		if rep.Excluded[k] != v {
			t.Errorf("excluded[%s] = %d, want %d (%v)", k, rep.Excluded[k], v, rep.Excluded)
		}
	}
	if len(rep.UnmappedLogins) != 1 || rep.UnmappedLogins[0] != "stranger" {
		t.Errorf("unmapped %v", rep.UnmappedLogins)
	}
	prs := 0
	for _, a := range rep.Arms {
		prs += a.PRs
	}
	if prs != 2 {
		t.Errorf("alice's PRs counted %d, want 2", prs)
	}
	for name, o := range map[string]Options{
		"both":         {Org: org, Experiment: e, Rings: []string{"ring1"}, From: t0, To: t1},
		"neither":      {Org: org, From: t0, To: t1},
		"empty window": {Org: org, Experiment: e, From: t1, To: t0},
		"one ring":     {Org: org, Rings: []string{"ring1"}, From: t0, To: t1},
		"unknown ring": {Org: org, Rings: []string{"ring1", "nope"}, From: t0, To: t1},
		"no control": {Org: org, Experiment: &policy.Experiment{Meta: policy.Meta{Name: "x"}, Rings: []string{"ring1"},
			Variants: []policy.Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}}}, From: t0, To: t1},
	} {
		if _, err := Analyze(context.Background(), st, nil, ids, o); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// The arm Analyze recovers is the one the fleet served: ResolveVariant while
// the experiment runs.
func TestArmMatchesServedVariant(t *testing.T) {
	org, e := testOrg("running")
	o := Options{Org: org, Experiment: e}
	arms := []string{"control", "next"}
	for i := range 500 {
		s := policy.Subject{ID: fmt.Sprintf("u%d@acme.com", i)}
		if i%7 == 0 {
			s.Groups = []string{"ai-platform"}
		}
		want := -1
		if v := e.ResolveVariant(s, org.ResolveRing(s).Name); v != nil {
			want = map[string]int{"control": 0, "next": 1}[v.Name]
		}
		if got := armOf(o, arms, s); got != want {
			t.Fatalf("%s: arm %d, served %d", s.ID, got, want)
		}
	}
}

type fakeCost map[string]ArmCost

func (f fakeCost) ArmCosts(context.Context, string, []string, time.Time, time.Time) (map[string]ArmCost, string, error) {
	return f, "gateway", nil
}

func TestAnalyzeCostPerMergedPR(t *testing.T) {
	org, e := testOrg("running")
	ids, st := world{devs: 100, cycleMult: 1, rateMult: 1, seed: 19}.build(t, org, e)
	rep, err := Analyze(context.Background(), st, fakeCost{"control": {USD: 1000, Units: 40}}, ids, Options{Org: org, Experiment: e, From: t0, To: t1})
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Arms[0]
	if c.Merged == 0 || math.Abs(c.CostPerMergedPR-1000/float64(c.Merged)) > 1e-9 || rep.CostSource != "gateway" {
		t.Fatalf("control arm %+v source %s", c, rep.CostSource)
	}
	if rep.Arms[1].CostPerMergedPR != 0 {
		t.Fatalf("no cost rows for next: %+v", rep.Arms[1])
	}
}

// Identical arms differ only by float noise (~1e-16): never "significant".
func TestAnalyzeIdenticalArmsNotSignificant(t *testing.T) {
	org, e := testOrg("running")
	var roster strings.Builder
	roster.WriteString("login,subject\n")
	var prs []PR
	for i := range 200 {
		fmt.Fprintf(&roster, "u%d,u%d@acme.com\n", i, i)
		m := t0.Add(5 * time.Hour)
		prs = append(prs, PR{Source: "github", Repo: "a/b", Number: int64(i + 1), Author: fmt.Sprintf("u%d", i), OpenedAt: t0, MergedAt: &m, ReviewRounds: 1})
	}
	ids, err := ParseIdentities(strings.NewReader(roster.String()))
	if err != nil {
		t.Fatal(err)
	}
	st := FileStore{Path: t.TempDir() + "/prs.jsonl"}
	if err := st.Put(context.Background(), prs); err != nil {
		t.Fatal(err)
	}
	rep, err := Analyze(context.Background(), st, nil, ids, Options{Org: org, Experiment: e, From: t0, To: t1, Slices: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, ef := range rep.Effects {
		if ef.State == StateSignificant {
			t.Errorf("%s: identical arms reported significant (CI [%g, %g])", ef.Metric, ef.CILo, ef.CIHi)
		}
	}
}
