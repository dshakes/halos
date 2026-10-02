package promote

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

func normals(rng *rand.Rand, n int, mu, sd float64) []float64 {
	x := make([]float64, n)
	for i := range x {
		x[i] = mu + sd*rng.NormFloat64()
	}
	return x
}

func exp() *policy.Experiment {
	return &policy.Experiment{
		Meta:     policy.Meta{Name: "sonnet-next", Kind: policy.KindExperiment},
		Variants: []policy.Variant{{Name: "control", Control: true}, {Name: "candidate"}},
		Metrics: policy.Metrics{
			Primary:    policy.MetricGoal{Metric: "halo.task.success", Direction: "increase"},
			Guardrails: []policy.MetricGoal{{Metric: "halo.cost.usd_per_session", Direction: "decrease", MaxRegression: 0.10}},
		},
		Stopping: policy.Stopping{Method: "msprt", Alpha: 0.05, MinSamples: 100, MaxDays: 14, MaxSpendUSD: 500},
	}
}

func TestEvaluate(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 1))
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(succC, succT, costC, costT float64, n int) map[string]map[string][]float64 {
		return map[string]map[string][]float64{
			"halo.task.success":         {"control": normals(rng, n, succC, 0.3), "candidate": normals(rng, n, succT, 0.3)},
			"halo.cost.usd_per_session": {"control": normals(rng, n, costC, 1), "candidate": normals(rng, n, costT, 1)},
		}
	}
	// The traffic guardrail `halo model switch --canary` generates, over a
	// control with no errors (per-unit error rates, candidate failing trtErr of units).
	errGuard := func(e *policy.Experiment) {
		e.Metrics.Guardrails = append(e.Metrics.Guardrails, policy.MetricGoal{Metric: "halo.api.error_rate", Direction: "decrease", MaxRegression: 0.05})
	}
	withErrs := func(d map[string]map[string][]float64, trtErr float64) map[string]map[string][]float64 {
		c, tr := make([]float64, 1000), make([]float64, 1000)
		for i := range tr {
			if rng.Float64() < trtErr {
				tr[i] = 1
			}
		}
		d["halo.api.error_rate"] = map[string][]float64{"control": c, "candidate": tr}
		return d
	}
	tests := []struct {
		name  string
		src   *MemorySource
		now   time.Time
		tweak func(*policy.Experiment)
		want  Verdict
	}{
		{"zero-error canary with a clear win promotes", &MemorySource{Start: start, Data: withErrs(mk(0.6, 0.7, 5, 5, 1000), 0)}, start.Add(48 * time.Hour), errGuard, Promote},
		{"errors over a zero-error control roll back", &MemorySource{Start: start, Data: withErrs(mk(0.6, 0.6, 5, 5, 1000), 0.3)}, start.Add(48 * time.Hour), errGuard, Rollback},
		{"clear win, guardrail ok", &MemorySource{Start: start, SpendUSD: 10, Data: mk(0.6, 0.7, 5, 5, 1000)}, start.Add(48 * time.Hour), nil, Promote},
		{"clear win, fixed horizon", &MemorySource{Start: start, Data: mk(0.6, 0.7, 5, 5, 1000)}, start.Add(48 * time.Hour), func(e *policy.Experiment) { e.Stopping.Method = "fixed" }, Promote},
		{"guardrail breach rolls back", &MemorySource{Start: start, Data: mk(0.6, 0.7, 5, 6, 1000)}, start.Add(48 * time.Hour), nil, Rollback},
		{"primary regression rolls back", &MemorySource{Start: start, Data: mk(0.7, 0.6, 5, 5, 1000)}, start.Add(48 * time.Hour), nil, Rollback},
		{"no effect continues", &MemorySource{Start: start, Data: mk(0.6, 0.6, 5, 5, 300)}, start.Add(48 * time.Hour), nil, Continue},
		{"below minSamples continues", &MemorySource{Start: start, Data: mk(0.6, 0.9, 5, 5, 20)}, start.Add(48 * time.Hour), nil, Continue},
		{"win but guardrail undecided continues", &MemorySource{Start: start, Data: mk(0.6, 0.7, 5, 5.5, 1000)}, start.Add(48 * time.Hour), nil, Continue},
		{"expired by days", &MemorySource{Start: start, Data: mk(0.6, 0.6, 5, 5, 300)}, start.Add(15 * 24 * time.Hour), nil, Expired},
		{"expired by spend", &MemorySource{Start: start, SpendUSD: 501, Data: mk(0.6, 0.6, 5, 5, 300)}, start.Add(time.Hour), nil, Expired},
		{"breach beats expiry", &MemorySource{Start: start, Data: mk(0.6, 0.7, 5, 6, 1000)}, start.Add(30 * 24 * time.Hour), nil, Rollback},
		{"no data yet continues", &MemorySource{}, start, nil, Continue},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := exp()
			if tc.tweak != nil {
				tc.tweak(e)
			}
			tc.src.Source = SourceGateway
			rep, err := EvaluateAt(context.Background(), e, tc.src, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != tc.want {
				t.Fatalf("got %v (%s), want %v", rep.Verdict, rep.Reason, tc.want)
			}
			// The deciding evidence's source is reported for promote/rollback only.
			if decided := rep.Verdict == Promote || rep.Verdict == Rollback; decided != (rep.Source == SourceGateway) {
				t.Errorf("verdict %s: source %q", rep.Verdict, rep.Source)
			}
			for _, g := range rep.Guardrails {
				if g.Source != SourceGateway {
					t.Errorf("guardrail %s: source %q", g.Metric, g.Source)
				}
			}
		})
	}
}

func TestEvaluateErrors(t *testing.T) {
	src := &MemorySource{Data: map[string]map[string][]float64{}}
	bad := exp()
	bad.Variants = bad.Variants[:1]
	if _, err := Evaluate(context.Background(), bad, src); err == nil {
		t.Fatal("want variant-count error")
	}
	bad = exp()
	bad.Variants[0].Control = false
	if _, err := Evaluate(context.Background(), bad, src); err == nil {
		t.Fatal("want no-control error")
	}
	bad = exp()
	bad.Stopping.Method = "bayes"
	rng := rand.New(rand.NewPCG(2, 2))
	src.Data["halo.task.success"] = map[string][]float64{"control": normals(rng, 200, 0, 1), "candidate": normals(rng, 200, 1, 1)}
	src.Data["halo.cost.usd_per_session"] = src.Data["halo.task.success"]
	src.Start = time.Now()
	if _, err := Evaluate(context.Background(), bad, src); err == nil {
		t.Fatal("want unknown-method error")
	}
}

func TestClickHouse(t *testing.T) {
	var gotQuery, gotUser string
	params := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		gotQuery, gotUser = string(b[:n]), r.Header.Get("X-ClickHouse-User")
		for k, v := range r.URL.Query() {
			params[k] = v[0]
		}
		if strings.Contains(gotQuery, "count()") {
			_, _ = w.Write([]byte(`{"n":5,"start":1767225600,"spend":12.5}` + "\n"))
			return
		}
		if strings.Contains(gotQuery, "boom") {
			http.Error(w, "boom", 500)
			return
		}
		_, _ = w.Write([]byte(`{"variant":"control","v":1}` + "\n" + `{"variant":"candidate","v":2}` + "\n" + `{"variant":"candidate","v":3}` + "\n"))
	}))
	defer srv.Close()
	ch := &ClickHouse{URL: srv.URL, Database: "halo", User: "u", Password: "p"}

	w, err := ch.Window(context.Background(), "exp'; DROP TABLE x;--")
	if err != nil || w.SpendUSD != 12.5 || w.Start.Unix() != 1767225600 {
		t.Fatalf("window %+v err %v", w, err)
	}
	if params["param_exp"] != "exp'; DROP TABLE x;--" || strings.Contains(gotQuery, "DROP") || gotUser != "u" || params["database"] != "halo" {
		t.Fatalf("value must be a bound param, not in SQL: q=%q params=%v", gotQuery, params)
	}
	s, _, err := ch.Samples(context.Background(), "e", "halo.task.success")
	if err != nil || len(s["candidate"]) != 2 || s["control"][0] != 1 || params["param_metric"] != "halo.task.success" {
		t.Fatalf("samples %v err %v", s, err)
	}
	if _, _, err := (&ClickHouse{URL: srv.URL, Table: "x; drop"}).Samples(context.Background(), "e", "m"); err == nil {
		t.Fatal("want bad table error")
	}
	if _, _, err := (&ClickHouse{URL: "http://127.0.0.1:1"}).Samples(context.Background(), "e", "m"); err == nil {
		t.Fatal("want connection error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ch.Samples(ctx, "e", "m"); err == nil {
		t.Fatal("want cancelled error")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) }))
	defer bad.Close()
	if _, _, err := (&ClickHouse{URL: bad.URL}).Samples(context.Background(), "e", "m"); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("want HTTP 500 error, got %v", err)
	}
}

const ringYAML = `# ring config
apiVersion: halos.dev/v1alpha1
kind: Ring
name: ring1-canary
order: 1
profile: base
release: sha256:old # current
---
apiVersion: halos.dev/v1alpha1
kind: Ring
name: ring2
release: sha256:other
`

const expYAML = `apiVersion: halos.dev/v1alpha1
kind: Experiment
name: sonnet-next
type: canary
`

func repo(t *testing.T) Target {
	t.Helper()
	d := t.TempDir()
	for f, c := range map[string]string{"ring.yaml": ringYAML, "exp.yaml": expYAML} {
		if err := os.WriteFile(filepath.Join(d, f), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Target{RepoDir: d, RingFile: "ring.yaml", ExperimentFile: "exp.yaml"}
}

func TestPlanAndApply(t *testing.T) {
	tg := repo(t)
	e := exp()
	ch, err := PlanPromote(tg, e, "ring1-canary", "sha256:new")
	if err != nil {
		t.Fatal(err)
	}
	ring := string(ch.Files["ring.yaml"])
	if !strings.Contains(ring, "release: sha256:new") || !strings.Contains(ring, "sha256:other") || !strings.Contains(ring, "# ring config") || !strings.Contains(ring, "# current") {
		t.Fatalf("ring edit wrong (other ring/comments must survive):\n%s", ring)
	}
	if !strings.Contains(string(ch.Files["exp.yaml"]), "status: concluded") {
		t.Fatalf("status not appended:\n%s", ch.Files["exp.yaml"])
	}
	for _, w := range []string{"--- a/ring.yaml", "-release: sha256:old", "+release: sha256:new", "+status: concluded"} {
		if !strings.Contains(ch.Patch, w) {
			t.Errorf("patch missing %q:\n%s", w, ch.Patch)
		}
	}
	// Planning never touches disk.
	if b, _ := os.ReadFile(filepath.Join(tg.RepoDir, "ring.yaml")); string(b) != ringYAML {
		t.Fatal("PlanPromote modified the working tree")
	}

	rb, err := PlanRollback(tg, e, "ring1-canary", "sha256:good")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRollback(tg.RepoDir, rb); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(tg.RepoDir, "ring.yaml")); !strings.Contains(string(b), "sha256:good") {
		t.Fatalf("rollback not applied:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(tg.RepoDir, "exp.yaml")); !strings.Contains(string(b), "status: paused") {
		t.Fatalf("status not paused:\n%s", b)
	}

	// Rollback without release only pauses.
	rb, err = PlanRollback(tg, e, "", "")
	if err != nil || len(rb.Files) != 1 {
		t.Fatalf("status-only rollback: %v %v", rb, err)
	}
	if _, err := PlanPromote(tg, e, "ring1-canary", ""); err == nil {
		t.Fatal("promote without release must fail")
	}
	if _, err := PlanPromote(tg, e, "nope", "sha256:x"); err == nil {
		t.Fatal("unknown ring must fail")
	}
	if _, err := PlanPromote(Target{RepoDir: tg.RepoDir, RingFile: "missing.yaml", ExperimentFile: "exp.yaml"}, e, "r", "x"); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestOpenPRNeverMerges(t *testing.T) {
	tg := repo(t)
	e := exp()
	ch, err := PlanPromote(tg, e, "ring1-canary", "sha256:new")
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	g := GHOpener{Exec: func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "git" {
			return nil, nil // rev-parse --show-prefix: repo root
		}
		return []byte("https://github.com/o/r/pull/7\n"), nil
	}}
	rep := Report{Verdict: Promote, Reason: "ok", Control: "control", Treatment: "candidate"}
	url, err := OpenPR(context.Background(), g, tg, ch, e, rep, "main")
	if err != nil || url != "https://github.com/o/r/pull/7" {
		t.Fatalf("url %q err %v", url, err)
	}
	all := strings.Join(calls, "\n")
	for _, w := range []string{"git worktree add --quiet -b halos/promote-sonnet-next-", "git add -- exp.yaml ring.yaml", "git push origin halos/promote-sonnet-next-", "git branch -D halos/promote-sonnet-next-", "gh pr create", "--base main"} {
		if !strings.Contains(all, w) {
			t.Errorf("missing call %q in:\n%s", w, all)
		}
	}
	if strings.Contains(all, "pr merge") || strings.Contains(all, "git merge") || strings.Contains(all, "--auto") {
		t.Fatalf("must never merge:\n%s", all)
	}
	if b, _ := os.ReadFile(filepath.Join(tg.RepoDir, "ring.yaml")); strings.Contains(string(b), "sha256:new") {
		t.Fatal("the user's working tree must not be modified")
	}
	// Only promote verdicts may open a promotion PR.
	if _, err := OpenPR(context.Background(), g, tg, ch, e, Report{Verdict: Rollback}, ""); err == nil {
		t.Fatal("non-promote verdict must be refused")
	}
	// A failing step surfaces with context.
	failing := GHOpener{Exec: func(_ context.Context, _, name string, args ...string) ([]byte, error) {
		if name == "git" && args[0] == "push" {
			return nil, os.ErrPermission
		}
		return nil, nil
	}}
	if _, err := OpenPR(context.Background(), failing, tg, ch, e, rep, ""); err == nil || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("want wrapped push error, got %v", err)
	}
}
