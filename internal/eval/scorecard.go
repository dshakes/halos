package eval

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/stats"
)

const (
	bootstrapIters = 2000
	bootstrapAlpha = 0.05
)

// VariantScore aggregates one variant's trials.
type VariantScore struct {
	Name        string  `json:"name"`
	Trials      int     `json:"trials"`
	Pass1       float64 `json:"pass1"`
	Pass1CILo   float64 `json:"pass1CILo"`
	Pass1CIHi   float64 `json:"pass1CIHi"`
	CostPerTask float64 `json:"costPerTaskUSD"` // mean cost per trial
	WallP50Ms   int64   `json:"wallP50Ms"`
	WallP95Ms   int64   `json:"wallP95Ms"`
	Tokens      int64   `json:"tokens"`
	ToolErrors  int     `json:"toolErrors"`
	Errors      int     `json:"errors"` // trials with a recorded Error

	Harness  string `json:"harness,omitempty"`
	Version  string `json:"version,omitempty"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
	// PassAtK / PassHatK are the per-task unbiased pass@k (any of k trials
	// passes) and pass^k (all k pass), averaged over tasks.
	K           int      `json:"k,omitempty"`
	PassAtK     float64  `json:"passAtK"`
	PassHatK    float64  `json:"passHatK"`
	ToolCalls   int      `json:"toolCalls"`
	GradeErrors int      `json:"gradeErrors"`
	JudgeScore  *float64 `json:"judgeScore,omitempty"` // mean judge score over judged trials
	// Unavailable counts trials this host could not measure (Trial.Unavailable,
	// e.g. codex without Landlock). They are excluded from every statistic; a
	// variant with no measured trials shows UnavailableReason, not 0%.
	Unavailable       int    `json:"unavailable,omitempty"`
	UnavailableReason string `json:"unavailableReason,omitempty"`
}

// measured is the number of trials that actually ran.
func (v VariantScore) measured() int { return v.Trials - v.Unavailable }

// Verdicts for a paired comparison against control.
const (
	VerdictBetter = "better"
	VerdictWorse  = "worse"
	VerdictNoDiff = "no_significant_difference"
)

// Comparison is a paired (by task) pass-rate comparison vs the control.
type Comparison struct {
	Variant string  `json:"variant"`
	Control string  `json:"control"`
	Tasks   int     `json:"tasks"`
	Delta   float64 `json:"delta"` // mean per-task pass rate: variant - control
	CILo    float64 `json:"ciLo"`
	CIHi    float64 `json:"ciHi"`
	Verdict string  `json:"verdict"`

	// Deltas are paired bootstrap CIs per metric over non-flaky tasks
	// (MetricPass, MetricCost, ...); Gate is the ship/hold/block verdict.
	Deltas map[string]MetricDelta `json:"deltas,omitempty"`
	Gate   *Gate                  `json:"gate,omitempty"`
}

// Scorecard is the full result of a suite run.
type Scorecard struct {
	Suite       string         `json:"suite"`
	Control     string         `json:"control"`
	Variants    []VariantScore `json:"variants"`
	Comparisons []Comparison   `json:"comparisons"`
	Trials      []Trial        `json:"trials"`

	Seed uint64 `json:"seed"`
	K    int    `json:"k,omitempty"`
	// Gate is the worst comparison gate; nil with a single variant.
	Gate       *Gate       `json:"gate,omitempty"`
	Thresholds *Thresholds `json:"thresholds,omitempty"`
	Judge      *JudgeInfo  `json:"judge,omitempty"`
}

// JudgeInfo pins what graded the run: the judge model and rubric id@version.
type JudgeInfo struct {
	Model   string   `json:"model"`
	Wire    string   `json:"wire,omitempty"`
	Rubrics []string `json:"rubrics"`
}

func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	return sorted[max(i, 0)]
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// BuildScorecard aggregates trials. The seed makes bootstrap CIs reproducible.
func BuildScorecard(s *Suite, trials []Trial, seed uint64) (*Scorecard, error) {
	sc := &Scorecard{Suite: s.Name, Control: s.Control, Trials: trials, Seed: seed, K: s.K}
	if s.K > 0 {
		th := s.Gate
		sc.Thresholds = &th
	}
	if refs := rubricRefs(trials); len(refs) > 0 {
		sc.Judge = &JudgeInfo{Rubrics: refs}
		if s.Judge != nil {
			sc.Judge.Model, sc.Judge.Wire = s.Judge.Model, s.Judge.Wire
		}
	}
	arms := map[string]map[string]*armTask{} // variant -> task
	judged := map[string][]float64{}
	passes := map[string][]float64{}
	perTask := map[string]map[string][]float64{} // variant -> task -> passes
	for _, v := range s.Variants {
		perTask[v.Name] = map[string][]float64{}
	}
	scores := map[string]*VariantScore{}
	walls := map[string][]int64{}
	for _, v := range s.Variants {
		scores[v.Name] = &VariantScore{Name: v.Name, Harness: v.Harness, Version: v.Version, Model: v.Model, Provider: v.Provider}
		arms[v.Name] = map[string]*armTask{}
	}
	for _, t := range trials {
		vs := scores[t.Variant]
		if vs == nil {
			return nil, fmt.Errorf("scorecard: trial for unknown variant %q", t.Variant)
		}
		vs.Trials++
		vs.CostPerTask += t.CostUSD
		vs.Tokens += t.Tokens
		vs.ToolErrors += t.ToolErrors
		if t.Error != "" {
			vs.Errors++
		}
		if t.Unavailable != "" {
			vs.Unavailable++
			vs.UnavailableReason = t.Unavailable
			continue
		}
		vs.ToolCalls += t.ToolCalls
		if t.GraderError != "" {
			vs.GradeErrors++
		}
		for _, g := range t.Grades {
			if g.Score != nil {
				judged[t.Variant] = append(judged[t.Variant], *g.Score)
			}
		}
		a := arms[t.Variant][t.Task]
		if a == nil {
			a = &armTask{}
			arms[t.Variant][t.Task] = a
		}
		a.add(t)
		walls[t.Variant] = append(walls[t.Variant], t.WallMs)
		passes[t.Variant] = append(passes[t.Variant], b2f(t.Pass))
		perTask[t.Variant][t.Task] = append(perTask[t.Variant][t.Task], b2f(t.Pass))
	}
	for _, v := range s.Variants {
		vs := scores[v.Name]
		if vs.Trials == 0 {
			return nil, fmt.Errorf("scorecard: no trials for variant %q", v.Name)
		}
		if vs.measured() == 0 { // nothing ran: report why, never a 0% score
			sc.Variants = append(sc.Variants, *vs)
			continue
		}
		b, err := stats.BootstrapMean(passes[v.Name], bootstrapIters, seed, bootstrapAlpha)
		if err != nil {
			return nil, fmt.Errorf("scorecard: variant %s: %w", v.Name, err)
		}
		vs.Pass1, vs.Pass1CILo, vs.Pass1CIHi = b.Mean, b.CILo, b.CIHi
		vs.CostPerTask /= float64(vs.measured())
		w := walls[v.Name]
		sort.Slice(w, func(i, j int) bool { return w[i] < w[j] })
		vs.WallP50Ms, vs.WallP95Ms = percentile(w, 0.50), percentile(w, 0.95)
		if err := passK(vs, arms[v.Name], s.K); err != nil {
			return nil, fmt.Errorf("scorecard: variant %s: %w", v.Name, err)
		}
		if js := judged[v.Name]; len(js) > 0 {
			m := 0.0
			for _, x := range js {
				m += x / float64(len(js))
			}
			vs.JudgeScore = &m
		}
		sc.Variants = append(sc.Variants, *vs)
	}
	for _, v := range s.Variants {
		if v.Name == s.Control {
			continue
		}
		var unmeasured []string
		for _, n := range []string{s.Control, v.Name} {
			if vs := scores[n]; vs.Unavailable > 0 {
				unmeasured = append(unmeasured, fmt.Sprintf("%s: %d/%d trials unmeasurable (%s); fix the host, not the candidate", n, vs.Unavailable, vs.Trials, vs.UnavailableReason))
			}
		}
		c := Comparison{Variant: v.Name, Control: s.Control, Verdict: VerdictNoDiff}
		g := Gate{Verdict: GateHold}
		if scores[s.Control].measured() > 0 && scores[v.Name].measured() > 0 {
			var err error
			if c, err = compare(perTask[s.Control], perTask[v.Name], seed); err != nil {
				return nil, fmt.Errorf("scorecard: %s vs %s: %w", v.Name, s.Control, err)
			}
			c.Variant, c.Control = v.Name, s.Control
			if s.Gate.MaxPassDrop != nil {
				if g, c.Deltas, err = gate(arms[s.Control], arms[v.Name], s.Gate, seed); err != nil {
					return nil, fmt.Errorf("scorecard: %s vs %s: %w", v.Name, s.Control, err)
				}
			}
		}
		if len(unmeasured) > 0 { // like grader errors: neither ship nor block on data the host could not produce
			g.Verdict, g.Reasons = GateHold, append(unmeasured, g.Reasons...)
		}
		if s.Gate.MaxPassDrop != nil { // validated suite
			c.Gate = &g
			if sc.Gate == nil {
				sc.Gate = &Gate{Verdict: GateShip}
			}
			sc.Gate.Verdict = worse(sc.Gate.Verdict, g.Verdict)
			for _, r := range g.Reasons {
				sc.Gate.Reasons = append(sc.Gate.Reasons, v.Name+": "+r)
			}
		}
		sc.Comparisons = append(sc.Comparisons, c)
	}
	return sc, nil
}

// passK fills pass@k and pass^k, averaged over tasks. A task with fewer than
// k trials uses k = its trial count.
func passK(vs *VariantScore, tasks map[string]*armTask, k int) error {
	if k < 1 || len(tasks) == 0 {
		return nil
	}
	vs.K = k
	names := make([]string, 0, len(tasks))
	for t := range tasks {
		names = append(names, t)
	}
	sort.Strings(names) // fixed summation order: byte-identical JSON across runs
	for _, t := range names {
		a := tasks[t]
		kk := min(k, a.n)
		at, err := stats.PassAtK(a.n, a.passes, kk)
		if err != nil {
			return err
		}
		hat, err := stats.PassHatK(a.n, a.passes, kk)
		if err != nil {
			return err
		}
		vs.PassAtK += at / float64(len(tasks))
		vs.PassHatK += hat / float64(len(tasks))
	}
	return nil
}

func compare(control, variant map[string][]float64, seed uint64) (Comparison, error) {
	var tasks []string
	for t := range control {
		if _, ok := variant[t]; ok {
			tasks = append(tasks, t)
		}
	}
	sort.Strings(tasks)
	avg := func(x []float64) float64 {
		s := 0.0
		for _, v := range x {
			s += v
		}
		return s / float64(len(x))
	}
	var c, v []float64
	for _, t := range tasks {
		c, v = append(c, avg(control[t])), append(v, avg(variant[t]))
	}
	b, err := stats.PairedBootstrap(c, v, bootstrapIters, seed, bootstrapAlpha)
	if err != nil {
		return Comparison{}, err
	}
	out := Comparison{Tasks: len(tasks), Delta: b.Mean, CILo: b.CILo, CIHi: b.CIHi, Verdict: VerdictNoDiff}
	switch {
	case b.CILo > 0:
		out.Verdict = VerdictBetter
	case b.CIHi < 0:
		out.Verdict = VerdictWorse
	}
	return out, nil
}

// JSON renders the scorecard as indented JSON.
func (sc *Scorecard) JSON() ([]byte, error) { return json.MarshalIndent(sc, "", "  ") }

// Markdown renders a human-readable scorecard, suitable as a PR comment.
func (sc *Scorecard) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Eval scorecard: %s\n\nControl: `%s`\n", sc.Suite, sc.Control)
	if sc.Gate != nil {
		fmt.Fprintf(&b, "\n**Gate: %s**\n", strings.ToUpper(sc.Gate.Verdict))
	}
	if sc.Judge != nil {
		fmt.Fprintf(&b, "\nJudge: `%s`, rubrics: %s\n", sc.Judge.Model, "`"+strings.Join(sc.Judge.Rubrics, "`, `")+"`")
	}
	k := max(sc.K, 1)
	fmt.Fprintf(&b, "\n| Variant | Trials | pass@1 (95%% CI) | pass@%d | pass^%d | Cost/task | Wall p50 | Wall p95 | Tool calls | Tool errors | Errors |\n", k, k)
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, v := range sc.Variants {
		if v.measured() == 0 {
			fmt.Fprintf(&b, "| %s | %d | error: %s | | | | | | | | %d |\n", v.Name, v.Trials, v.UnavailableReason, v.Errors)
			continue
		}
		fmt.Fprintf(&b, "| %s | %d | %.1f%% (%.1f-%.1f) | %.1f%% | %.1f%% | $%.4f | %.1fs | %.1fs | %d | %d | %d |\n",
			v.Name, v.Trials, 100*v.Pass1, 100*v.Pass1CILo, 100*v.Pass1CIHi, 100*v.PassAtK, 100*v.PassHatK,
			v.CostPerTask, float64(v.WallP50Ms)/1000, float64(v.WallP95Ms)/1000, v.ToolCalls, v.ToolErrors, v.Errors+v.GradeErrors)
	}
	if len(sc.Comparisons) > 0 {
		b.WriteString("\n## Paired comparison vs control\n\n| Variant | Tasks | Delta pass rate (95% CI) | Verdict |\n|---|---|---|---|\n")
		measured := map[string]int{}
		for _, v := range sc.Variants {
			measured[v.Name] = v.measured()
		}
		for _, c := range sc.Comparisons {
			if measured[c.Variant] == 0 || measured[c.Control] == 0 {
				fmt.Fprintf(&b, "| %s | %d | n/a: unmeasurable on this host | %s |\n", c.Variant, c.Tasks, GateHold)
				continue
			}
			fmt.Fprintf(&b, "| %s | %d | %+.1f pp (%+.1f to %+.1f) | %s |\n",
				c.Variant, c.Tasks, 100*c.Delta, 100*c.CILo, 100*c.CIHi, c.Verdict)
		}
	}
	for _, c := range sc.Comparisons {
		if c.Gate == nil {
			continue
		}
		fmt.Fprintf(&b, "\n## %s vs %s: %s\n\n", c.Variant, c.Control, strings.ToUpper(c.Gate.Verdict))
		for _, r := range c.Gate.Reasons {
			fmt.Fprintf(&b, "- %s\n", r)
		}
		if len(c.Deltas) > 0 {
			b.WriteString("\n| Metric | Baseline | Delta (95% CI) |\n|---|---|---|\n")
			for _, m := range []string{MetricPass, MetricCost, MetricTokens, MetricWall, MetricToolCalls} {
				d := c.Deltas[m]
				if m == MetricPass {
					fmt.Fprintf(&b, "| %s | %.1f%% | %+.1f pp (%+.1f to %+.1f) |\n", m, 100*d.Baseline, 100*d.Mean, 100*d.CILo, 100*d.CIHi)
					continue
				}
				f := map[string]string{MetricCost: "%.4f", MetricToolCalls: "%.1f"}[m]
				if f == "" {
					f = "%.0f" // tokens, wall_ms
				}
				sf := strings.Replace(f, "%", "%+", 1)
				fmt.Fprintf(&b, "| %s | "+f+" | "+sf+" ("+sf+" to "+sf+") |\n", m, d.Baseline, d.Mean, d.CILo, d.CIHi)
			}
		}
		if len(c.Gate.Regressed) > 0 {
			b.WriteString("\nRegressed tasks:\n\n")
			for _, t := range c.Gate.Regressed {
				fmt.Fprintf(&b, "- `%s`: %.0f%% -> %.0f%%\n", t.Task, 100*t.Baseline, 100*t.Candidate)
			}
		}
		if len(c.Gate.Flaky) > 0 {
			b.WriteString("\nFlaky tasks (excluded from the gate):\n\n")
			for _, t := range c.Gate.Flaky {
				fmt.Fprintf(&b, "- `%s`: %s\n", t.Task, t.Reason)
			}
		}
	}
	return b.String()
}

// Table renders a compact fixed-width terminal table (one row per variant).
func (sc *Scorecard) Table() string {
	verdict := map[string]string{sc.Control: "baseline"}
	for _, c := range sc.Comparisons {
		verdict[c.Variant] = c.Verdict
		if c.Gate != nil {
			verdict[c.Variant] = c.Gate.Verdict
		}
	}
	w := len("VARIANT")
	for _, v := range sc.Variants {
		w = max(w, len(v.Name))
	}
	k := max(sc.K, 1)
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s  %6s  %6s  %6s  %8s  %7s  %5s  %s\n", w, "VARIANT", "PASS@1",
		fmt.Sprintf("PASS@%d", k), fmt.Sprintf("PASS^%d", k), "$/TASK", "P50", "TOOLS", "VERDICT")
	for _, v := range sc.Variants {
		if v.measured() == 0 {
			fmt.Fprintf(&b, "%-*s  error: %s  %s\n", w, v.Name, v.UnavailableReason, verdict[v.Name])
			continue
		}
		tools := float64(v.ToolCalls) / float64(v.measured())
		fmt.Fprintf(&b, "%-*s  %5.0f%%  %5.0f%%  %5.0f%%  %8s  %6.1fs  %5.1f  %s\n", w, v.Name,
			100*v.Pass1, 100*v.PassAtK, 100*v.PassHatK, fmt.Sprintf("$%.3f", v.CostPerTask),
			float64(v.WallP50Ms)/1000, tools, verdict[v.Name])
	}
	if sc.Gate != nil {
		fmt.Fprintf(&b, "gate: %s\n", strings.ToUpper(sc.Gate.Verdict))
	}
	return b.String()
}
