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
}

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
}

// Scorecard is the full result of a suite run.
type Scorecard struct {
	Suite       string         `json:"suite"`
	Control     string         `json:"control"`
	Variants    []VariantScore `json:"variants"`
	Comparisons []Comparison   `json:"comparisons"`
	Trials      []Trial        `json:"trials"`
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
	sc := &Scorecard{Suite: s.Name, Control: s.Control, Trials: trials}
	passes := map[string][]float64{}
	perTask := map[string]map[string][]float64{} // variant -> task -> passes
	for _, v := range s.Variants {
		perTask[v.Name] = map[string][]float64{}
	}
	scores := map[string]*VariantScore{}
	walls := map[string][]int64{}
	for _, v := range s.Variants {
		scores[v.Name] = &VariantScore{Name: v.Name}
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
		walls[t.Variant] = append(walls[t.Variant], t.WallMs)
		passes[t.Variant] = append(passes[t.Variant], b2f(t.Pass))
		perTask[t.Variant][t.Task] = append(perTask[t.Variant][t.Task], b2f(t.Pass))
	}
	for _, v := range s.Variants {
		vs := scores[v.Name]
		if vs.Trials == 0 {
			return nil, fmt.Errorf("scorecard: no trials for variant %q", v.Name)
		}
		b, err := stats.BootstrapMean(passes[v.Name], bootstrapIters, seed, bootstrapAlpha)
		if err != nil {
			return nil, fmt.Errorf("scorecard: variant %s: %w", v.Name, err)
		}
		vs.Pass1, vs.Pass1CILo, vs.Pass1CIHi = b.Mean, b.CILo, b.CIHi
		vs.CostPerTask /= float64(vs.Trials)
		w := walls[v.Name]
		sort.Slice(w, func(i, j int) bool { return w[i] < w[j] })
		vs.WallP50Ms, vs.WallP95Ms = percentile(w, 0.50), percentile(w, 0.95)
		sc.Variants = append(sc.Variants, *vs)
	}
	for _, v := range s.Variants {
		if v.Name == s.Control {
			continue
		}
		c, err := compare(perTask[s.Control], perTask[v.Name], seed)
		if err != nil {
			return nil, fmt.Errorf("scorecard: %s vs %s: %w", v.Name, s.Control, err)
		}
		c.Variant, c.Control = v.Name, s.Control
		sc.Comparisons = append(sc.Comparisons, c)
	}
	return sc, nil
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

// Markdown renders a human-readable scorecard.
func (sc *Scorecard) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Eval scorecard: %s\n\nControl: `%s`\n\n", sc.Suite, sc.Control)
	b.WriteString("| Variant | Trials | pass@1 (95% CI) | Cost/task | Wall p50 | Wall p95 | Tool errors | Errors |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, v := range sc.Variants {
		fmt.Fprintf(&b, "| %s | %d | %.1f%% (%.1f-%.1f) | $%.4f | %.1fs | %.1fs | %d | %d |\n",
			v.Name, v.Trials, 100*v.Pass1, 100*v.Pass1CILo, 100*v.Pass1CIHi,
			v.CostPerTask, float64(v.WallP50Ms)/1000, float64(v.WallP95Ms)/1000, v.ToolErrors, v.Errors)
	}
	if len(sc.Comparisons) > 0 {
		b.WriteString("\n## Paired comparison vs control\n\n| Variant | Tasks | Delta pass rate (95% CI) | Verdict |\n|---|---|---|---|\n")
		for _, c := range sc.Comparisons {
			fmt.Fprintf(&b, "| %s | %d | %+.1f pp (%+.1f to %+.1f) | %s |\n",
				c.Variant, c.Tasks, 100*c.Delta, 100*c.CILo, 100*c.CIHi, c.Verdict)
		}
	}
	return b.String()
}
