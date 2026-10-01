package eval

import (
	"errors"
	"fmt"
	"sort"

	"github.com/dshakes/halos/internal/stats"
)

// Regression verdicts of the gate, worst last.
const (
	GateShip  = "ship"  // candidate is non-inferior on every gated metric
	GateHold  = "hold"  // inconclusive: rerun with more trials or tasks
	GateBlock = "block" // candidate is confidently worse
)

var gateRank = map[string]int{GateShip: 0, GateHold: 1, GateBlock: 2}

func worse(a, b string) string {
	if gateRank[b] > gateRank[a] {
		return b
	}
	return a
}

// Thresholds is a suite's `gate:` block. Pass-rate margins are absolute
// (0.05 = 5 percentage points); cost/tokens/wall/tool-call limits are
// relative increases over the baseline mean (0.2 = +20%) and are only gated
// when set.
type Thresholds struct {
	// MaxPassDrop is the non-inferiority margin on the paired per-task pass
	// rate: ship needs the CI lower bound >= -MaxPassDrop. Default 0.05.
	MaxPassDrop          *float64 `yaml:"max_pass_drop,omitempty" json:"maxPassDrop,omitempty"`
	MaxCostIncrease      *float64 `yaml:"max_cost_increase,omitempty" json:"maxCostIncrease,omitempty"`
	MaxTokensIncrease    *float64 `yaml:"max_tokens_increase,omitempty" json:"maxTokensIncrease,omitempty"`
	MaxWallIncrease      *float64 `yaml:"max_wall_increase,omitempty" json:"maxWallIncrease,omitempty"`
	MaxToolCallsIncrease *float64 `yaml:"max_tool_calls_increase,omitempty" json:"maxToolCallsIncrease,omitempty"`
	// TaskRegression is the per-task pass-rate drop that marks a task as
	// regressed (default 0.5); more than MaxRegressedTasks (default 0) blocks.
	TaskRegression    float64 `yaml:"task_regression,omitempty" json:"taskRegression"`
	MaxRegressedTasks int     `yaml:"max_regressed_tasks,omitempty" json:"maxRegressedTasks"`
	// MinTasks is the fewest non-flaky tasks a verdict other than hold needs
	// (default 1).
	MinTasks int `yaml:"min_tasks,omitempty" json:"minTasks"`
}

func (g *Thresholds) validate() error {
	if g.MaxPassDrop == nil {
		d := 0.05
		g.MaxPassDrop = &d
	}
	if g.TaskRegression == 0 {
		g.TaskRegression = 0.5
	}
	if g.MinTasks == 0 {
		g.MinTasks = 1
	}
	for _, p := range []*float64{g.MaxPassDrop, g.MaxCostIncrease, g.MaxTokensIncrease, g.MaxWallIncrease, g.MaxToolCallsIncrease} {
		if p != nil && *p < 0 {
			return errors.New("thresholds must be >= 0")
		}
	}
	if g.TaskRegression < 0 || g.TaskRegression > 1 || g.MaxRegressedTasks < 0 || g.MinTasks < 0 {
		return errors.New("task_regression must be in [0,1]; max_regressed_tasks and min_tasks >= 0")
	}
	return nil
}

// MetricDelta is a paired (by task) bootstrap estimate of candidate -
// baseline for one metric; Baseline is the baseline's mean per-task value.
type MetricDelta struct {
	Mean     float64 `json:"mean"`
	CILo     float64 `json:"ciLo"`
	CIHi     float64 `json:"ciHi"`
	Baseline float64 `json:"baseline"`
}

// Metric keys of Comparison.Deltas.
const (
	MetricPass      = "pass_rate"
	MetricCost      = "cost_usd"
	MetricTokens    = "tokens"
	MetricWall      = "wall_ms"
	MetricToolCalls = "tool_calls"
)

// TaskDiff is one task's per-arm pass rates.
type TaskDiff struct {
	Task      string  `json:"task"`
	Baseline  float64 `json:"baseline"`  // pass rate over trials
	Candidate float64 `json:"candidate"` // pass rate over trials
	Status    string  `json:"status"`    // regressed | improved | same | flaky
	Reason    string  `json:"reason,omitempty"`
}

// Gate is the regression verdict of one comparison (or, on the scorecard,
// the worst over all comparisons).
type Gate struct {
	Verdict   string     `json:"verdict"` // ship | hold | block
	Reasons   []string   `json:"reasons"`
	Flaky     []TaskDiff `json:"flaky,omitempty"`
	Regressed []TaskDiff `json:"regressed,omitempty"`
	Tasks     []TaskDiff `json:"tasks,omitempty"`
}

// armTask accumulates one variant's trials on one task.
type armTask struct {
	n, passes, graderErrs         int
	cost, tokens, wall, toolCalls float64
}

func (a *armTask) add(t Trial) {
	a.n++
	if t.Pass {
		a.passes++
	}
	if t.GraderError != "" {
		a.graderErrs++
	}
	a.cost += t.CostUSD
	a.tokens += float64(t.Tokens)
	a.wall += float64(t.WallMs)
	a.toolCalls += float64(t.ToolCalls)
}

func (a *armTask) metric(m string) float64 {
	switch m {
	case MetricPass:
		return float64(a.passes) / float64(a.n)
	case MetricCost:
		return a.cost / float64(a.n)
	case MetricTokens:
		return a.tokens / float64(a.n)
	case MetricWall:
		return a.wall / float64(a.n)
	}
	return a.toolCalls / float64(a.n)
}

// gate compares candidate against baseline over the tasks both ran. Flaky
// tasks (baseline outcome varies across its trials) are reported and left out
// of every gated statistic, since a task that flips on the unchanged baseline
// cannot attribute a flip on the candidate.
func gate(base, cand map[string]*armTask, th Thresholds, seed uint64) (Gate, map[string]MetricDelta, error) {
	g := Gate{Verdict: GateShip}
	var tasks []string
	for t := range base {
		if cand[t] != nil {
			tasks = append(tasks, t)
		}
	}
	sort.Strings(tasks)
	var gated []string
	graderErrs := 0
	for _, t := range tasks {
		b, c := base[t], cand[t]
		d := TaskDiff{Task: t, Baseline: b.metric(MetricPass), Candidate: c.metric(MetricPass), Status: "same"}
		graderErrs += b.graderErrs + c.graderErrs
		switch {
		case b.n >= 2 && b.passes > 0 && b.passes < b.n:
			d.Status, d.Reason = "flaky", fmt.Sprintf("baseline passed %d/%d trials", b.passes, b.n)
			g.Flaky = append(g.Flaky, d)
		case d.Baseline-d.Candidate >= th.TaskRegression:
			d.Status = "regressed"
			g.Regressed = append(g.Regressed, d)
		case d.Candidate > d.Baseline:
			d.Status = "improved"
		}
		if d.Status != "flaky" {
			gated = append(gated, t)
		}
		g.Tasks = append(g.Tasks, d)
	}
	deltas := map[string]MetricDelta{}
	if len(gated) < th.MinTasks || len(gated) == 0 {
		g.Verdict = GateHold
		g.Reasons = append(g.Reasons, fmt.Sprintf("only %d non-flaky tasks (%d flaky); need %d", len(gated), len(g.Flaky), max(th.MinTasks, 1)))
		return g, deltas, nil
	}
	for _, m := range []string{MetricPass, MetricCost, MetricTokens, MetricWall, MetricToolCalls} {
		bs, cs := make([]float64, len(gated)), make([]float64, len(gated))
		for i, t := range gated {
			bs[i], cs[i] = base[t].metric(m), cand[t].metric(m)
		}
		r, err := stats.PairedBootstrap(bs, cs, bootstrapIters, seed, bootstrapAlpha)
		if err != nil {
			return g, nil, fmt.Errorf("gate %s: %w", m, err)
		}
		bm := 0.0
		for _, x := range bs {
			bm += x / float64(len(bs))
		}
		deltas[m] = MetricDelta{Mean: r.Mean, CILo: r.CILo, CIHi: r.CIHi, Baseline: bm}
	}

	p := deltas[MetricPass]
	margin := *th.MaxPassDrop
	switch {
	case p.CILo >= -margin:
	case p.CIHi < 0:
		g.Verdict = GateBlock
		g.Reasons = append(g.Reasons, fmt.Sprintf("pass rate significantly worse: %+.1f pp (95%% CI %+.1f to %+.1f)", 100*p.Mean, 100*p.CILo, 100*p.CIHi))
	default:
		g.Verdict = GateHold
		g.Reasons = append(g.Reasons, fmt.Sprintf("pass rate CI lower bound %+.1f pp is below the -%.1f pp margin; inconclusive", 100*p.CILo, 100*margin))
	}
	if len(g.Regressed) > th.MaxRegressedTasks {
		g.Verdict = worse(g.Verdict, GateBlock)
		g.Reasons = append(g.Reasons, fmt.Sprintf("%d tasks regressed (max %d)", len(g.Regressed), th.MaxRegressedTasks))
	}
	for _, lim := range []struct {
		m   string
		max *float64
	}{{MetricCost, th.MaxCostIncrease}, {MetricTokens, th.MaxTokensIncrease}, {MetricWall, th.MaxWallIncrease}, {MetricToolCalls, th.MaxToolCallsIncrease}} {
		if lim.max == nil {
			continue
		}
		d := deltas[lim.m]
		if d.Baseline <= 0 {
			g.Reasons = append(g.Reasons, fmt.Sprintf("%s not gated: baseline mean is 0 (harness does not report it)", lim.m))
			continue
		}
		lo, hi := d.CILo/d.Baseline, d.CIHi/d.Baseline
		switch {
		case hi <= *lim.max:
		case lo > *lim.max:
			g.Verdict = worse(g.Verdict, GateBlock)
			g.Reasons = append(g.Reasons, fmt.Sprintf("%s up %+.0f%% (CI %+.0f%% to %+.0f%%), limit +%.0f%%", lim.m, 100*d.Mean/d.Baseline, 100*lo, 100*hi, 100**lim.max))
		default:
			g.Verdict = worse(g.Verdict, GateHold)
			g.Reasons = append(g.Reasons, fmt.Sprintf("%s CI upper bound %+.0f%% exceeds the +%.0f%% limit; inconclusive", lim.m, 100*hi, 100**lim.max))
		}
	}
	if graderErrs > 0 { // contaminated data proves nothing either way: neither ship nor block
		g.Verdict = GateHold
		g.Reasons = append(g.Reasons, fmt.Sprintf("%d trials had grader errors (counted as failures); rerun before trusting the verdict", graderErrs))
	}
	if g.Verdict == GateShip {
		g.Reasons = append(g.Reasons, fmt.Sprintf("non-inferior on %d tasks: pass rate %+.1f pp (95%% CI %+.1f to %+.1f)", len(gated), 100*p.Mean, 100*p.CILo, 100*p.CIHi))
	}
	return g, deltas, nil
}
