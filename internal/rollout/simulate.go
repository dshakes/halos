package rollout

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// Simulation scenarios.
const (
	ScenarioHealthy    = "healthy"    // treatment matches control on every metric
	ScenarioRegression = "regression" // the first guardrail regresses from BreachStep on
)

// SimOptions configures Simulate. Zero values take the defaults noted.
type SimOptions struct {
	Scenario string        // default healthy
	Tick     time.Duration // default 1h
	Horizon  time.Duration // default 120d
	// UnitsPerHour is how many new users the experiment sees per hour at 100%; default 1000.
	UnitsPerHour int
	// BreachStep is the step index a regression starts at (default: the second
	// step with metric gates, else the first).
	BreachStep *int
	// ApproveAfter is how long a simulated human takes to approve; default 4h.
	ApproveAfter time.Duration
	Seed         uint64
	// Recorded, when set, replaces synthetic evidence: one entry per tick (the
	// last repeats). Scorecards still come from the policy dir.
	Recorded []Evidence
}

// SimEvent is one notable moment of a simulation.
type SimEvent struct {
	At       string       `json:"at"` // elapsed since start, e.g. "T+2d4h"
	Elapsed  int64        `json:"elapsedSeconds"`
	Step     string       `json:"step"`
	Action   Action       `json:"action"`
	Reasons  []string     `json:"reasons"`
	Gates    []GateResult `json:"gates"`
	Approved bool         `json:"approved,omitempty"`
}

// SimResult is a whole simulated run.
type SimResult struct {
	Rollout  string     `json:"rollout"`
	Scenario string     `json:"scenario"`
	Outcome  Action     `json:"outcome"` // complete | rollback | pause | hold (horizon reached)
	Duration string     `json:"duration"`
	Events   []SimEvent `json:"events"`
}

const simCap = 20000 // samples per arm per metric

// Simulate runs the real state machine (Evaluate, with guardrails computed by
// promote.EvaluateAt over seeded synthetic samples, or recorded evidence)
// from "not started" until it completes, rolls back, pauses or reaches the
// horizon, assuming every proposed PR merges immediately. Deterministic for
// a given seed. It writes nothing.
func Simulate(ctx context.Context, dir string, org *policy.Org, r *policy.Rollout, o SimOptions) (SimResult, error) {
	o = simDefaults(r, o)
	var exp *policy.Experiment
	var ctl, trt *policy.Variant
	if r.Experiment != "" { // optional when no step has metric gates (validated)
		if exp = findExp(org, r.Experiment); exp == nil {
			return SimResult{}, fmt.Errorf("simulate %s: experiment %q not found", r.Name, r.Experiment)
		}
		var ok bool
		if ctl, trt, ok = exp.Arms(); !ok {
			return SimResult{}, fmt.Errorf("simulate %s: experiment %q needs one control and one treatment", r.Name, exp.Name)
		}
	}
	ro := *r
	ro.Status, ro.Step = policy.RolloutActive, ""
	res := SimResult{Rollout: r.Name, Scenario: o.Scenario, Outcome: Hold, Events: []SimEvent{}}
	start := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC) // fixed: output is reproducible
	st := NewState(r.Name)
	src := promote.SourceCLI
	if r.Axis == policy.AxisTraffic {
		src = promote.SourceGateway
	}
	var samples map[string]map[string][]float64 // this step's full synthetic arms
	lastKey, waitingSince, tick := "", time.Time{}, 0
	for el := time.Duration(0); el <= o.Horizon; el, tick = el+o.Tick, tick+1 {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		now := start.Add(el)
		ev, err := Gather(ctx, dir, org, &ro, st, nil, now)
		if err != nil {
			return res, err
		}
		if ev.Scorecard == nil && st.Step >= 0 && ro.Steps[st.Step].Gates.Scorecard != nil {
			ev.Scorecard, ev.ScorecardErr = simScorecard(ro.Steps[st.Step].Gates.Scorecard), ""
		}
		switch {
		case len(o.Recorded) > 0:
			rec := o.Recorded[min(tick, len(o.Recorded)-1)]
			ev.Report, ev.Approved = rec.Report, rec.Approved
		case exp != nil && st.Step >= 0 && NeedsMetrics(ro.Steps[st.Step]):
			s := ro.Steps[st.Step]
			if samples == nil {
				samples = synth(exp, s, ctl.Name, trt.Name, o, st.Step)
			}
			nc, nt := units(s, now.Sub(st.EnteredAt), o.UnitsPerHour)
			data := map[string]map[string][]float64{}
			for m, arms := range samples {
				data[m] = map[string][]float64{ctl.Name: arms[ctl.Name][:nc], trt.Name: arms[trt.Name][:nt]}
			}
			rep, err := promote.EvaluateAt(ctx, GateExperiment(exp, s), &promote.MemorySource{Start: st.EnteredAt, Data: data, Source: src}, now)
			if err != nil {
				return res, fmt.Errorf("simulate %s: %w", r.Name, err)
			}
			ev.Report = &rep
		}
		if !waitingSince.IsZero() && now.Sub(waitingSince) >= o.ApproveAfter {
			ev.Approved = true
		}
		d := Evaluate(&ro, st, ev, now)
		if d.AwaitingApproval && waitingSince.IsZero() {
			waitingSince = now
		}
		key := fmt.Sprint(st.Step, d.Action, pendingGates(d))
		if key != lastKey || d.Action != Hold {
			name := "-"
			if st.Step >= 0 {
				name = ro.Steps[st.Step].Name
			}
			res.Events = append(res.Events, SimEvent{At: "T+" + Days(el), Elapsed: int64(el / time.Second), Step: name,
				Action: d.Action, Reasons: d.Reasons, Gates: d.Gates, Approved: ev.Approved && d.Action != Hold})
			lastKey = key
		}
		res.Duration = Days(el)
		switch d.Action {
		case Advance:
			ro.Step = ro.Steps[d.Next].Name // the PR merges at once
			st.Sync(&ro, now)
			samples, waitingSince = nil, time.Time{}
		case Hold:
		default:
			res.Outcome = d.Action
			return res, nil
		}
	}
	return res, nil
}

func simDefaults(r *policy.Rollout, o SimOptions) SimOptions {
	if o.Scenario == "" {
		o.Scenario = ScenarioHealthy
	}
	if o.Tick <= 0 {
		o.Tick = time.Hour
	}
	if o.Horizon <= 0 {
		o.Horizon = 120 * 24 * time.Hour
	}
	if o.UnitsPerHour <= 0 {
		o.UnitsPerHour = 1000
	}
	if o.ApproveAfter <= 0 {
		o.ApproveAfter = 4 * time.Hour
	}
	if o.BreachStep == nil {
		var gated []int
		for i, s := range r.Steps {
			if len(s.Gates.Guardrails) > 0 {
				gated = append(gated, i)
			}
		}
		b := 0
		if len(gated) > 0 {
			b = gated[min(1, len(gated)-1)]
		}
		o.BreachStep = &b
	}
	return o
}

func pendingGates(d Decision) string {
	var g []string
	for _, x := range d.Gates {
		if x.Status != GatePass {
			g = append(g, x.Gate)
		}
	}
	return strings.Join(g, ",")
}

// units is how many control/treatment users a step has seen after in.
func units(s policy.RolloutStep, in time.Duration, perHour int) (nc, nt int) {
	total := in.Hours() * float64(perHour)
	f := s.EffectivePercent() / 100
	switch s.Strategy {
	case policy.StrategyHoldout:
		f = 1 - f
	case policy.StrategyDarkLaunch: // every mirrored request yields both arms
		n := min(int(total*f), simCap)
		return n, n
	}
	return min(int(total*(1-f)), simCap), min(int(total*f), simCap)
}

// synth draws each arm's per-unit values for the primary and the step's
// guardrails: mean 1, sd 0.25. Healthy treatment is 0.5% better; in the
// regression scenario the first guardrail is 2x its limit worse from
// BreachStep on.
func synth(exp *policy.Experiment, s policy.RolloutStep, ctl, trt string, o SimOptions, step int) map[string]map[string][]float64 {
	goals := append([]policy.MetricGoal{exp.Metrics.Primary}, s.Gates.Guardrails...)
	out := map[string]map[string][]float64{}
	for i, g := range goals {
		if out[g.Metric] != nil {
			continue
		}
		worse := -0.005 // a hair better
		if o.Scenario == ScenarioRegression && step >= *o.BreachStep && len(s.Gates.Guardrails) > 0 && g.Metric == s.Gates.Guardrails[0].Metric {
			worse = max(2*g.MaxRegression, 0.1)
		}
		shift := worse
		if g.Direction == "increase" {
			shift = -worse
		}
		rng := rand.New(rand.NewPCG(o.Seed, uint64(step*64+i))) //nolint:gosec // simulation, not crypto
		draw := func(mean float64) []float64 {
			x := make([]float64, simCap)
			for j := range x {
				x[j] = mean + 0.25*rng.NormFloat64()
			}
			return x
		}
		out[g.Metric] = map[string][]float64{ctl: draw(1), trt: draw(1 + shift)}
	}
	return out
}

// simScorecard stands in for a scorecard file that does not exist yet: the
// variant clears the gate's bars.
func simScorecard(g *policy.ScorecardGate) *eval.Scorecard {
	p := max(g.MinPass1+0.05, 0.75)
	return &eval.Scorecard{Suite: "simulated", Control: "control",
		Variants:    []eval.VariantScore{{Name: g.Variant, Pass1: p}, {Name: "control", Pass1: p - 0.01}},
		Comparisons: []eval.Comparison{{Variant: g.Variant, Control: "control", Delta: 0.01, CILo: -0.02, CIHi: 0.04, Verdict: eval.VerdictNoDiff}}}
}
