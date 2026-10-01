// Package rollout drives a policy.Rollout through its steps.
//
// Evaluate is a pure, deterministic state machine: given the rollout, its
// persisted State, the Evidence gathered for the live step and the time, it
// decides advance | hold | rollback | pause | complete. It never acts. The
// controller acts on decisions asymmetrically, like internal/promote:
// rollback and pause happen automatically; advance and complete only ever
// open a PR (Plan) that a human merges. Nothing here merges.
package rollout

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/stats"
)

// Action is what should happen to a rollout now.
type Action string

const (
	Advance  Action = "advance"  // propose the next step (PR)
	Hold     Action = "hold"     // stay; gates pending
	Rollback Action = "rollback" // a gate breached and onFailure is rollback
	Pause    Action = "pause"    // a gate breached and onFailure is pause
	Complete Action = "complete" // last step passed: propose GA (PR)
)

// Gate statuses.
const (
	GatePass    = "pass"
	GateFail    = "fail"
	GatePending = "pending"
)

// GateResult is one gate's outcome, with value vs threshold for humans.
type GateResult struct {
	Gate      string `json:"gate"` // bake | samples | guardrail:<metric> | scorecard | approval
	Status    string `json:"status"`
	Value     string `json:"value,omitempty"`
	Threshold string `json:"threshold,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Decision is Evaluate's output.
type Decision struct {
	Action  Action       `json:"action"`
	Step    int          `json:"step"` // live step index, -1 = not started
	Next    int          `json:"next"` // step an advance proposes, else -1
	Reasons []string     `json:"reasons"`
	Gates   []GateResult `json:"gates"`
	// AwaitingApproval: everything but the approval gate passed.
	AwaitingApproval bool `json:"awaitingApproval,omitempty"`
	// Source is the evidence source of a breach: promote.SourceGateway,
	// promote.SourceCLI or "scorecard". Only gateway evidence may auto-kill.
	Source string `json:"source,omitempty"`
}

// Evidence is what the live step's gates are judged on.
type Evidence struct {
	// Report is the backing experiment evaluated with the step's guardrails
	// and minSamples (see GateExperiment); nil = no metric evidence.
	Report *promote.Report `json:"report,omitempty"`
	// Scorecard is the step's eval scorecard; nil with ScorecardErr = unreadable.
	Scorecard    *eval.Scorecard `json:"-"`
	ScorecardErr string          `json:"scorecardError,omitempty"`
	// Approved: a human is advancing this step by hand (`halo rollout advance`).
	Approved bool `json:"approved,omitempty"`
}

// Evaluate decides what to do with r now. It is pure: same inputs, same output.
// r must be resolved with Effective so the backing experiment's guardrails
// count.
//
// Order: (1) policy status and controller halts hold; (2) not started ->
// advance to step 0; (3) a failed guardrail or scorecard -> the step's
// onFailure, at any time; (4) bake, samples, guardrails, scorecard and
// approval must all pass, else hold; (5) advance, or complete after the last.
func Evaluate(r *policy.Rollout, st State, ev Evidence, now time.Time) Decision {
	d := Decision{Step: st.Step, Next: -1, Reasons: []string{}, Gates: []GateResult{}}
	hold := func(format string, a ...any) Decision {
		d.Action = Hold
		d.Reasons = append(d.Reasons, fmt.Sprintf(format, a...))
		return d
	}
	if s := r.EffectiveStatus(); s != policy.RolloutActive {
		return hold("rollout is %s", s)
	}
	if st.Halted != "" {
		return hold("halted by %s at step %q; waiting for its PR to merge", st.Halted, st.StepName)
	}
	if st.Step < 0 || st.Step >= len(r.Steps) {
		if len(r.Steps) == 0 {
			return hold("rollout has no steps")
		}
		d.Action, d.Next = Advance, 0
		d.Reasons = append(d.Reasons, "not started: propose step "+r.Steps[0].Name)
		return d
	}
	s := r.Steps[st.Step]
	d.Gates = gates(s, st, ev, now)

	// (3) breaches act immediately, before bake or samples.
	for _, g := range d.Gates {
		if g.Status != GateFail {
			continue
		}
		d.Reasons = append(d.Reasons, fmt.Sprintf("%s failed: %s (threshold %s)", g.Gate, g.Value, g.Threshold))
		if d.Source == "" {
			d.Source = "scorecard"
			if g.Gate != "scorecard" && ev.Report != nil {
				d.Source = guardrailSource(ev.Report, g.Gate)
			}
		}
	}
	if len(d.Reasons) > 0 {
		d.Action = Rollback
		if s.FailureAction() == "pause" {
			d.Action = Pause
		}
		return d
	}

	// (4) everything must pass.
	pending := 0
	for _, g := range d.Gates {
		if g.Status == GatePending {
			pending++
			d.Reasons = append(d.Reasons, g.Gate+": "+g.Detail)
		}
	}
	if pending > 0 {
		last := d.Gates[len(d.Gates)-1]
		d.AwaitingApproval = pending == 1 && last.Gate == "approval" && last.Status == GatePending
		d.Action = Hold
		return d
	}
	if st.Step == len(r.Steps)-1 {
		d.Action = Complete
		d.Reasons = append(d.Reasons, "all gates passed on the last step: propose completion")
		return d
	}
	d.Action, d.Next = Advance, st.Step+1
	d.Reasons = append(d.Reasons, "all gates passed: propose step "+r.Steps[d.Next].Name)
	return d
}

func guardrailSource(rep *promote.Report, gate string) string {
	for _, g := range rep.Guardrails {
		if "guardrail:"+g.Metric == gate {
			return g.Source
		}
	}
	return rep.Source
}

// gates evaluates the step's gates in a fixed order; approval is always last.
func gates(s policy.RolloutStep, st State, ev Evidence, now time.Time) []GateResult {
	var out []GateResult
	bake, _ := s.BakeDuration() // validated
	if bake > 0 {
		g := GateResult{Gate: "bake", Threshold: Days(bake)}
		switch {
		case st.EnteredAt.IsZero():
			g.Status, g.Value, g.Detail = GatePending, "unknown", "step entry time unknown (no controller state)"
		case now.Sub(st.EnteredAt) < bake:
			el := now.Sub(st.EnteredAt)
			g.Status, g.Value, g.Detail = GatePending, Days(el), fmt.Sprintf("baking, %s left", Days(bake-el))
		default:
			g.Status, g.Value = GatePass, Days(now.Sub(st.EnteredAt))
		}
		out = append(out, g)
	}
	rep := ev.Report
	if s.MinSamples > 0 {
		g := GateResult{Gate: "samples", Threshold: fmt.Sprintf(">= %d per arm", s.MinSamples)}
		switch {
		case rep == nil:
			g.Status, g.Value, g.Detail = GatePending, "unknown", "no metric evidence"
		case min(rep.NControl, rep.NTreatment) < s.MinSamples:
			g.Status, g.Value = GatePending, fmt.Sprintf("%d/%d", rep.NControl, rep.NTreatment)
			g.Detail = fmt.Sprintf("%s of %d per arm", g.Value, s.MinSamples)
		default:
			g.Status, g.Value = GatePass, fmt.Sprintf("%d/%d", rep.NControl, rep.NTreatment)
		}
		out = append(out, g)
	}
	for _, m := range s.Gates.Guardrails {
		g := GateResult{Gate: "guardrail:" + m.Metric, Threshold: fmt.Sprintf("regression <= %.1f%%", 100*m.MaxRegression), Status: GatePending, Value: "unknown", Detail: "no metric evidence"}
		if rep != nil {
			g.Detail = "not evaluated"
			for _, r := range rep.Guardrails {
				if r.Metric != m.Metric {
					continue
				}
				g.Value = fmt.Sprintf("%+.1f%% [%+.1f%%, %+.1f%%]", 100*r.Result.Regression, 100*r.Result.Lower, 100*r.Result.Upper)
				switch r.Result.Status {
				case stats.Pass:
					g.Status, g.Detail = GatePass, ""
				case stats.Fail:
					g.Status, g.Detail = GateFail, "regression significantly above the limit"
				default:
					g.Detail = fmt.Sprintf("inconclusive, upper bound %+.1f%% vs limit %.1f%%", 100*r.Result.Upper, 100*m.MaxRegression)
				}
			}
		}
		out = append(out, g)
	}
	// The experiment loop rolls back on a significantly worse primary metric;
	// an owned experiment must not lose that.
	if rep != nil && rep.Verdict == promote.Rollback && !slices.ContainsFunc(rep.Guardrails, func(g promote.GuardrailReport) bool { return g.Result.Status == stats.Fail }) {
		out = append(out, GateResult{Gate: "primary", Status: GateFail, Value: rep.Reason, Threshold: "not significantly worse"})
	}
	if sc := s.Gates.Scorecard; sc != nil {
		out = append(out, scorecardGate(sc, ev))
	}
	if s.Gates.Approval {
		g := GateResult{Gate: "approval", Threshold: "human advance", Status: GatePending, Value: "none", Detail: "awaiting a human (halo rollout advance)"}
		if ev.Approved {
			g.Status, g.Value, g.Detail = GatePass, "approved", ""
		}
		out = append(out, g)
	}
	return out
}

func scorecardGate(sc *policy.ScorecardGate, ev Evidence) GateResult {
	g := GateResult{Gate: "scorecard", Status: GatePending}
	var th []string
	if sc.MinPass1 > 0 {
		th = append(th, fmt.Sprintf("pass@1 >= %.1f%%", 100*sc.MinPass1))
	}
	th = append(th, fmt.Sprintf("delta >= %+.1fpp", -100*sc.MaxRegression))
	g.Threshold = strings.Join(th, ", ")
	if ev.Scorecard == nil {
		g.Value, g.Detail = "missing", "scorecard "+sc.File+" not available"
		if ev.ScorecardErr != "" {
			g.Detail = ev.ScorecardErr
		}
		return g
	}
	var pass1 *float64
	for _, v := range ev.Scorecard.Variants {
		if v.Name == sc.Variant {
			pass1 = &v.Pass1
		}
	}
	if pass1 == nil {
		g.Value, g.Detail = "missing", fmt.Sprintf("variant %q not in scorecard %s", sc.Variant, sc.File)
		return g
	}
	g.Value = fmt.Sprintf("pass@1 %.1f%%", 100**pass1)
	g.Status = GatePass
	if sc.MinPass1 > 0 && *pass1 < sc.MinPass1 {
		g.Status = GateFail
	}
	for _, c := range ev.Scorecard.Comparisons {
		if c.Variant != sc.Variant {
			continue
		}
		g.Value += fmt.Sprintf(", delta %+.1fpp vs %s (%s)", 100*c.Delta, c.Control, c.Verdict)
		if c.Verdict == eval.VerdictWorse || c.Delta < -sc.MaxRegression {
			g.Status = GateFail
		}
		// Scorecards from newer builds carry a non-inferiority gate per
		// comparison; older ones have none and rely on the checks above.
		if c.Gate == nil {
			continue
		}
		g.Value += ", eval gate " + c.Gate.Verdict
		switch c.Gate.Verdict {
		case eval.GateBlock:
			g.Status = GateFail
		case eval.GateHold:
			if g.Status == GatePass {
				g.Status, g.Detail = GatePending, "eval gate hold: "+strings.Join(c.Gate.Reasons, "; ")
			}
		}
	}
	return g
}
