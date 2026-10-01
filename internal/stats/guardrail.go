package stats

import (
	"fmt"
	"math"
)

// GuardrailStatus is the verdict on one guardrail metric.
type GuardrailStatus string

const (
	Pass         GuardrailStatus = "pass"         // regression is significantly below the limit
	Fail         GuardrailStatus = "fail"         // regression is significantly above the limit
	Inconclusive GuardrailStatus = "inconclusive" // not enough evidence either way
)

// GuardrailResult reports the relative regression of treatment vs control
// (positive = worse) with a one-sided (1-alpha) bound on each side.
type GuardrailResult struct {
	Status        GuardrailStatus `json:"status"`
	Regression    float64         `json:"regression"` // point estimate, relative to control mean
	Lower         float64         `json:"lower"`      // one-sided (1-alpha) bounds on Regression
	Upper         float64         `json:"upper"`
	MaxRegression float64         `json:"maxRegression"`
}

// SeqGuardrail tests whether treatment regressed against control by more
// than maxRegression (relative, e.g. 0.05). direction is the metric's good
// direction: "increase" (lower is a regression) or "decrease" (higher is a
// regression). It is always valid (peeking-safe): it feeds the delta-method relative regression and its variance into an mSPRT
// and reads the verdict off the resulting confidence sequence, which holds
// simultaneously over all looks: Fail if the lower bound exceeds maxRegression,
// Pass if the upper bound is below it. alpha bounds the probability that
// *any* look ever wrongly fails/passes. Result.Lower/Upper are the sequence
// bounds. Each call sees one look; a confidence sequence at any single look is
// valid, so no state is needed across polls.
func SeqGuardrail(control, treatment []float64, direction string, maxRegression, alpha float64) (GuardrailResult, error) {
	if direction != "increase" && direction != "decrease" {
		return GuardrailResult{}, fmt.Errorf("stats: unknown direction %q", direction)
	}
	res := GuardrailResult{Status: Inconclusive, MaxRegression: maxRegression}
	if len(control) < 2 || len(treatment) < 2 {
		return res, ErrTooFewSamples
	}
	mc, mt := mean(control), mean(treatment)
	if mc == 0 {
		return res, nil
	}
	nc, nt := float64(len(control)), float64(len(treatment))
	r := (mt - mc) / math.Abs(mc)
	vr := variance(treatment)/nt/(mc*mc) + mt*mt*variance(control)/nc/(mc*mc*mc*mc)
	// Mixture sd: the size of regression we care about (power only, not validity).
	tau := maxRegression
	if tau <= 0 {
		tau = 0.05
	}
	sr := NewMSPRT(alpha, tau*tau).ObserveEstimate(r, vr, len(control), len(treatment))
	lo, hi := sr.CILo, sr.CIHi
	res.Regression = r
	if direction == "increase" { // a drop is the regression
		res.Regression, lo, hi = -r, -hi, -lo
	}
	res.Lower, res.Upper = lo, hi
	switch {
	case lo > maxRegression:
		res.Status = Fail
	case hi < maxRegression:
		res.Status = Pass
	}
	return res, nil
}
