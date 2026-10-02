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
	Regression    float64         `json:"regression"` // point estimate, relative to control mean (absolute when that is 0)
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
	nc, nt := float64(len(control)), float64(len(treatment))
	if mc == 0 {
		return zeroBaseline(res, control, treatment, direction, maxRegression, alpha), nil
	}
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

// zeroBaseline decides a guardrail whose control mean is 0 (typically an
// error rate with no control errors). The relative regression is then 0 when
// the arms agree and unbounded otherwise, so the test runs on the absolute
// difference (Regression/Lower/Upper are absolute here): Fail when the
// treatment is significantly worse, since any worsening of a zero baseline
// exceeds every relative limit; Pass when it is certainly no worse (both arms
// exactly 0) and the limit allows no change.
func zeroBaseline(res GuardrailResult, control, treatment []float64, direction string, maxRegression, alpha float64) GuardrailResult {
	d := mean(treatment)
	v := variance(control)/float64(len(control)) + variance(treatment)/float64(len(treatment))
	lo, hi := d, d // no variance: the difference is exact
	if v > 0 {
		// Mixture sd: the observed spread (power only, not validity).
		tau2 := variance(append(append([]float64{}, control...), treatment...))
		sr := NewMSPRT(alpha, tau2).ObserveEstimate(d, v, len(control), len(treatment))
		lo, hi = sr.CILo, sr.CIHi
	}
	res.Regression = d
	if direction == "increase" {
		res.Regression, lo, hi = -d, -hi, -lo
	}
	res.Lower, res.Upper = lo, hi
	switch {
	case lo > 0:
		res.Status = Fail
	case hi <= 0 && maxRegression > 0:
		res.Status = Pass
	}
	return res
}
