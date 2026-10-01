package stats

import "math"

// Decision is the outcome of a sequential test at the current look.
type Decision string

const (
	Continue   Decision = "continue"
	RejectNull Decision = "reject_null"
)

// SeqResult is an always-valid snapshot. PValue and the CI are valid under
// continuous peeking. mSPRT can only reject the null; it never "accepts", so
// callers stop on a sample/time budget instead (see internal/promote).
type SeqResult struct {
	PValue   float64 // always-valid p-value (running min of 1/Lambda)
	Decision Decision
	Effect   float64 // treatment - control
	CILo     float64 // (1-alpha) confidence sequence (running intersection)
	CIHi     float64
	NC, NT   int
}

// MSPRT is a stateful two-sample normal-mixture sequential probability ratio
// test (Johari et al. 2017). Feed it the cumulative data at each look. Not
// safe for concurrent use.
type MSPRT struct {
	Alpha float64
	// Tau2 is the mixture variance: the prior variance of the true effect.
	// Pick roughly (plausible effect size)^2; power, not validity, depends on it.
	Tau2 float64

	p      float64
	lo, hi float64
}

// NewMSPRT returns a test with the given alpha and mixture variance.
func NewMSPRT(alpha, tau2 float64) *MSPRT {
	return &MSPRT{Alpha: alpha, Tau2: tau2, p: 1, lo: math.Inf(-1), hi: math.Inf(1)}
}

// lambda returns the log mixture likelihood ratio for effect estimate d
// with variance v of the estimate.
func (m *MSPRT) logLambda(d, v float64) float64 {
	return 0.5*math.Log(v/(v+m.Tau2)) + m.Tau2*d*d/(2*v*(v+m.Tau2))
}

func (m *MSPRT) update(d, v float64, nc, nt int) SeqResult {
	res := SeqResult{Effect: d, NC: nc, NT: nt}
	if v > 0 && !math.IsNaN(v) && !math.IsNaN(d) {
		if p := math.Min(1, math.Exp(-m.logLambda(d, v))); p < m.p {
			m.p = p
		}
		w := math.Sqrt(v * (v + m.Tau2) / m.Tau2 * (2*math.Log(1/m.Alpha) + math.Log((v+m.Tau2)/v)))
		m.lo, m.hi = math.Max(m.lo, d-w), math.Min(m.hi, d+w)
	}
	res.PValue, res.CILo, res.CIHi = m.p, m.lo, m.hi
	res.Decision = Continue
	if m.p <= m.Alpha {
		res.Decision = RejectNull
	}
	return res
}

// ObserveEstimate updates with a pre-computed effect estimate d and the
// variance v of that estimate (e.g. a delta-method relative difference).
func (m *MSPRT) ObserveEstimate(d, v float64, nc, nt int) SeqResult { return m.update(d, v, nc, nt) }

// ObserveMeans updates with cumulative samples of a continuous metric.
func (m *MSPRT) ObserveMeans(control, treatment []float64) SeqResult {
	if len(control) < 2 || len(treatment) < 2 {
		return SeqResult{PValue: m.p, Decision: Continue, CILo: m.lo, CIHi: m.hi, NC: len(control), NT: len(treatment)}
	}
	v := variance(control)/float64(len(control)) + variance(treatment)/float64(len(treatment))
	return m.update(mean(treatment)-mean(control), v, len(control), len(treatment))
}
