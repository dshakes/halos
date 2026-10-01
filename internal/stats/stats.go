// Package stats holds the statistics Halos uses to gate rollouts:
// always-valid sequential tests (mSPRT), fixed-horizon Welch tests, CUPED
// variance reduction, paired bootstrap for eval scorecards, and guardrail
// evaluation. Stdlib only.
package stats

import (
	"errors"
	"math"
)

// ErrTooFewSamples is returned when a test needs more observations.
var ErrTooFewSamples = errors.New("stats: need at least 2 samples per arm")

func mean(x []float64) float64 {
	if len(x) == 0 {
		return math.NaN()
	}
	s := 0.0
	for _, v := range x {
		s += v
	}
	return s / float64(len(x))
}

// variance is the unbiased sample variance.
func variance(x []float64) float64 {
	if len(x) < 2 {
		return math.NaN()
	}
	m := mean(x)
	s := 0.0
	for _, v := range x {
		s += (v - m) * (v - m)
	}
	return s / float64(len(x)-1)
}

// incBeta is the regularised incomplete beta function I_x(a,b)
// (continued fraction, Numerical Recipes 6.4).
func incBeta(a, b, x float64) float64 {
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 1
	}
	la, _ := math.Lgamma(a + b)
	lb, _ := math.Lgamma(a)
	lc, _ := math.Lgamma(b)
	bt := math.Exp(la - lb - lc + a*math.Log(x) + b*math.Log(1-x))
	if x < (a+1)/(a+b+2) {
		return bt * betaCF(a, b, x) / a
	}
	return 1 - bt*betaCF(b, a, 1-x)/b
}

func betaCF(a, b, x float64) float64 {
	const tiny = 1e-300
	qab, qap, qam := a+b, a+1, a-1
	c, d := 1.0, 1-qab*x/qap
	if math.Abs(d) < tiny {
		d = tiny
	}
	d = 1 / d
	h := d
	for m := 1; m <= 300; m++ {
		fm := float64(m)
		aa := fm * (b - fm) * x / ((qam + 2*fm) * (a + 2*fm))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		h *= d * c
		aa = -(a + fm) * (qab + fm) * x / ((a + 2*fm) * (qap + 2*fm))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < 1e-14 {
			break
		}
	}
	return h
}

// tCDF is the Student t CDF with df degrees of freedom.
func tCDF(t, df float64) float64 {
	x := df / (df + t*t)
	tail := 0.5 * incBeta(df/2, 0.5, x)
	if t > 0 {
		return 1 - tail
	}
	return tail
}

// tQuantile inverts tCDF by bisection.
func tQuantile(p, df float64) float64 {
	lo, hi := -1e3, 1e3
	for i := 0; i < 200; i++ {
		mid := (lo + hi) / 2
		if tCDF(mid, df) < p {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

// WelchResult is a fixed-horizon two-sample comparison (treatment - control).
type WelchResult struct {
	Effect float64 // mean(t) - mean(c)
	SE     float64
	T, DF  float64
	PValue float64 // two-sided
	CILo   float64 // (1-alpha) two-sided CI on Effect
	CIHi   float64
	NC, NT int
	MeanC  float64
	MeanT  float64
}

// Welch runs Welch's unequal-variance t-test.
func Welch(control, treatment []float64, alpha float64) (WelchResult, error) {
	if len(control) < 2 || len(treatment) < 2 {
		return WelchResult{}, ErrTooFewSamples
	}
	vc, vt := variance(control)/float64(len(control)), variance(treatment)/float64(len(treatment))
	se := math.Sqrt(vc + vt)
	r := WelchResult{NC: len(control), NT: len(treatment), MeanC: mean(control), MeanT: mean(treatment), SE: se}
	r.Effect = r.MeanT - r.MeanC
	if se == 0 {
		r.PValue = 1
		if r.Effect != 0 {
			r.PValue = 0
		}
		r.CILo, r.CIHi = r.Effect, r.Effect
		return r, nil
	}
	r.T = r.Effect / se
	r.DF = (vc + vt) * (vc + vt) / (vc*vc/float64(len(control)-1) + vt*vt/float64(len(treatment)-1))
	r.PValue = 2 * (1 - tCDF(math.Abs(r.T), r.DF))
	q := tQuantile(1-alpha/2, r.DF)
	r.CILo, r.CIHi = r.Effect-q*se, r.Effect+q*se
	return r, nil
}

// CUPED adjusts y using pre-period covariate x with coefficient theta:
// y' = y - theta*(x - mean(x)). Mean of y is preserved, variance shrinks.
func CUPED(y, x []float64, theta float64) []float64 {
	mx := mean(x)
	out := make([]float64, len(y))
	for i := range y {
		out[i] = y[i] - theta*(x[i]-mx)
	}
	return out
}

// CUPEDArms adjusts both arms with a single pooled theta = cov(y,x)/var(x)
// (pooling keeps the treatment-effect estimate unbiased). y and x must be
// index-aligned per arm.
func CUPEDArms(yc, xc, yt, xt []float64) (adjC, adjT []float64, theta float64, err error) {
	if len(yc) != len(xc) || len(yt) != len(xt) {
		return nil, nil, 0, errors.New("stats: covariate length mismatch")
	}
	y := append(append([]float64{}, yc...), yt...)
	x := append(append([]float64{}, xc...), xt...)
	if len(y) < 2 {
		return nil, nil, 0, ErrTooFewSamples
	}
	my, mx := mean(y), mean(x)
	var cov, vx float64
	for i := range y {
		cov += (y[i] - my) * (x[i] - mx)
		vx += (x[i] - mx) * (x[i] - mx)
	}
	if vx > 0 {
		theta = cov / vx
	}
	// Centre on the pooled covariate mean so both arms shift identically.
	adj := func(ys, xs []float64) []float64 {
		out := make([]float64, len(ys))
		for i := range ys {
			out[i] = ys[i] - theta*(xs[i]-mx)
		}
		return out
	}
	return adj(yc, xc), adj(yt, xt), theta, nil
}
