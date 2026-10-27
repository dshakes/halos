package stats

import (
	"errors"
	"math"
)

// SRMResult is a sample ratio mismatch check: a chi-square goodness-of-fit
// test of the observed units per arm against the configured weights.
type SRMResult struct {
	Chi2     float64 `json:"chi2"`
	PValue   float64 `json:"pValue"`
	Mismatch bool    `json:"mismatch"` // PValue < alpha
}

// SRM tests observed[i] against weights[i] (normalised). A mismatch means
// units were lost or gained unevenly between arms (logging, eligibility,
// attrition caused by the treatment), so arm differences are not trustworthy
// estimates of the effect. The conventional alpha is 0.001.
func SRM(observed []int, weights []float64, alpha float64) (SRMResult, error) {
	if len(observed) != len(weights) || len(observed) < 2 {
		return SRMResult{}, errors.New("stats: SRM needs one weight per arm and at least two arms")
	}
	var n, w float64
	for i, o := range observed {
		if o < 0 || !(weights[i] > 0) {
			return SRMResult{}, errors.New("stats: SRM counts must be >= 0 and weights > 0")
		}
		n, w = n+float64(o), w+weights[i]
	}
	if n == 0 {
		return SRMResult{}, ErrTooFewSamples
	}
	var chi2 float64
	for i, o := range observed {
		exp := n * weights[i] / w
		chi2 += (float64(o) - exp) * (float64(o) - exp) / exp
	}
	p := gammaQ(float64(len(observed)-1)/2, chi2/2)
	return SRMResult{Chi2: chi2, PValue: p, Mismatch: p < alpha}, nil
}

// gammaQ is the regularised upper incomplete gamma function Q(a, x); the
// chi-square survival function with k degrees of freedom is gammaQ(k/2, x/2).
// Series for x < a+1, else a continued fraction (Numerical Recipes 6.2).
func gammaQ(a, x float64) float64 {
	if x <= 0 {
		return 1
	}
	lg, _ := math.Lgamma(a)
	front := math.Exp(-x + a*math.Log(x) - lg)
	if x < a+1 {
		ap, del, sum := a, 1/a, 1/a
		for range 1000 {
			ap++
			del *= x / ap
			sum += del
			if math.Abs(del) < math.Abs(sum)*1e-15 {
				break
			}
		}
		return max(0, 1-sum*front)
	}
	const tiny = 1e-300
	b := x + 1 - a
	c, d := 1/tiny, 1/b
	h := d
	for i := 1; i <= 1000; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < 1e-15 {
			break
		}
	}
	return front * h
}
