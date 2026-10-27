package stats

import (
	"errors"
	"math"
	"math/rand/v2"
	"sort"
)

// BootstrapResult is a percentile bootstrap estimate of a mean.
type BootstrapResult struct {
	Mean   float64
	CILo   float64
	CIHi   float64
	PGreat float64 // share of resamples with mean > 0 (paired diffs: P(treatment better))
	N      int
}

// BootstrapMean is a percentile bootstrap CI of the mean of x. Deterministic
// for a given seed.
func BootstrapMean(x []float64, iters int, seed uint64, alpha float64) (BootstrapResult, error) {
	if len(x) == 0 {
		return BootstrapResult{}, errors.New("stats: bootstrap of empty sample")
	}
	if iters < 1 {
		return BootstrapResult{}, errors.New("stats: bootstrap iters must be >= 1")
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) //nolint:gosec // seeded PRNG for reproducible bootstrap CIs; not security sensitive
	means := make([]float64, iters)
	pos := 0
	for i := range means {
		s := 0.0
		for range x {
			s += x[rng.IntN(len(x))]
		}
		means[i] = s / float64(len(x))
		if means[i] > 0 {
			pos++
		}
	}
	sort.Float64s(means)
	at := func(q float64) float64 {
		i := int(q * float64(iters-1))
		return means[i]
	}
	return BootstrapResult{Mean: mean(x), CILo: at(alpha / 2), CIHi: at(1 - alpha/2), PGreat: float64(pos) / float64(iters), N: len(x)}, nil
}

// PairedBootstrap bootstraps the mean of (treatment[i]-control[i]) over
// tasks, preserving the pairing. Slices must be index-aligned.
func PairedBootstrap(control, treatment []float64, iters int, seed uint64, alpha float64) (BootstrapResult, error) {
	if len(control) != len(treatment) {
		return BootstrapResult{}, errors.New("stats: paired samples differ in length")
	}
	d := make([]float64, len(control))
	for i := range d {
		d[i] = treatment[i] - control[i]
	}
	return BootstrapMean(d, iters, seed, alpha)
}

// ClusterBootstrapMean is a percentile bootstrap CI of the mean of x when
// observations are grouped in clusters (cluster[i] labels x[i]), e.g. the
// steps of one agent session. Steps of a session are correlated, so
// resampling them independently understates the variance; this resamples
// whole clusters and takes the ratio estimator sum(x)/n over the resample.
// With one observation per cluster it reduces to BootstrapMean.
func ClusterBootstrapMean(x []float64, cluster []string, iters int, seed uint64, alpha float64) (BootstrapResult, error) {
	if len(x) != len(cluster) {
		return BootstrapResult{}, errors.New("stats: cluster labels differ in length from the sample")
	}
	if len(x) == 0 {
		return BootstrapResult{}, errors.New("stats: bootstrap of empty sample")
	}
	if iters < 1 {
		return BootstrapResult{}, errors.New("stats: bootstrap iters must be >= 1")
	}
	idx := map[string]int{}
	var sums, ns []float64
	for i, c := range cluster {
		j, ok := idx[c]
		if !ok {
			j = len(sums)
			idx[c] = j
			sums, ns = append(sums, 0), append(ns, 0)
		}
		sums[j] += x[i]
		ns[j]++
	}
	k := len(sums)
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) //nolint:gosec // seeded PRNG for reproducible bootstrap CIs; not security sensitive
	means := make([]float64, iters)
	pos := 0
	for i := range means {
		s, n := 0.0, 0.0
		for range k {
			j := rng.IntN(k)
			s, n = s+sums[j], n+ns[j]
		}
		means[i] = s / n
		if means[i] > 0 {
			pos++
		}
	}
	sort.Float64s(means)
	at := func(q float64) float64 { return means[int(q*float64(iters-1))] }
	return BootstrapResult{Mean: mean(x), CILo: at(alpha / 2), CIHi: at(1 - alpha/2), PGreat: float64(pos) / float64(iters), N: len(x)}, nil
}

// PairedClusterBootstrap is PairedBootstrap with cluster resampling.
func PairedClusterBootstrap(control, treatment []float64, cluster []string, iters int, seed uint64, alpha float64) (BootstrapResult, error) {
	if len(control) != len(treatment) {
		return BootstrapResult{}, errors.New("stats: paired samples differ in length")
	}
	d := make([]float64, len(control))
	for i := range d {
		d[i] = treatment[i] - control[i]
	}
	return ClusterBootstrapMean(d, cluster, iters, seed, alpha)
}

// Cluster is one cluster's contribution to a ratio estimator: the sums of a
// numerator and a denominator over its observations, e.g. one developer's
// total PR cycle hours (Num) over their merged PRs (Den).
type Cluster struct{ Num, Den float64 }

// DiffResult is a two-arm estimate of ratio(treatment) - ratio(control),
// where an arm's ratio is sum(Num)/sum(Den) over its clusters.
type DiffResult struct {
	Control   float64 `json:"control"`
	Treatment float64 `json:"treatment"`
	Effect    float64 `json:"effect"` // Treatment - Control
	CILo      float64 `json:"ciLo"`
	CIHi      float64 `json:"ciHi"`
	// Rel is Effect/Control with its CI (resamples whose control ratio is 0
	// are left out of the relative CI); all 0 when Control is 0.
	Rel     float64 `json:"rel"`
	RelCILo float64 `json:"relCiLo"`
	RelCIHi float64 `json:"relCiHi"`
	SE      float64 `json:"se"` // bootstrap standard deviation of Effect
	NC      int     `json:"nControl"`
	NT      int     `json:"nTreatment"`
}

// ClusterBootstrapDiff is a percentile bootstrap CI of the difference between
// two independent arms' ratio estimators. Whole clusters are resampled within
// each arm (stratified by arm), so correlated observations of one cluster
// never count as independent evidence. Every Den must be > 0. Deterministic
// for a given seed.
func ClusterBootstrapDiff(control, treatment []Cluster, iters int, seed uint64, alpha float64) (DiffResult, error) {
	if len(control) == 0 || len(treatment) == 0 {
		return DiffResult{}, errors.New("stats: bootstrap of an empty arm")
	}
	if iters < 2 {
		return DiffResult{}, errors.New("stats: bootstrap iters must be >= 2")
	}
	for _, arm := range [][]Cluster{control, treatment} {
		for _, c := range arm {
			if !(c.Den > 0) {
				return DiffResult{}, errors.New("stats: cluster denominator must be > 0")
			}
		}
	}
	ratio := func(cs []Cluster) float64 {
		var n, d float64
		for _, c := range cs {
			n, d = n+c.Num, d+c.Den
		}
		return n / d
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) //nolint:gosec // seeded PRNG for reproducible bootstrap CIs; not security sensitive
	resample := func(cs []Cluster) float64 {
		var n, d float64
		for range cs {
			c := cs[rng.IntN(len(cs))]
			n, d = n+c.Num, d+c.Den
		}
		return n / d
	}
	r := DiffResult{Control: ratio(control), Treatment: ratio(treatment), NC: len(control), NT: len(treatment)}
	r.Effect = r.Treatment - r.Control
	diffs, rels := make([]float64, iters), make([]float64, 0, iters)
	var sum, sum2 float64
	for i := range diffs {
		c, t := resample(control), resample(treatment)
		diffs[i] = t - c
		if c != 0 {
			rels = append(rels, (t-c)/c)
		}
		sum, sum2 = sum+diffs[i], sum2+diffs[i]*diffs[i]
	}
	n := float64(iters)
	r.SE = math.Sqrt(max(0, (sum2-sum*sum/n)/(n-1)))
	sort.Float64s(diffs)
	sort.Float64s(rels)
	at := func(s []float64, q float64) float64 { return s[int(q*float64(len(s)-1))] }
	r.CILo, r.CIHi = at(diffs, alpha/2), at(diffs, 1-alpha/2)
	if r.Control != 0 && len(rels) > 0 {
		r.Rel = r.Effect / r.Control
		r.RelCILo, r.RelCIHi = at(rels, alpha/2), at(rels, 1-alpha/2)
	}
	return r, nil
}
