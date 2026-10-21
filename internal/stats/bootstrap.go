package stats

import (
	"errors"
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
