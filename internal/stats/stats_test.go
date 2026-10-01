package stats

import (
	"math"
	"math/rand/v2"
	"testing"
)

func normals(rng *rand.Rand, n int, mu, sd float64) []float64 {
	x := make([]float64, n)
	for i := range x {
		x[i] = mu + sd*rng.NormFloat64()
	}
	return x
}

// peek runs an mSPRT over growing prefixes; returns whether it ever rejected.
func peek(c, t []float64, alpha, tau2 float64) (bool, int) {
	m := NewMSPRT(alpha, tau2)
	for n := 20; n <= len(c); n += 10 {
		if m.ObserveMeans(c[:n], t[:n]).Decision == RejectNull {
			return true, n
		}
	}
	return false, 0
}

func TestMSPRTFalsePositiveRateUnderPeeking(t *testing.T) {
	const sims, alpha, margin = 500, 0.05, 0.03
	rng := rand.New(rand.NewPCG(1, 2))
	fp := 0
	for i := 0; i < sims; i++ {
		if rej, _ := peek(normals(rng, 1000, 0, 1), normals(rng, 1000, 0, 1), alpha, 0.1); rej {
			fp++
		}
	}
	if rate := float64(fp) / sims; rate > alpha+margin {
		t.Fatalf("false-positive rate %.3f > %.3f", rate, alpha+margin)
	}
}

func TestMSPRTDetectsStrongEffect(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 50; i++ {
		if rej, _ := peek(normals(rng, 500, 0, 1), normals(rng, 500, 0.5, 1), 0.05, 0.25); !rej {
			t.Fatalf("sim %d: effect 0.5sd not detected in 500/arm", i)
		}
	}
}

// Binary metric fed as 0/1 samples: the confidence sequence covers the true
// lift and the test rejects.
func TestMSPRTBinaryMetricAndCI(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	m := NewMSPRT(0.05, 0.01)
	var c, tr []float64
	bern := func(p float64) float64 {
		if rng.Float64() < p {
			return 1
		}
		return 0
	}
	var last SeqResult
	for n := 1; n <= 2000; n++ {
		c, tr = append(c, bern(0.30)), append(tr, bern(0.45))
		if n%50 == 0 {
			last = m.ObserveMeans(c, tr)
		}
	}
	if last.Decision != RejectNull {
		t.Fatalf("want reject_null, got %+v", last)
	}
	if !(last.CILo < 0.15 && 0.15 < last.CIHi) {
		t.Fatalf("CS [%.3f,%.3f] should cover 0.15", last.CILo, last.CIHi)
	}
	if got := NewMSPRT(0.05, 1).ObserveMeans([]float64{1}, []float64{0}); got.Decision != Continue {
		t.Fatalf("tiny sample must continue, got %v", got.Decision)
	}
}

func TestWelch(t *testing.T) {
	// Known t-distribution values: CDF(1; df=1)=0.75, two-sided p(t=2, df=10)=0.07339.
	if math.Abs(tCDF(1, 1)-0.75) > 1e-9 || math.Abs(2*(1-tCDF(2, 10))-0.07339) > 1e-4 {
		t.Fatalf("tCDF wrong: %v %v", tCDF(1, 1), 2*(1-tCDF(2, 10)))
	}
	a := []float64{27.5, 21.0, 19.0, 23.6, 17.0, 17.9, 16.9, 20.1, 21.9, 22.6, 23.1, 19.6, 19.0, 21.7, 21.4}
	b := []float64{27.1, 22.0, 20.8, 23.4, 23.4, 23.5, 25.8, 22.0, 24.8, 20.2, 21.9, 22.1, 22.9, 20.5, 24.4}
	r, err := Welch(a, b, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(r.T-2.4554) > 1e-3 || math.Abs(r.PValue-0.0214) > 1e-3 {
		t.Fatalf("t=%.4f p=%.4f", r.T, r.PValue)
	}
	if !(r.CILo < r.Effect && r.Effect < r.CIHi) || r.CILo <= 0 {
		t.Fatalf("CI [%.3f,%.3f] effect %.3f", r.CILo, r.CIHi, r.Effect)
	}
	if _, err := Welch(a[:1], b, 0.05); err == nil {
		t.Fatal("want error on tiny sample")
	}
	if r, _ := Welch([]float64{1, 1}, []float64{1, 1}, 0.05); r.PValue != 1 {
		t.Fatalf("identical constants p=%v", r.PValue)
	}
}

func TestCUPEDReducesVariance(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	n := 2000
	xc, xt := normals(rng, n, 10, 3), normals(rng, n, 10, 3)
	yc, yt := make([]float64, n), make([]float64, n)
	for i := 0; i < n; i++ {
		yc[i] = xc[i] + rng.NormFloat64()*0.5
		yt[i] = xt[i] + 0.3 + rng.NormFloat64()*0.5
	}
	raw, _ := Welch(yc, yt, 0.05)
	ac, at, theta, err := CUPEDArms(yc, xc, yt, xt)
	if err != nil {
		t.Fatal(err)
	}
	adj, _ := Welch(ac, at, 0.05)
	if math.Abs(theta-1) > 0.05 {
		t.Fatalf("theta=%.3f want ~1", theta)
	}
	if adj.SE > raw.SE/3 {
		t.Fatalf("SE %.4f not reduced enough vs %.4f", adj.SE, raw.SE)
	}
	if math.Abs(adj.Effect-0.3) > 0.05 {
		t.Fatalf("effect %.3f want ~0.3", adj.Effect)
	}
	if _, _, _, err := CUPEDArms(yc, xc[:1], yt, xt); err == nil {
		t.Fatal("want length mismatch error")
	}
}

func TestPairedBootstrap(t *testing.T) {
	c := []float64{0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0}
	tr := []float64{1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1}
	r1, err := PairedBootstrap(c, tr, 2000, 42, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := PairedBootstrap(c, tr, 2000, 42, 0.05)
	if r1 != r2 {
		t.Fatal("same seed must give identical result")
	}
	if r1.CILo <= 0 || r1.PGreat < 0.99 {
		t.Fatalf("expected clear improvement: %+v", r1)
	}
	if _, err := PairedBootstrap(c, tr[:3], 10, 1, 0.05); err == nil {
		t.Fatal("want length error")
	}
	if _, err := BootstrapMean(nil, 10, 1, 0.05); err == nil {
		t.Fatal("want empty error")
	}
	if _, err := BootstrapMean(c, 0, 1, 0.05); err == nil {
		t.Fatal("want iters error")
	}
}

func TestSeqGuardrail(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 10))
	base := normals(rng, 3000, 100, 10)
	tests := []struct {
		name      string
		treatment []float64
		dir       string
		max       float64
		want      GuardrailStatus
	}{
		{"cost up 20% fails (decrease goal)", normals(rng, 3000, 120, 10), "decrease", 0.05, Fail},
		{"cost flat passes", normals(rng, 3000, 100, 10), "decrease", 0.05, Pass},
		{"success drop 20% fails (increase goal)", normals(rng, 3000, 80, 10), "increase", 0.05, Fail},
		{"success up passes", normals(rng, 3000, 110, 10), "increase", 0.05, Pass},
		{"borderline is inconclusive", normals(rng, 3000, 105, 10), "decrease", 0.05, Inconclusive},
		{"small noisy sample inconclusive", normals(rng, 5, 100, 40), "decrease", 0.05, Inconclusive},
		{"zero max uses default mixture", normals(rng, 3000, 120, 10), "decrease", 0, Fail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SeqGuardrail(base, tc.treatment, tc.dir, tc.max, 0.05)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.want || got.MaxRegression != tc.max || !(got.Lower <= got.Regression && got.Regression <= got.Upper) {
				t.Fatalf("got %v want %v (%+v)", got.Status, tc.want, got)
			}
		})
	}
	// Direction flips the sign: a 20% drop is +0.2 regression for "increase".
	if r, _ := SeqGuardrail(base, normals(rng, 3000, 80, 10), "increase", 0.05, 0.05); math.Abs(r.Regression-0.2) > 0.02 {
		t.Fatalf("regression %v want ~0.2", r.Regression)
	}
	if _, err := SeqGuardrail(base, base, "sideways", 0.05, 0.05); err == nil {
		t.Fatal("want direction error")
	}
	if r, err := SeqGuardrail(base[:1], base, "increase", 0.05, 0.05); err != ErrTooFewSamples || r.Status != Inconclusive {
		t.Fatalf("want ErrTooFewSamples + inconclusive, got %v %v", r.Status, err)
	}
	if r, err := SeqGuardrail([]float64{0, 0, 0}, []float64{1, 2, 3}, "decrease", 0.05, 0.05); err != nil || r.Status != Inconclusive {
		t.Fatalf("zero control mean must be inconclusive, got %v %v", r.Status, err)
	}
}

// Peeking-safe: under no regression, repeated looks at growing samples almost
// never Fail (alpha bounds the chance any look does).
func TestSeqGuardrailNoFalseFailUnderPeeking(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 12))
	const sims, alpha = 200, 0.05
	fails := 0
	for i := 0; i < sims; i++ {
		c, tr := normals(rng, 1000, 100, 10), normals(rng, 1000, 100, 10)
		for n := 20; n <= 1000; n += 20 {
			if r, _ := SeqGuardrail(c[:n], tr[:n], "decrease", 0, alpha); r.Status == Fail {
				fails++
				break
			}
		}
	}
	if rate := float64(fails) / sims; rate > alpha {
		t.Fatalf("false fail rate %.3f > %.2f", rate, alpha)
	}
}

func TestCUPEDPreservesMean(t *testing.T) {
	y, x := []float64{1, 2, 3, 4}, []float64{10, 12, 14, 16}
	out := CUPED(y, x, 0.5)
	if math.Abs(mean(out)-mean(y)) > 1e-12 || variance(out) >= variance(y) {
		t.Fatalf("CUPED %v: mean %v var %v", out, mean(out), variance(out))
	}
}
