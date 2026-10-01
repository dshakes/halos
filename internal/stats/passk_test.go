package stats

import (
	"math"
	"math/rand/v2"
	"testing"
)

func TestPassAtKKnownAnswers(t *testing.T) {
	tests := []struct {
		n, c, k        int
		passAt, passHt float64
	}{
		{5, 2, 1, 0.4, 0.4},
		{5, 2, 2, 0.7, 0.1}, // 1 - C(3,2)/C(5,2) = 0.7; C(2,2)/C(5,2) = 0.1
		{5, 5, 3, 1, 1},
		{4, 0, 2, 0, 0},
		{10, 3, 5, 1 - 21.0/252, 0},           // C(7,5)=21, C(10,5)=252; c<k
		{10, 8, 3, 1, 56.0 / 120},             // n-c<k; C(8,3)=56, C(10,3)=120
		{100, 50, 10, 1 - 0.000593, 0.000593}, // symmetric at c = n/2: C(50,10)/C(100,10)
	}
	for _, tc := range tests {
		a, err := PassAtK(tc.n, tc.c, tc.k)
		if err != nil {
			t.Fatal(err)
		}
		h, err := PassHatK(tc.n, tc.c, tc.k)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(a-tc.passAt) > 1e-5 || math.Abs(h-tc.passHt) > 1e-5 {
			t.Errorf("n=%d c=%d k=%d: pass@k=%.6f pass^k=%.6f, want %.6f %.6f", tc.n, tc.c, tc.k, a, h, tc.passAt, tc.passHt)
		}
	}
	for _, bad := range [][3]int{{0, 0, 1}, {3, 4, 1}, {3, 1, 0}, {3, 1, 4}, {3, -1, 1}} {
		if _, err := PassAtK(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("PassAtK%v: want error", bad)
		}
		if _, err := PassHatK(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("PassHatK%v: want error", bad)
		}
	}
}

// A paired bootstrap over tasks whose true per-task delta is 0.3 must cover
// 0.3 and exclude 0.
func TestPairedBootstrapCoversKnownDelta(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 7))
	var c, tr []float64
	for range 60 {
		base := rng.Float64() * 10 // large between-task variance: pairing removes it
		c = append(c, base)
		tr = append(tr, base+0.3+rng.NormFloat64()*0.2)
	}
	b, err := PairedBootstrap(c, tr, 4000, 1, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	if b.CILo > 0.3 || b.CIHi < 0.3 || b.CILo <= 0 {
		t.Fatalf("CI [%.3f, %.3f] must cover 0.3 and exclude 0", b.CILo, b.CIHi)
	}
}
