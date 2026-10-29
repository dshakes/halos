package stats

import (
	"math"
	"testing"
)

func TestGammaQChiSquareCriticalValues(t *testing.T) {
	for _, tc := range []struct {
		df, x, want float64
	}{
		{1, 3.841459, 0.05},
		{2, 5.991465, 0.05},
		{3, 7.814728, 0.05},
		{1, 10.827566, 0.001},
		{10, 18.307038, 0.05},
		{1, 0, 1},
	} {
		if got := gammaQ(tc.df/2, tc.x/2); math.Abs(got-tc.want) > 1e-5 {
			t.Errorf("chi2 sf(%g, df=%g) = %.6f, want %.6f", tc.x, tc.df, got, tc.want)
		}
	}
}

func TestSRM(t *testing.T) {
	tests := []struct {
		name     string
		obs      []int
		w        []float64
		mismatch bool
		wantErr  bool
	}{
		{"balanced 50/50", []int{1003, 997}, []float64{50, 50}, false, false},
		{"lost treatment units", []int{1000, 850}, []float64{50, 50}, true, false},
		{"90/10 as configured", []int{901, 99}, []float64{90, 10}, false, false},
		{"90/10 served 50/50", []int{500, 500}, []float64{90, 10}, true, false},
		{"three arms", []int{340, 330, 330}, []float64{1, 1, 1}, false, false},
		{"length mismatch", []int{1, 2}, []float64{1}, false, true},
		{"zero weight", []int{1, 2}, []float64{1, 0}, false, true},
		{"no units", []int{0, 0}, []float64{1, 1}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := SRM(tc.obs, tc.w, 0.001)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && r.Mismatch != tc.mismatch {
				t.Fatalf("mismatch = %v (chi2 %.2f p %.2g), want %v", r.Mismatch, r.Chi2, r.PValue, tc.mismatch)
			}
		})
	}
}

func TestClusterBootstrapDiff(t *testing.T) {
	// 40 clusters per arm, 5 observations each; treatment lowers the mean by 2.
	mk := func(base float64, off int) []Cluster {
		var cs []Cluster
		for i := range 40 {
			sum := 0.0
			for j := range 5 {
				sum += base + float64((i*7+j*3+off)%9) - 4 // mean-zero noise
			}
			cs = append(cs, Cluster{Num: sum, Den: 5})
		}
		return cs
	}
	c, tr := mk(10, 0), mk(8, 0)
	r, err := ClusterBootstrapDiff(c, tr, 2000, 1, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(r.Effect+2) > 1e-9 || r.CILo > -2 || r.CIHi < -2 || r.CIHi >= 0 {
		t.Fatalf("effect %.3f CI [%.3f, %.3f]: want -2 inside a CI that excludes 0", r.Effect, r.CILo, r.CIHi)
	}
	if math.Abs(r.Rel+0.2) > 0.01 || r.RelCILo > -0.2 || r.RelCIHi < -0.2 {
		t.Fatalf("relative %.3f CI [%.3f, %.3f]: want -0.2 inside", r.Rel, r.RelCILo, r.RelCIHi)
	}
	if r.SE <= 0 || r.NC != 40 || r.NT != 40 {
		t.Fatalf("SE %.4f n %d/%d", r.SE, r.NC, r.NT)
	}
	if again, _ := ClusterBootstrapDiff(c, tr, 2000, 1, 0.05); again != r {
		t.Fatal("not deterministic for a seed")
	}
	for name, args := range map[string][2][]Cluster{
		"empty arm": {nil, tr},
		"zero den":  {{{Num: 1, Den: 0}}, tr},
	} {
		if _, err := ClusterBootstrapDiff(args[0], args[1], 100, 1, 0.05); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
