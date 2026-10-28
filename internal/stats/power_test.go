package stats

import (
	"math"
	"testing"
)

func TestSampleSize(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		sd, mde, alpha, power float64
		want                  int
		wantErr               bool
	}{
		// textbook: d = 0.2 at 5%/80% needs 393 per arm
		{"small effect", 1, 0.2, 0.05, 0.8, 393, false},
		{"medium effect", 1, 0.5, 0.05, 0.8, 63, false},
		{"90% power", 1, 0.5, 0.05, 0.9, 85, false},
		// rate p=0.3, +10% relative: sd = sqrt(.21), delta = .03
		{"rate", math.Sqrt(0.21), 0.03, 0.05, 0.8, 3663, false},
		{"zero sd", 0, 0.1, 0.05, 0.8, 0, true},
		{"zero mde", 1, 0, 0.05, 0.8, 0, true},
		{"alpha 1", 1, 0.1, 1, 0.8, 0, true},
		{"power 1", 1, 0.1, 0.05, 1, 0, true},
		{"nan sd", math.NaN(), 0.1, 0.05, 0.8, 0, true},
		{"overflow", 1, 1e-9, 0.05, 0.8, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := SampleSize(tc.sd, tc.mde, tc.alpha, tc.power)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if n != tc.want {
				t.Fatalf("n = %d, want %d", n, tc.want)
			}
			if err == nil {
				d, err := MDE(n, tc.sd, tc.alpha, tc.power)
				if err != nil || d > tc.mde || d < tc.mde*0.99 {
					t.Fatalf("MDE(%d) = %v, %v; want just under %v", n, d, err, tc.mde)
				}
			}
		})
	}
	if _, err := MDE(1, 1, 0.05, 0.8); err == nil {
		t.Fatal("MDE with n=1 must fail")
	}
	if q := NormalQuantile(0.975); math.Abs(q-1.959964) > 1e-6 {
		t.Fatalf("z(.975) = %v", q)
	}
}
