package assign

import (
	"fmt"
	"math"
	"testing"
)

func TestBucketDeterministicAndInRange(t *testing.T) {
	for i := 0; i < 5000; i++ {
		u := fmt.Sprintf("user-%d", i)
		b := Bucket("salt", u)
		if b < 0 || b >= Buckets {
			t.Fatalf("bucket %d out of range", b)
		}
		if b != Bucket("salt", u) {
			t.Fatalf("bucket not deterministic for %s", u)
		}
	}
}

func TestBucketSaltIndependence(t *testing.T) {
	same := 0
	const n = 5000
	for i := 0; i < n; i++ {
		u := fmt.Sprintf("user-%d", i)
		if Bucket("s1", u) == Bucket("s2", u) {
			same++
		}
	}
	if same > n/100 { // expect ~n/10000
		t.Fatalf("salts look correlated: %d/%d equal buckets", same, n)
	}
}

func TestPick(t *testing.T) {
	tests := []struct {
		name    string
		weights []float64
		want    func(int) bool
	}{
		{"nil", nil, func(i int) bool { return i == -1 }},
		{"empty", []float64{}, func(i int) bool { return i == -1 }},
		{"all zero", []float64{0, 0}, func(i int) bool { return i == -1 }},
		{"all negative", []float64{-1, -2}, func(i int) bool { return i == -1 }},
		{"single", []float64{3}, func(i int) bool { return i == 0 }},
		{"zero weights never picked", []float64{0, 1, 0}, func(i int) bool { return i == 1 }},
		{"negative ignored", []float64{-5, 1}, func(i int) bool { return i == 1 }},
		{"trailing zero", []float64{1, 0}, func(i int) bool { return i == 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 500; i++ {
				if got := Pick("s", fmt.Sprintf("u%d", i), tt.weights); !tt.want(got) {
					t.Fatalf("Pick = %d", got)
				}
			}
		})
	}
}

// Known-answer vectors: a change to the hash would silently reshuffle every
// user's ring and variant. If this fails, the change is a fleet-wide
// re-assignment and needs to be deliberate.
func TestBucketKnownAnswers(t *testing.T) {
	for _, tc := range []struct {
		salt, subject string
		want          int
	}{
		{"halos/rings", "alice@example.com", 4417},
		{"halos/rings", "bob", 8577},
		{"exp-1", "alice@example.com", 5964},
		{"exp-1/shadow", "session-123", 6587},
		{"", "", 3192},
	} {
		if got := Bucket(tc.salt, tc.subject); got != tc.want {
			t.Errorf("Bucket(%q, %q) = %d, want %d", tc.salt, tc.subject, got, tc.want)
		}
	}
	for i, want := range []int{0, 1, 0, 2, 1} {
		if got := Pick("s", fmt.Sprintf("u%d", i), []float64{1, 1, 1}); got != want {
			t.Errorf("Pick(u%d) = %d, want %d", i, got, want)
		}
	}
}

func TestShare(t *testing.T) {
	for _, tc := range []struct {
		frac float64
		want int
	}{
		{0.57 / 100, 57}, // 56.99.. in float
		{0.0057, 57},
		{0.29 / 100, 29},
		{0.05, 500},
		{0, 0},
		{1, Buckets},
		{-0.1, 0},
		{1.5, Buckets},
	} {
		if got := Share(tc.frac); got != tc.want {
			t.Errorf("Share(%v) = %d, want %d", tc.frac, got, tc.want)
		}
	}
}

func TestPickDistribution(t *testing.T) {
	tests := []struct {
		name    string
		weights []float64
	}{
		{"even", []float64{1, 1}},
		{"skewed", []float64{95, 5}},
		{"unnormalised three", []float64{2, 3, 5}},
		{"with zero", []float64{1, 0, 3}},
	}
	const n = 100000
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts := make([]int, len(tt.weights))
			for i := 0; i < n; i++ {
				counts[Pick("dist", fmt.Sprintf("user-%d", i), tt.weights)]++
			}
			var total float64
			for _, w := range tt.weights {
				total += w
			}
			for i, w := range tt.weights {
				got, want := float64(counts[i])/n, w/total
				if math.Abs(got-want) > 0.005 {
					t.Errorf("variant %d share = %.4f, want %.4f ±0.005", i, got, want)
				}
			}
		})
	}
}
