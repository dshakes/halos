package fixme

import "testing"

func TestMean(t *testing.T) {
	if got := Mean([]float64{1, 2, 3}); got != 2 {
		t.Fatalf("Mean = %v, want 2", got)
	}
	if got := Mean(nil); got != 0 {
		t.Fatalf("Mean(nil) = %v, want 0", got)
	}
}
