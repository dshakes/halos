package rename

import "testing"

func TestComputeTotal(t *testing.T) {
	if got := ComputeTotal([]int{100, 100}, 10); got != 220 {
		t.Fatalf("got %d", got)
	}
	if got := OrderTotal([]int{50}); got != 55 {
		t.Fatalf("got %d", got)
	}
}
