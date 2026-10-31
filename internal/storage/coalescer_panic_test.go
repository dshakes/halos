package storage

import (
	"testing"
	"time"
)

// A panicking run propagates its panic (not a fatal unlock of an unlocked
// mutex) and leaves the Coalescer usable.
func TestCoalescerPanickingRun(t *testing.T) {
	var c Coalescer
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("recovered %v, want the run's panic", r)
			}
		}()
		_ = c.Do(func() error { panic("boom") })
		t.Fatal("Do returned after a panicking run")
	}()

	done := make(chan error, 1)
	go func() { done <- c.Do(func() error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("next run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("next Do hung: running stayed set after the panic")
	}
}
