package gateway

import (
	"sync"
	"time"
)

// Breaker is a per-key circuit breaker. After Threshold consecutive failures a
// key is open for Cooldown; then exactly one probe request is let through
// (half-open): success closes it, failure re-opens it for another Cooldown.
// Safe for concurrent use. Allow must be followed by Done or Cancel.
type Breaker struct {
	Threshold int           // consecutive failures that open the circuit (default 5)
	Cooldown  time.Duration // open time before a half-open probe (default 30s)

	now func() time.Time // test hook
	mu  sync.Mutex
	st  map[string]*breakerState
}

type breakerState struct {
	fails     int
	openUntil time.Time
	probing   bool
}

func (b *Breaker) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

func (b *Breaker) cfg() (int, time.Duration) {
	n, d := b.Threshold, b.Cooldown
	if n <= 0 {
		n = 5
	}
	if d <= 0 {
		d = 30 * time.Second
	}
	return n, d
}

// Allow reports whether a request may be sent to key now.
func (b *Breaker) Allow(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.st[key]
	n, _ := b.cfg()
	if s == nil || s.fails < n {
		return true
	}
	if b.clock().Before(s.openUntil) || s.probing {
		return false
	}
	s.probing = true
	return true
}

// Done records the outcome of an allowed request.
func (b *Breaker) Done(key string, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st == nil {
		b.st = map[string]*breakerState{}
	}
	s := b.st[key]
	if s == nil {
		s = &breakerState{}
		b.st[key] = s
	}
	s.probing = false
	n, d := b.cfg()
	if ok {
		s.fails = 0
		return
	}
	if s.fails++; s.fails >= n {
		s.openUntil = b.clock().Add(d)
	}
}

// Cancel releases an allowed request that never produced a verdict (the client
// went away), so a half-open probe slot is not leaked.
func (b *Breaker) Cancel(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.st[key]; s != nil {
		s.probing = false
	}
}

// State is "closed", "open" or "half-open" (an expired open circuit).
func (b *Breaker) State(key string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, _ := b.cfg()
	switch s := b.st[key]; {
	case s == nil || s.fails < n:
		return "closed"
	case b.clock().Before(s.openUntil):
		return "open"
	}
	return "half-open"
}
