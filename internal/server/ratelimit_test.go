package server

import (
	"io"
	"log/slog"
	"testing"
)

func TestAPILimiter(t *testing.T) {
	a := newAPILimiter(1, 3)
	for i := range 3 {
		if !a.allow("alice") {
			t.Fatalf("request %d within burst refused", i)
		}
	}
	if a.allow("alice") {
		t.Fatal("request past burst allowed")
	}
	if !a.allow("bob") {
		t.Fatal("one principal's budget throttled another")
	}
	off := newAPILimiter(0, 0)
	for range 10 {
		if !off.allow("x") {
			t.Fatal("rate 0 must not limit")
		}
	}
}

func TestAPIRateLimitHTTP(t *testing.T) {
	s, err := New(Config{
		PolicyDir: "../../examples/acme-corp", Token: tok,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DevUser: "admin@test", DevAdmin: true, APIRate: 0.001, APIBurst: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	for i := range 2 {
		if c := do(h, "GET", "/api/v1/me", "", "").Code; c != 200 {
			t.Fatalf("request %d: %d", i, c)
		}
	}
	w := do(h, "GET", "/api/v1/me", "", "")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("past burst: %d retry-after=%q", w.Code, w.Header().Get("Retry-After"))
	}
	// Fleet devices authenticate separately and are not charged to console budgets.
	if c := do(h, "POST", "/api/v1/fleet/report", "Bearer "+tok, report("h1", "ga", "2.1.0", false)).Code; c != 204 {
		t.Fatalf("fleet report throttled: %d", c)
	}
}
