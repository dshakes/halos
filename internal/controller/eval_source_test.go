package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/promote"
)

// Invariant: eval-sourced evidence (`halo eval online` judge scores) is
// trusted for verdicts and PRs but NEVER trips the kill switch; only gateway
// evidence does. Covers both the experiment loop and rollouts.
func TestEvalEvidenceNeverKills(t *testing.T) {
	t.Run("experiment", func(t *testing.T) {
		r := newRig(t, promote.Rollback)
		r.c.Metrics.(*promote.MemorySource).Source = promote.SourceEval
		for range 2 {
			if err := r.c.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if got := r.killed(t); len(got) != 0 {
			t.Fatalf("killed on eval evidence: %v", got)
		}
		if len(r.w.calls) != 1 || r.w.calls[0].status != "paused" {
			t.Fatalf("eval evidence must still open the pause PR: %+v", r.w.calls)
		}
		ev := r.n.events
		if len(ev) != 1 || ev[0].Killed || ev[0].KillOutcome != KillNotGateway || !strings.Contains(ev[0].KillError, `"eval"-sourced`) ||
			!strings.Contains(ev[0].Text(), "non-gateway (CLI or eval) evidence") {
			t.Fatalf("events = %+v", ev)
		}
	})
	t.Run("rollout", func(t *testing.T) {
		r, w, _ := rolloutRig(t, promote.Rollback, "c5")
		r.c.Metrics.(*promote.MemorySource).Source = promote.SourceEval
		ticks(t, r.c, 2)
		if got := r.killed(t); len(got) != 0 {
			t.Fatalf("killed on eval evidence: %v", got)
		}
		if len(w.prs) != 1 || len(r.n.events) != 1 || r.n.events[0].KillOutcome != KillNotGateway {
			t.Fatalf("prs=%+v events=%+v", w.prs, r.n.events)
		}
	})
	t.Run("gateway still kills", func(t *testing.T) { // control: the rig does kill on gateway evidence
		r := newRig(t, promote.Rollback)
		if err := r.c.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := r.killed(t); len(got) != 1 {
			t.Fatalf("gateway evidence must kill: %v", got)
		}
	})
}
