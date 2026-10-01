package promote

import (
	"context"
	"math/rand/v2"
	"testing"
	"time"
)

// peekRollbackRate runs sims experiments, evaluating after every added
// sample pair, and returns the fraction that ever return Rollback.
// The primary metric has no effect, so only the cost guardrail can roll back.
func peekRollbackRate(t *testing.T, sims, nMax int, costRatio float64) float64 {
	t.Helper()
	const sd = 1.0
	rolled := 0
	for s := 0; s < sims; s++ {
		rng := rand.New(rand.NewPCG(uint64(s), 7))
		e := exp()
		e.Stopping.MinSamples = 20
		e.Stopping.Method = "fixed" // keep the primary from deciding first
		e.Metrics.Guardrails[0].MaxRegression = 0.10
		succ := normals(rng, nMax, 0.6, 0.3)
		succT := normals(rng, nMax, 0.6, 0.3)
		cc := normals(rng, nMax, 5, sd)
		ct := normals(rng, nMax, 5*costRatio, sd)
		for n := 20; n <= nMax; n++ {
			src := &MemorySource{Data: map[string]map[string][]float64{
				"halo.task.success":         {"control": succ[:n], "candidate": succT[:n]},
				"halo.cost.usd_per_session": {"control": cc[:n], "candidate": ct[:n]},
			}}
			rep, err := EvaluateAt(context.Background(), e, src, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict == Rollback && len(rep.Guardrails) > 0 && rep.Guardrails[0].Result.Status == "fail" {
				rolled++
				break
			}
		}
	}
	return float64(rolled) / float64(sims)
}

func TestGuardrailPeekingFalseRollbackRate(t *testing.T) {
	const alpha = 0.05
	// Worst-case null: regression exactly at the limit (+10% cost), peeking every step.
	if r := peekRollbackRate(t, 500, 120, 1.10); r > alpha+0.03 {
		t.Errorf("false rollback rate at the limit = %.3f, want <= %.2f", r, alpha+0.03)
	}
	if r := peekRollbackRate(t, 500, 120, 1.0); r > alpha+0.03 {
		t.Errorf("false rollback rate with no regression = %.3f", r)
	}
}

func TestGuardrailPeekingDetectsRegression(t *testing.T) {
	if r := peekRollbackRate(t, 100, 250, 1.20); r < 0.9 {
		t.Errorf("+20%% cost detected in only %.2f of sims (limit 10%%)", r)
	}
}
