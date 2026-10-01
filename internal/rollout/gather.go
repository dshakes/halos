package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// GateExperiment is exp as step s's gates see it: the step's guardrails and
// minSamples replace the experiment's own, and budgets are dropped (a rollout
// does not expire), so promote.EvaluateAt reports exactly the step's evidence.
func GateExperiment(exp *policy.Experiment, s policy.RolloutStep) *policy.Experiment {
	c := *exp
	c.Metrics.Guardrails = s.Gates.Guardrails
	c.Stopping.MinSamples = s.MinSamples
	c.Stopping.MaxDays, c.Stopping.MaxSpendUSD = 0, 0
	return &c
}

// NeedsMetrics reports whether step s is judged on experiment evidence.
func NeedsMetrics(s policy.RolloutStep) bool { return s.MinSamples > 0 || len(s.Gates.Guardrails) > 0 }

// Gather collects the live step's evidence: the backing experiment from
// metrics (nil = none; only queried when the step has metric gates) and the
// scorecard file under dir. A metrics error is returned; a missing or bad
// scorecard is reported in the evidence (the gate stays pending).
func Gather(ctx context.Context, dir string, org *policy.Org, r *policy.Rollout, st State, metrics promote.MetricSource, now time.Time) (Evidence, error) {
	var ev Evidence
	if st.Step < 0 || st.Step >= len(r.Steps) {
		return ev, nil
	}
	s := r.Steps[st.Step]
	if metrics != nil && NeedsMetrics(s) {
		exp := findExp(org, r.Experiment)
		if exp == nil {
			return ev, fmt.Errorf("rollout %s: experiment %q not found", r.Name, r.Experiment)
		}
		rep, err := promote.EvaluateAt(ctx, GateExperiment(exp, s), metrics, now)
		if err != nil {
			return ev, fmt.Errorf("rollout %s: evidence: %w", r.Name, err)
		}
		ev.Report = &rep
	}
	if sc := s.Gates.Scorecard; sc != nil {
		card, err := LoadScorecard(dir, sc.File)
		if err != nil {
			ev.ScorecardErr = err.Error()
		}
		ev.Scorecard = card
	}
	return ev, nil
}

// LoadScorecard reads a `halo eval run --output json` scorecard at rel inside dir.
func LoadScorecard(dir, rel string) (*eval.Scorecard, error) {
	c := path.Clean(filepath.ToSlash(rel))
	if path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return nil, fmt.Errorf("scorecard %q escapes the policy dir", rel)
	}
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(c)))
	if err != nil {
		return nil, fmt.Errorf("scorecard: %w", err)
	}
	var sc eval.Scorecard
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("scorecard %s: %w", rel, err)
	}
	return &sc, nil
}
