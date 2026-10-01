package rollout

import (
	"fmt"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// PolicyState is the state implied by the policy alone (no controller state
// file): the live step, with an unknown entry time.
func PolicyState(r *policy.Rollout) State {
	st := NewState(r.Name)
	if i := r.StepIndex(r.Step); i >= 0 {
		st.Step, st.StepName = i, r.Step
	}
	return st
}

// NextAction is what a human advance proposes from r's live step: the next
// step, or completion after the last.
func NextAction(r *policy.Rollout) (Action, int) {
	i := r.StepIndex(r.Step)
	if i == len(r.Steps)-1 {
		return Complete, -1
	}
	return Advance, i + 1
}

// Title is the PR title for act.
func Title(r *policy.Rollout, act Action, next int) string {
	switch act {
	case Advance:
		s := r.Steps[next]
		return fmt.Sprintf("Rollout %s: advance to %s (%s, %g%%)", r.Name, s.Name, s.Strategy, s.EffectivePercent())
	case Complete:
		return fmt.Sprintf("Rollout %s: complete", r.Name)
	case Rollback:
		return fmt.Sprintf("Rollout %s: roll back", r.Name)
	default:
		return fmt.Sprintf("Rollout %s: %s", r.Name, act)
	}
}

// Branch is the PR branch for act.
func Branch(r *policy.Rollout, act Action, next int) string {
	if act == Advance {
		return "halos/rollout-" + r.Name + "-" + r.Steps[next].Name
	}
	return "halos/rollout-" + r.Name + "-" + string(act)
}

// Body renders a PR body: intro, the gate table of d, manual steps and the
// diff. Halos never merges it.
func Body(intro string, d Decision, manual []string, patch string) string {
	var b strings.Builder
	b.WriteString(intro + "\n\n")
	if len(d.Gates) > 0 {
		b.WriteString("| Gate | Status | Value | Threshold |\n|---|---|---|---|\n")
		for _, g := range d.Gates {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", g.Gate, g.Status, g.Value, g.Threshold)
		}
		b.WriteString("\n")
	}
	for _, r := range d.Reasons {
		b.WriteString("- " + r + "\n")
	}
	for _, m := range manual {
		b.WriteString("\n**Manual step before merging:** " + m + "\n")
	}
	b.WriteString("\n```diff\n" + patch + "```\n\nOpened by Halos; a human must review and merge.\n")
	return b.String()
}
