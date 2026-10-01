package controller

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
)

// RolloutWriter opens a rollout PR: plan builds the change in the writer's
// checkout dir, body renders the PR body around its patch. GitWriter and
// server.GitPolicyWriter implement it. It must never merge.
type RolloutWriter interface {
	ProposeRollout(ctx context.Context, plan func(dir string) (*promote.Change, error), branch, title string, body func(patch string) string) (prURL string, err error)
}

// ProposeRollout implements RolloutWriter on this checkout.
func (w *GitWriter) ProposeRollout(ctx context.Context, plan func(string) (*promote.Change, error), branch, title string, body func(string) string) (string, error) {
	dir := filepath.Join(w.RepoDir, w.Subdir)
	ch, err := plan(dir)
	if err != nil {
		return "", fmt.Errorf("rollout PR: %w", err)
	}
	if ch.Patch == "" {
		return "", fmt.Errorf("rollout PR %s: policy already has this change", branch)
	}
	url, err := w.Opener.OpenPR(ctx, promote.PRRequest{RepoDir: dir, Base: w.Base, Branch: branch, Title: title, Body: body(ch.Patch), Files: ch.Files, Edit: ch.Edit})
	if err != nil {
		return "", fmt.Errorf("rollout PR %s: %w", branch, err)
	}
	return url, nil
}

// tickRollouts drives every active rollout once. Like experiments, rollback
// and pause act automatically; advance and complete only open a PR.
func (c *Controller) tickRollouts(ctx context.Context, org *policy.Org) error {
	if c.RolloutStateDir == "" {
		return nil
	}
	rs := append([]*policy.Rollout(nil), org.Rollouts...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
	var errs []error
	for _, r := range rs {
		if err := ctx.Err(); err != nil {
			errs = append(errs, c.fail(fmt.Errorf("controller: tick deadline before rollout %s: %w", r.Name, err)))
			break
		}
		if err := c.rolloutStep(ctx, org, r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rolloutOwned reports whether exp backs an active rollout: the rollout, not
// the experiment loop, decides on it then.
func rolloutOwned(org *policy.Org, exp string) bool {
	for _, r := range org.Rollouts {
		if r.Experiment == exp && r.EffectiveStatus() == policy.RolloutActive {
			return true
		}
	}
	return false
}

func (c *Controller) rolloutStep(ctx context.Context, org *policy.Org, r *policy.Rollout) error {
	now := c.now()
	st, err := rollout.LoadState(c.RolloutStateDir, r.Name)
	if err != nil {
		// A state file that fails its hash chain is never acted on.
		return c.fail(fmt.Errorf("controller: rollout %s: %w", r.Name, err))
	}
	dirty := st.Sync(r, now)
	save := func(errs ...error) error {
		if err := st.Save(c.RolloutStateDir); err != nil {
			errs = append(errs, c.fail(fmt.Errorf("controller: rollout %s: %w", r.Name, err)))
		}
		return errors.Join(errs...)
	}
	if r.EffectiveStatus() != policy.RolloutActive {
		if dirty {
			return save()
		}
		return nil
	}
	if st.Halted == "" && r.Experiment != "" {
		if killed, err := c.killed(r.Experiment); err != nil {
			return save(c.fail(fmt.Errorf("controller: read kill switch for %s: %w", r.Experiment, err)))
		} else if killed {
			// Its evidence is all-control; humans unkill or roll back.
			d := rollout.Decision{Action: rollout.Hold, Step: st.Step, Next: -1,
				Reasons: []string{fmt.Sprintf("experiment %s is killed; unkill it or roll the rollout back (not evaluated while killed)", r.Experiment)}}
			st.Last, st.LastAt = &d, now
			return save(c.rolloutNotify(ctx, r, &st, Event{Verdict: VerdictKilled, Killed: true}, d))
		}
	}

	var d rollout.Decision
	if st.Halted != "" {
		// Finish the halt's pending actions from the recorded (hash-chained)
		// halt event; never re-evaluate, never trust the display-only Last.
		d = rollout.Decision{Action: rollout.Action(st.Halted), Step: st.Step, Next: -1, Reasons: []string{st.HaltReason}, Source: st.HaltSource}
	} else {
		ev, err := rollout.Gather(ctx, c.PolicyDir, org, r, st, c.Metrics, now)
		if err != nil {
			return save(c.fail(fmt.Errorf("controller: %w", err)))
		}
		d = rollout.Evaluate(rollout.Effective(org, r), st, ev, now)
		st.Last, st.LastAt = &d, now
		c.log().Info("rollout evaluated", "rollout", r.Name, "step", st.StepName, "action", d.Action, "reasons", strings.Join(d.Reasons, "; "))
	}

	switch d.Action {
	case rollout.Rollback, rollout.Pause:
		if st.Halted == "" {
			st.Halt(string(d.Action), d.Source, strings.Join(d.Reasons, "; "), now)
			if err := save(); err != nil { // the halt must stick before anything else happens
				return err
			}
		}
		return save(c.rolloutHalt(ctx, org, r, &st, d))
	case rollout.Advance, rollout.Complete:
		return save(c.rolloutPropose(ctx, org, r, &st, d))
	default:
		if d.AwaitingApproval {
			return save(c.rolloutNotify(ctx, r, &st, Event{Verdict: "awaiting_approval"}, d))
		}
		return save()
	}
}

// rolloutHalt: kill switch first (traffic axis, gateway evidence only), then
// the PR, then notify; humans are told even if the kill or PR failed.
func (c *Controller) rolloutHalt(ctx context.Context, org *policy.Org, r *policy.Rollout, st *rollout.State, d rollout.Decision) error {
	var errs []error
	ev := Event{Verdict: promote.Verdict(d.Action)}
	if d.Action == rollout.Rollback && r.Axis == policy.AxisTraffic && r.Experiment != "" {
		reason := fmt.Sprintf("rollout %s rollback: %s", r.Name, strings.Join(d.Reasons, "; "))
		switch det, done := st.Did("kill"); {
		case done:
			ev.Killed, ev.KillError = det == "", det
			ev.KillOutcome = killOutcome(ev.Killed)
		case d.Source != promote.SourceGateway:
			ev.KillOutcome = KillNotGateway
			ev.KillError = fmt.Sprintf("not auto-killed: the deciding evidence is %q-sourced; only gateway-sourced evidence may trip the kill switch", d.Source)
		case c.Kill == nil:
			ev.KillOutcome, ev.KillError = KillNotConfigured, "kill switch not configured — rollback requires merging the PR"
			c.log().Error("ROLLOUT ROLLBACK NOT ENFORCED: kill switch not configured", "rollout", r.Name)
		default:
			if _, err := c.Kill.Kill(ctx, r.Experiment, Actor, reason); err != nil {
				ev.KillOutcome, ev.KillError = KillFailed, err.Error()
				errs = append(errs, c.fail(fmt.Errorf("controller: kill %s for rollout %s: %w", r.Experiment, r.Name, err)))
			} else {
				ev.Killed, ev.KillError = c.KillCaveat == "", c.KillCaveat
				ev.KillOutcome = killOutcome(ev.Killed)
				st.Mark("kill", c.KillCaveat, c.now())
				c.log().Warn("kill switch tripped for rollout", "rollout", r.Name, "experiment", r.Experiment, "caveat", c.KillCaveat)
			}
		}
	}
	intro := fmt.Sprintf("Automated **%s** of rollout `%s` at step `%s`: a gate failed.", d.Action, r.Name, st.StepName)
	if ev.Killed {
		intro += fmt.Sprintf(" The kill switch for experiment `%s` was tripped, so gateways already route everyone to control; merging makes it permanent in policy.", r.Experiment)
	} else if d.Action == rollout.Rollback {
		intro += " **Merge urgently**: exposure continues until this merges and ships."
	}
	url, err := c.rolloutPR(ctx, org, r, st, d.Action, -1, intro, d)
	ev.PRURL = url
	if err != nil {
		ev.PRError = "PR failed"
		errs = append(errs, err)
	}
	errs = append(errs, c.rolloutNotify(ctx, r, st, ev, d))
	return errors.Join(errs...)
}

// rolloutPropose opens the advance/complete PR once per step, then notifies
// with its URL; a failed PR is retried next tick before anyone is told.
func (c *Controller) rolloutPropose(ctx context.Context, org *policy.Org, r *policy.Rollout, st *rollout.State, d rollout.Decision) error {
	intro := fmt.Sprintf("Automated proposal: rollout `%s` passed every gate of step `%s`. Merging moves it on; the controller never merges.", r.Name, st.StepName)
	if st.Step < 0 {
		intro = fmt.Sprintf("Automated proposal: start rollout `%s` with step `%s`.", r.Name, r.Steps[0].Name)
	}
	url, err := c.rolloutPR(ctx, org, r, st, d.Action, d.Next, intro, d)
	if err != nil {
		return err
	}
	return c.rolloutNotify(ctx, r, st, Event{Verdict: promote.Verdict(d.Action), PRURL: url}, d)
}

// rolloutPR opens act's PR once per step; later ticks return the recorded URL.
func (c *Controller) rolloutPR(ctx context.Context, org *policy.Org, r *policy.Rollout, st *rollout.State, act rollout.Action, next int, intro string, d rollout.Decision) (string, error) {
	key := "pr:" + string(act)
	if url, done := st.Did(key); done {
		return url, nil
	}
	w, ok := c.Writer.(RolloutWriter)
	if !ok {
		c.log().Warn("no rollout PR writer configured; not opening a PR", "rollout", r.Name, "action", act)
		return "", nil
	}
	manual := rollout.ManualSteps(org, r, act)
	url, err := w.ProposeRollout(ctx, func(dir string) (*promote.Change, error) { return rollout.Plan(dir, org, r, act, next) },
		rollout.Branch(r, act, next), rollout.Title(r, act, next),
		func(patch string) string { return rollout.Body(intro, d, manual, patch) })
	if err != nil {
		return "", c.fail(fmt.Errorf("controller: rollout %s %s PR: %w", r.Name, act, err))
	}
	c.log().Info("controller opened rollout PR", "rollout", r.Name, "action", act, "pr", url)
	st.Mark(key, url, c.now())
	return url, nil
}

// rolloutNotify delivers ev once per channel per step and verdict.
func (c *Controller) rolloutNotify(ctx context.Context, r *policy.Rollout, st *rollout.State, ev Event, d rollout.Decision) error {
	ev.Rollout, ev.Experiment, ev.Axis, ev.Reason, ev.At = r.Name, r.Experiment, string(r.Axis), strings.Join(d.Reasons, "; "), c.now().UTC()
	names, ns := channels(c.Notifier)
	var errs []error
	for i, n := range ns {
		key := "notify:" + string(ev.Verdict) + ":" + names[i]
		if _, done := st.Did(key); done {
			continue
		}
		if err := n.Notify(ctx, ev); err != nil {
			errs = append(errs, c.fail(fmt.Errorf("controller: notify rollout %s (%s) via %s: %w", r.Name, ev.Verdict, names[i], err)))
			continue
		}
		st.Mark(key, "", c.now())
	}
	return errors.Join(errs...)
}
