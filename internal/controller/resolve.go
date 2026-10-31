package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
)

// All-clears. A sink that opted into "resolved" (PagerDuty by default, the
// generic webhook on request) is told when a condition it was told about is
// over, so an incident closes without anyone remembering to close it:
//
//   - experiment rollback: the experiment left "running" (a human merged the
//     pause PR);
//   - experiment or rollout killed: the kill was lifted, or the experiment
//     or rollout left its running state;
//   - rollout rollback/pause: the rollout left "active" in policy (a human
//     merged the pause or rollback) or a human moved it to another step.
//
// An all-clear is sent only for a condition this channel was actually told
// about, once, and is best effort: the controller's own state (reset an
// experiment, sync a rollout) never waits on a notification, so an all-clear
// that fails after the sink's retries is logged and counted
// (halo_controller_notifications_total{result="error"}), not retried; the
// incident then has to be closed by hand.

// resolveBy is the reason carried on an all-clear.
const (
	resolveLeftRunning = "the experiment left running (a human merged the pause or conclusion)"
	resolveUnkilled    = "the kill switch was lifted"
	resolveInactive    = "the rollout left active in policy (a human merged the pause or rollback)"
	resolveStepMoved   = "a human moved the rollout to another step"
)

var (
	experimentPaging = []promote.Verdict{promote.Rollback, VerdictKilled}
	rolloutPaging    = []promote.Verdict{promote.Rollback, promote.Verdict(rollout.Pause), VerdictKilled}
)

// resolveExperiment sends exp's all-clear for each of verdicts that a channel
// announced and has not yet cleared.
func (c *Controller) resolveExperiment(ctx context.Context, exp, why string, verdicts ...promote.Verdict) error {
	names, ns := channels(c.Notifier)
	var errs []error
	for i, n := range ns {
		rs, ok := n.(resolver)
		if !ok {
			continue
		}
		action := ActionNotify + ":" + names[i]
		for _, v := range verdicts {
			if !rs.ResolvesFor(Event{Experiment: exp, Verdict: v}) {
				continue
			}
			if _, opened := c.State.Done(exp, string(v), action); !opened {
				continue
			}
			rv := "resolved:" + string(v)
			if _, cleared := c.State.Done(exp, rv, action); cleared {
				continue
			}
			key, _, ierr := c.intend(exp, rv, action)
			if fenced(ierr) {
				return errors.Join(append(errs, ierr)...)
			}
			errs = append(errs, ierr)
			ev := Event{ID: key, Experiment: exp, Verdict: v, Resolved: true, Reason: why, At: c.now().UTC()}
			if err := n.Notify(ctx, ev); err != nil {
				errs = append(errs, c.fail(fmt.Errorf("controller: resolve %s (%s) via %s: %w", exp, v, names[i], err)))
				continue
			}
			errs = append(errs, c.recordDone(exp, rv, action))
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) recordDone(exp, verdict, action string) error {
	if err := c.State.Record(exp, verdict, action, "", c.now()); err != nil {
		return c.fail(err)
	}
	return nil
}

// rolloutResolve sends the all-clears due for r. It must run before
// State.Sync, which forgets what the controller did at the old step. changed
// reports whether st was modified (the caller must save it).
func (c *Controller) rolloutResolve(ctx context.Context, r *policy.Rollout, st *rollout.State, persist func() error) (changed bool, _ error) {
	names, ns := channels(c.Notifier)
	inactive := r.EffectiveStatus() != policy.RolloutActive
	moved := r.StepIndex(r.Step) != st.Step
	var errs []error
	for i, n := range ns {
		rs, ok := n.(resolver)
		if !ok {
			continue
		}
		for _, v := range rolloutPaging {
			if !rs.ResolvesFor(Event{Rollout: r.Name, Verdict: v}) {
				continue
			}
			opened := "notify:" + string(v) + ":" + names[i]
			cleared := "notify:resolved:" + string(v) + ":" + names[i]
			if _, ok := st.Did(opened); !ok {
				continue
			}
			if _, ok := st.Did(cleared); ok {
				continue
			}
			var why string
			switch {
			case inactive:
				why = resolveInactive
			case moved:
				why = resolveStepMoved
			case v == VerdictKilled && r.Experiment != "":
				if k, err := c.killed(r.Experiment); err == nil && !k {
					why = resolveUnkilled
				}
			}
			if why == "" {
				continue
			}
			key, _, ierr := c.rolloutIntend(st, persist, cleared)
			if fenced(ierr) {
				return changed, errors.Join(append(errs, ierr)...)
			}
			errs = append(errs, ierr)
			changed = true // the intent is recorded in st
			ev := Event{ID: key, Rollout: r.Name, Experiment: r.Experiment, Axis: string(r.Axis), Verdict: v, Resolved: true, Reason: why, At: c.now().UTC()}
			if err := n.Notify(ctx, ev); err != nil {
				errs = append(errs, c.fail(fmt.Errorf("controller: resolve rollout %s (%s) via %s: %w", r.Name, v, names[i], err)))
				continue
			}
			st.Mark(cleared, "", c.now())
			changed = true
		}
	}
	return changed, errors.Join(errs...)
}
