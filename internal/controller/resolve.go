package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
//
// Deletion. A name removed from policy while an incident is open would never
// be visited again, so the incident would stay paged forever. Each tick
// therefore looks for tracked names missing from the loaded policy: every
// experiment with controller state, and every rollout that announced a paging
// condition (recorded under "rollout:<name>" in the state log, since rollout
// state has no index). It sends the all-clear (reason resolveDeleted) to each
// sink that opened an incident, once, then drops the state, even when the
// all-clear failed (same best-effort rule). Only names the controller tracked
// are handled: a policy that fails to load never reaches this code.

// resolveBy is the reason carried on an all-clear.
const (
	resolveLeftRunning = "the experiment left running (a human merged the pause or conclusion)"
	resolveUnkilled    = "the kill switch was lifted"
	resolveInactive    = "the rollout left active in policy (a human merged the pause or rollback)"
	resolveStepMoved   = "a human moved the rollout to another step"
	resolveDeleted     = "the experiment or rollout was deleted from policy"
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
	return c.rolloutResolveWhy(ctx, r, st, persist, "")
}

// rolloutResolveWhy is rolloutResolve with a fixed reason (deleted rollouts).
func (c *Controller) rolloutResolveWhy(ctx context.Context, r *policy.Rollout, st *rollout.State, persist func() error, fixed string) (changed bool, _ error) {
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
			why := fixed
			switch {
			case why != "":
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

// rolloutTrack is the state-log name that remembers a rollout announced a
// paging condition, so its deletion from policy can be noticed.
const rolloutTrack = "rollout:"

// trackRollout records (once) that rollout name has an announced paging condition.
func (c *Controller) trackRollout(name string) error {
	if _, ok := c.State.Done(rolloutTrack+name, "tracked", "tracked"); ok {
		return nil
	}
	return c.recordDone(rolloutTrack+name, "tracked", "tracked")
}

// resolveDeleted clears incidents of experiments and rollouts that vanished
// from org, then drops their state (see the file comment).
func (c *Controller) resolveDeleted(ctx context.Context, org *policy.Org) error {
	live := map[string]bool{}
	for _, e := range org.Experiments {
		live[e.Name] = true
	}
	for _, r := range org.Rollouts {
		live[rolloutTrack+r.Name] = true
	}
	var errs []error
	for _, n := range c.State.Names() {
		if live[n] {
			continue
		}
		var err error
		if name, ok := strings.CutPrefix(n, rolloutTrack); ok {
			err = c.resolveDeletedRollout(ctx, name)
		} else {
			err = c.resolveExperiment(ctx, n, resolveDeleted, experimentPaging...)
		}
		if err != nil {
			errs = append(errs, err)
			if fenced(err) {
				return errors.Join(errs...)
			}
		}
		if err := c.State.Reset(n, c.now()); err != nil {
			errs = append(errs, c.fail(err))
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) resolveDeletedRollout(ctx context.Context, name string) error {
	store := c.rolloutStates()
	if store == nil {
		return nil
	}
	st, err := store.Load(ctx, name)
	if err != nil {
		return c.fail(fmt.Errorf("controller: deleted rollout %s: %w", name, err))
	}
	persist := func() error {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stateSaveTimeout)
		defer cancel()
		if err := store.Save(sctx, &st); err != nil {
			return c.fail(fmt.Errorf("controller: rollout %s: %w", name, err))
		}
		return nil
	}
	r := &policy.Rollout{Meta: policy.Meta{Name: name}, Status: policy.RolloutAborted}
	changed, rerr := c.rolloutResolveWhy(ctx, r, &st, persist, resolveDeleted)
	if changed {
		rerr = errors.Join(rerr, persist())
	}
	return rerr
}
