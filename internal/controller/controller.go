// Package controller is the automated experiment loop: every tick it
// evaluates each running experiment (promote.Evaluate), persists the verdict
// for halo-server, and acts on it.
//
//   - rollback: trip the traffic-plane kill switch immediately, open a PR
//     setting status: paused with the evidence, notify.
//   - promote: open a PR concluding the experiment (never merged), notify.
//   - expired: open a PR concluding the experiment, notify.
//
// Every action is taken at most once per experiment run (StateLog), so
// repeated ticks never duplicate PRs or notifications. Nothing here merges.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// Actor is the identity the controller records on kills and audit entries.
const Actor = "halo-controller"

// Controller wires the loop. Org, Metrics and State are required.
type Controller struct {
	Org     func() (*policy.Org, error) // e.g. policy.Load of the served policy dir
	Metrics promote.MetricSource
	Writer  Writer     // nil: no PRs (logged)
	Kill    KillSwitch // nil: rollbacks are not enforced until the PR merges (logged, notified)
	// KillCaveat, when set, is why a successful Kill is not known to be
	// enforced by gateways (e.g. `halo controller run` without
	// --killswitch-served); messages report it instead of claiming enforcement.
	KillCaveat string
	// Kills is read each tick: a killed running experiment is not evaluated
	// (its evidence is all-control) and humans are told once. nil = no check.
	Kills        *KillStore
	Notifier     Notifier // nil: none
	State        *StateLog
	VerdictsPath string // "" = do not persist verdicts
	Clock        func() time.Time
	Log          *slog.Logger
	TickTimeout  time.Duration // default 2m; bounds one whole tick

	// RolloutStateDir holds one hash-chained state file per Rollout ("" =
	// rollouts are not driven); PolicyDir is where step scorecards are read.
	RolloutStateDir, PolicyDir string

	ticks, errs atomic.Uint64
	vmu         sync.Mutex
	verdicts    map[promote.Verdict]uint64
}

// DefaultTickTimeout bounds one tick (all experiments).
const DefaultTickTimeout = 2 * time.Minute

func (c *Controller) now() time.Time {
	if c.Clock != nil {
		return c.Clock()
	}
	return time.Now()
}

func (c *Controller) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

func (c *Controller) fail(err error) error {
	c.errs.Add(1)
	return err
}

// Tick evaluates every running experiment once and acts on the verdicts,
// then drives active rollouts (see tickRollouts). Per-experiment failures
// don't stop the others; all are joined in the result.
func (c *Controller) Tick(ctx context.Context) error {
	c.ticks.Add(1)
	d := c.TickTimeout
	if d <= 0 {
		d = DefaultTickTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	org, err := c.Org()
	if err != nil {
		return c.fail(fmt.Errorf("controller: load policy: %w", err))
	}
	exps := append([]*policy.Experiment(nil), org.Experiments...)
	sort.Slice(exps, func(i, j int) bool { return exps[i].Name < exps[j].Name })
	var errs []error
	for _, e := range exps {
		if err := ctx.Err(); err != nil {
			errs = append(errs, c.fail(fmt.Errorf("controller: tick deadline before %s: %w", e.Name, err)))
			break
		}
		if e.Status != "running" {
			// A human merged the pause/conclude (or never started it): the
			// next run of this experiment starts with a clean slate.
			if err := c.State.Reset(e.Name, c.now()); err != nil {
				errs = append(errs, c.fail(err))
			}
			continue
		}
		if rolloutOwned(org, e.Name) {
			continue // an active Rollout drives its backing experiment
		}
		if err := c.step(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, c.tickRollouts(ctx, org))
	return errors.Join(errs...)
}

func (c *Controller) step(ctx context.Context, e *policy.Experiment) error {
	// Rolled back in this run: never re-evaluate (a later promote verdict must
	// not conclude it); only finish pending rollback actions from the recorded
	// evidence. Cleared when the experiment leaves "running".
	if d, done := c.State.Done(e.Name, string(promote.Rollback), ActionRollback); done {
		return c.rollback(ctx, e, decodeReport(d))
	}
	if killed, err := c.killed(e.Name); err != nil {
		return c.fail(fmt.Errorf("controller: read kill switch for %s: %w", e.Name, err))
	} else if killed {
		return c.hold(ctx, e)
	}
	now := c.now()
	rep, err := promote.EvaluateAt(ctx, e, c.Metrics, now)
	if err != nil {
		return c.fail(fmt.Errorf("controller: evaluate %s: %w", e.Name, err))
	}
	c.vmu.Lock()
	if c.verdicts == nil {
		c.verdicts = map[promote.Verdict]uint64{}
	}
	c.verdicts[rep.Verdict]++
	c.vmu.Unlock()
	c.log().Info("experiment evaluated", "experiment", e.Name, "verdict", rep.Verdict, "reason", rep.Reason,
		"n_control", rep.NControl, "n_treatment", rep.NTreatment)

	var errs []error
	if c.VerdictsPath != "" {
		if err := promote.UpsertVerdict(c.VerdictsPath, e.Name, rep, now.UTC()); err != nil {
			errs = append(errs, c.fail(fmt.Errorf("controller: %w", err)))
		}
	}
	switch rep.Verdict {
	case promote.Rollback:
		errs = append(errs, c.record(e, rep.Verdict, ActionRollback, encodeReport(rep)), c.rollback(ctx, e, rep))
	case promote.Promote, promote.Expired:
		errs = append(errs, c.conclude(ctx, e, rep))
	}
	return errors.Join(errs...)
}

func (c *Controller) record(e *policy.Experiment, v promote.Verdict, action, detail string) error {
	if err := c.State.Record(e.Name, string(v), action, detail, c.now()); err != nil {
		return c.fail(err)
	}
	return nil
}

func killOutcome(enforced bool) KillOutcome {
	if enforced {
		return KillEnforced
	}
	return KillRecorded
}

// rollback: kill first (instant, no merge), then PR, then notify. The
// notification goes out even if the kill or PR failed: humans must know.
func (c *Controller) rollback(ctx context.Context, e *policy.Experiment, rep promote.Report) error {
	v := rep.Verdict
	var errs []error
	ev := Event{Experiment: e.Name, Axis: string(e.Axis), Verdict: v, Reason: rep.Reason, Report: rep, At: c.now().UTC()}

	recorded := false // kill written but not known to be enforced (KillCaveat)
	if d, done := c.State.Done(e.Name, string(v), ActionKill); done {
		ev.Killed, ev.KillError, recorded = d == "", d, d != ""
		ev.KillOutcome = killOutcome(ev.Killed)
	} else if rep.Source != promote.SourceGateway {
		// Only the authenticated gateway receiver's evidence may auto-kill: CLI
		// telemetry is client-controlled (anyone who can reach the collector can
		// forge it), so it opens the pause PR and notifies, and a human decides.
		ev.KillOutcome = KillNotGateway
		ev.KillError = fmt.Sprintf("not auto-killed: the deciding evidence is %q-sourced (client-controlled telemetry); only gateway-sourced evidence may trip the kill switch", rep.Source)
		c.log().Warn("rollback verdict on non-gateway evidence; kill switch not tripped", "experiment", e.Name, "source", rep.Source, "reason", rep.Reason)
	} else if c.Kill == nil {
		ev.KillOutcome = KillNotConfigured
		ev.KillError = "kill switch not configured — rollback requires merging the pause PR"
		c.log().Error("ROLLBACK NOT ENFORCED: kill switch not configured; traffic keeps flowing to the treatment until the pause PR merges", "experiment", e.Name)
	} else if _, err := c.Kill.Kill(ctx, e.Name, Actor, "rollback: "+rep.Reason); err != nil {
		ev.KillOutcome, ev.KillError = KillFailed, err.Error()
		errs = append(errs, c.fail(fmt.Errorf("controller: kill %s: %w", e.Name, err)))
	} else {
		ev.Killed, ev.KillError, recorded = c.KillCaveat == "", c.KillCaveat, c.KillCaveat != ""
		ev.KillOutcome = killOutcome(ev.Killed)
		c.log().Warn("kill switch tripped", "experiment", e.Name, "reason", rep.Reason, "caveat", c.KillCaveat)
		errs = append(errs, c.record(e, v, ActionKill, c.KillCaveat))
	}

	var intro string
	switch {
	case ev.Killed:
		intro = fmt.Sprintf("Automated **rollback** for experiment `%s`: the kill switch was tripped, so gateways already route everyone to control. Merging this pause makes it permanent in policy (and rolls back client-axis variants).", e.Name)
	case recorded:
		intro = fmt.Sprintf("Automated **rollback** for experiment `%s`. The kill was %s. Traffic may keep flowing to the treatment until this is merged and shipped: **merge urgently**.", e.Name, ev.KillError)
	default:
		intro = fmt.Sprintf("Automated **rollback** for experiment `%s`. The kill switch could NOT be tripped (%s): traffic keeps flowing to the treatment until this is merged and shipped: **merge urgently**.", e.Name, ev.KillError)
	}
	url, err := c.pr(ctx, e, rep, "paused", fmt.Sprintf("Pause experiment %s: rollback verdict", e.Name), intro)
	ev.PRURL = url
	if err != nil {
		ev.PRError = "PR failed"
		errs = append(errs, err)
	}
	errs = append(errs, c.notify(ctx, e, ev))
	return errors.Join(errs...)
}

// conclude handles promote and expired: PR first, then notify with its URL;
// if the PR fails, the notification waits for the next tick.
func (c *Controller) conclude(ctx context.Context, e *policy.Experiment, rep promote.Report) error {
	var title, intro string
	if rep.Verdict == promote.Promote {
		title = fmt.Sprintf("Promote %s: %s wins", e.Name, rep.Treatment)
		intro = fmt.Sprintf("Automated **promotion** proposal for experiment `%s`. Merging concludes it, which returns everyone to control: before merging, add the change that rolls the treatment out (ring release for client-axis, gateway model route for traffic-axis).", e.Name)
	} else {
		title = fmt.Sprintf("Conclude %s: budget exhausted", e.Name)
		intro = fmt.Sprintf("Experiment `%s` **expired** (maxDays/maxSpendUSD reached) without a decision. Merging concludes it; everyone returns to control.", e.Name)
	}
	url, err := c.pr(ctx, e, rep, "concluded", title, intro)
	if err != nil {
		return err
	}
	return c.notify(ctx, e, Event{Experiment: e.Name, Axis: string(e.Axis), Verdict: rep.Verdict, Reason: rep.Reason, PRURL: url, Report: rep, At: c.now().UTC()})
}

// pr opens the status PR once; later ticks return the recorded URL.
func (c *Controller) pr(ctx context.Context, e *policy.Experiment, rep promote.Report, status, title, intro string) (string, error) {
	v := string(rep.Verdict)
	if url, done := c.State.Done(e.Name, v, ActionPR); done {
		return url, nil
	}
	if c.Writer == nil {
		c.log().Warn("no policy writer configured; not opening a PR", "experiment", e.Name, "verdict", v)
		return "", nil
	}
	url, err := c.Writer.ProposeStatus(ctx, e.Name, status, title, intro+"\n\n"+Evidence(rep))
	if err != nil {
		return "", c.fail(fmt.Errorf("controller: PR for %s (%s): %w", e.Name, v, err))
	}
	c.log().Info("controller opened PR", "experiment", e.Name, "verdict", v, "pr", url)
	return url, c.record(e, rep.Verdict, ActionPR, url)
}

// notify delivers ev once per channel: a channel that failed is retried on
// later ticks without re-posting to the ones that succeeded.
func (c *Controller) notify(ctx context.Context, e *policy.Experiment, ev Event) error {
	v := string(ev.Verdict)
	if _, done := c.State.Done(e.Name, v, ActionNotify); done { // pre-per-channel log
		return nil
	}
	names, ns := channels(c.Notifier)
	var errs []error
	for i, n := range ns {
		action := ActionNotify + ":" + names[i]
		if _, done := c.State.Done(e.Name, v, action); done {
			continue
		}
		if err := n.Notify(ctx, ev); err != nil {
			errs = append(errs, c.fail(fmt.Errorf("controller: notify %s (%s) via %s: %w", e.Name, v, names[i], err)))
			continue
		}
		errs = append(errs, c.record(e, ev.Verdict, action, ""))
	}
	return errors.Join(errs...)
}

// killed reports whether the kill switch currently holds exp.
func (c *Controller) killed(exp string) (bool, error) {
	if c.Kills == nil {
		return false, nil
	}
	recs, _, err := c.Kills.Killed()
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if r.Experiment == exp {
			return true, nil
		}
	}
	return false, nil
}

// hold: a running experiment is killed (an admin kill, or one left over from
// an earlier run). Its evidence is all-control, so it is not evaluated; humans
// are told once per run to unkill before resuming.
func (c *Controller) hold(ctx context.Context, e *policy.Experiment) error {
	if _, done := c.State.Done(e.Name, string(VerdictKilled), ActionHold); !done {
		c.log().Warn("experiment is killed; not evaluating it until it is unkilled", "experiment", e.Name)
		if err := c.record(e, VerdictKilled, ActionHold, ""); err != nil {
			return err
		}
	}
	return c.notify(ctx, e, Event{Experiment: e.Name, Axis: string(e.Axis), Verdict: VerdictKilled, Killed: true, At: c.now().UTC(),
		Reason: fmt.Sprintf("experiment %s is killed; unkill before resuming (not evaluated while killed)", e.Name)})
}

// encodeReport is the ActionRollback detail. NaN/Inf statistics do not
// encode; then only the fields humans need for the pause PR are kept.
func encodeReport(rep promote.Report) string {
	b, err := json.Marshal(rep)
	if err != nil {
		b, _ = json.Marshal(promote.Report{Verdict: rep.Verdict, Reason: rep.Reason, Control: rep.Control, Treatment: rep.Treatment,
			NControl: rep.NControl, NTreatment: rep.NTreatment}) // plain strings/ints: cannot fail
	}
	return string(b)
}

func decodeReport(d string) promote.Report {
	rep := promote.Report{Verdict: promote.Rollback, Reason: "recorded rollback (evidence unavailable)"}
	_ = json.Unmarshal([]byte(d), &rep) // best effort: the rollback proceeds either way
	rep.Verdict = promote.Rollback
	return rep
}

// Evidence renders a verdict report as Markdown for PR bodies.
func Evidence(rep promote.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- Verdict: **%s** (%s)\n- Control: `%s` (n=%d), treatment: `%s` (n=%d)\n- Primary effect: %+.4g (p=%.4f)\n",
		rep.Verdict, rep.Reason, rep.Control, rep.NControl, rep.Treatment, rep.NTreatment, rep.Effect, rep.PValue)
	for _, g := range rep.Guardrails {
		fmt.Fprintf(&b, "- Guardrail `%s`: %s (regression %.1f%%, limit %.1f%%)\n", g.Metric, g.Result.Status, 100*g.Result.Regression, 100*g.Result.MaxRegression)
	}
	return b.String()
}

// Run ticks every interval until ctx ends. After a failed tick it retries
// sooner (15s, 30s, ... capped at interval) so a transient ClickHouse or git
// error doesn't delay a rollback by a whole interval.
func (c *Controller) Run(ctx context.Context, interval time.Duration) {
	const retryBase = 15 * time.Second
	fails := 0
	for {
		wait := interval
		if err := c.Tick(ctx); err != nil {
			fails++
			wait = min(interval, retryBase<<min(fails-1, 10))
			c.log().Error("controller tick failed", "err", err, "consecutive_failures", fails, "retry_in", wait)
		} else {
			fails = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// WriteMetrics writes Prometheus text-format counters.
func (c *Controller) WriteMetrics(w io.Writer) {
	fmt.Fprintf(w, "# TYPE halo_controller_ticks_total counter\nhalo_controller_ticks_total %d\n", c.ticks.Load())
	fmt.Fprintf(w, "# TYPE halo_controller_errors_total counter\nhalo_controller_errors_total %d\n", c.errs.Load())
	c.vmu.Lock()
	defer c.vmu.Unlock()
	fmt.Fprint(w, "# TYPE halo_controller_verdicts_total counter\n")
	for _, v := range []promote.Verdict{promote.Continue, promote.Expired, promote.Promote, promote.Rollback} {
		fmt.Fprintf(w, "halo_controller_verdicts_total{verdict=%q} %d\n", v, c.verdicts[v])
	}
}
