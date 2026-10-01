package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
)

func findRollout(org *policy.Org, name string) (*policy.Rollout, error) {
	var names []string
	for _, r := range org.Rollouts {
		if r.Name == name {
			return r, nil
		}
		names = append(names, r.Name)
	}
	return nil, fmt.Errorf("unknown rollout %q (have: %s)", name, strings.Join(names, ", "))
}

// rolloutEvidence is the optional evidence wiring shared by status and advance.
type rolloutEvidence struct {
	dataDir string
	ch      clickhouseFlags
}

func (f *rolloutEvidence) add(c *cobra.Command) {
	c.Flags().StringVar(&f.dataDir, "data-dir", "", "controller data dir: read <data-dir>/rollouts/<name>.json for step entry time and history")
	c.Flags().StringVar(&f.ch.url, "clickhouse", "", "ClickHouse HTTP URL for metric gates (optional)")
	c.Flags().StringVar(&f.ch.db, "database", "", "ClickHouse database")
	c.Flags().StringVar(&f.ch.user, "user", "", "ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD)")
}

// decide evaluates r's live step with whatever evidence is configured.
func (f *rolloutEvidence) decide(cmd *cobra.Command, dir string, org *policy.Org, r *policy.Rollout, approved bool) (rollout.State, rollout.Evidence, rollout.Decision, error) {
	now := time.Now()
	st := rollout.PolicyState(r)
	if f.dataDir != "" {
		var err error
		if st, err = rollout.LoadState(rolloutStateDir(f.dataDir), r.Name); err != nil {
			return st, rollout.Evidence{}, rollout.Decision{}, err
		}
		st.Sync(r, now) // view only; never saved here
	}
	var ms promote.MetricSource
	if f.ch.url != "" {
		ms = f.ch.client()
	}
	ev, err := rollout.Gather(cmd.Context(), dir, org, r, st, ms, now)
	if err != nil {
		return st, ev, rollout.Decision{}, err
	}
	ev.Approved = approved
	return st, ev, rollout.Evaluate(rollout.Effective(org, r), st, ev, now), nil
}

func rolloutStateDir(dataDir string) string { return filepath.Join(dataDir, "rollouts") }

func (a *app) cmdRollout() *cobra.Command {
	c := &cobra.Command{Use: "rollout", Short: "Phased rollouts: plan, status, simulate; advance opens a PR, never merges"}
	load := func(cmd *cobra.Command, name string) (string, *policy.Org, *policy.Rollout, error) {
		dir, err := policyDir(cmd, nil)
		if err != nil {
			return "", nil, nil, err
		}
		org, err := a.loadValid(dir)
		if err != nil {
			return "", nil, nil, err
		}
		r, err := findRollout(org, name)
		return dir, org, r, err
	}

	c.AddCommand(&cobra.Command{
		Use: "list", Short: "List rollouts", Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			return a.emit(org.Rollouts, func() {
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tAXIS\tSTATUS\tSTEP\tEXPERIMENT")
				for _, r := range org.Rollouts {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Axis, r.EffectiveStatus(), stepLabel(r), r.Experiment)
				}
				tw.Flush()
			})
		},
	})

	c.AddCommand(&cobra.Command{
		Use: "plan <name>", Short: "Show the rollout's steps, gates and earliest timeline", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, org, r, err := load(cmd, args[0])
			if err != nil {
				return err
			}
			t := rollout.BuildTimeline(org, r)
			manual := rollout.ManualSteps(org, r, rollout.Complete)
			return a.emit(map[string]any{"timeline": t, "manualOnComplete": manual}, func() { a.printTimeline(t, manual) })
		},
	})

	var ev rolloutEvidence
	status := &cobra.Command{
		Use: "status <name>", Short: "Show the live step, gate values vs thresholds and the next action", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, org, r, err := load(cmd, args[0])
			if err != nil {
				return err
			}
			st, e, d, err := ev.decide(cmd, dir, org, r, false)
			if err != nil {
				return err
			}
			return a.emit(map[string]any{"rollout": r.Name, "status": r.EffectiveStatus(), "state": st, "evidence": e, "decision": d},
				func() { a.printStatus(org, r, st, d, ev) })
		},
	}
	ev.add(status)
	c.AddCommand(status)

	var so rollout.SimOptions
	var evFile string
	var breach int
	sim := &cobra.Command{
		Use: "simulate <name>", Short: "Run the state machine on synthetic or recorded evidence (writes nothing)", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		Long: "Runs the real gate logic (guardrails via the same sequential test as the controller) from \"not started\"\n" +
			"until the rollout completes, rolls back, pauses or hits --horizon, assuming every PR merges at once.\n" +
			"--scenario healthy|regression synthesises seeded per-user samples; --evidence replays a JSON array of\n" +
			"{\"report\": <halo exp analyze --output json>, \"approved\": bool}, one per tick (the last repeats).",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, org, r, err := load(cmd, args[0])
			if err != nil {
				return err
			}
			if so.Scenario != rollout.ScenarioHealthy && so.Scenario != rollout.ScenarioRegression {
				return fmt.Errorf("--scenario must be %s or %s", rollout.ScenarioHealthy, rollout.ScenarioRegression)
			}
			if cmd.Flags().Changed("breach-step") {
				so.BreachStep = &breach
			}
			if evFile != "" {
				b, err := os.ReadFile(evFile)
				if err != nil {
					return fmt.Errorf("--evidence: %w", err)
				}
				if err := json.Unmarshal(b, &so.Recorded); err != nil {
					return fmt.Errorf("--evidence %s: %w", evFile, err)
				}
			}
			res, err := rollout.Simulate(cmd.Context(), dir, org, r, so)
			if err != nil {
				return err
			}
			return a.emit(res, func() { a.printSim(res, so, evFile != "") })
		},
	}
	sf := sim.Flags()
	sf.StringVar(&so.Scenario, "scenario", rollout.ScenarioHealthy, "synthetic evidence: healthy | regression")
	sf.IntVar(&breach, "breach-step", 0, "regression: 0-based step index the regression starts at (default: the second guardrailed step)")
	sf.DurationVar(&so.Tick, "tick", time.Hour, "controller tick")
	sf.DurationVar(&so.Horizon, "horizon", 120*24*time.Hour, "stop after this much simulated time")
	sf.IntVar(&so.UnitsPerHour, "users-per-hour", 1000, "new users the backing experiment sees per hour at 100%")
	sf.DurationVar(&so.ApproveAfter, "approve-after", 4*time.Hour, "how long the simulated human takes to approve")
	sf.Uint64Var(&so.Seed, "seed", 1, "RNG seed (output is reproducible)")
	sf.StringVar(&evFile, "evidence", "", "recorded evidence JSON (replaces the scenario)")
	c.AddCommand(sim)

	var reason, base string
	var dry, force bool
	var aev rolloutEvidence
	advance := &cobra.Command{
		Use: "advance <name>", Short: "Open a PR moving the rollout to its next step (or completing it); never merges", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		Long: "You are the approval: the PR is opened even with pending gates (listed in its body), but not when a\n" +
			"gate has failed unless --force. Without --data-dir/--clickhouse, bake and metric gates show as unknown.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return errors.New("--reason is required")
			}
			dir, org, r, err := load(cmd, args[0])
			if err != nil {
				return err
			}
			if s := r.EffectiveStatus(); s == policy.RolloutAborted || s == policy.RolloutCompleted {
				return fmt.Errorf("rollout %s is %s", r.Name, s)
			}
			_, _, d, err := aev.decide(cmd, dir, org, r, true)
			if err != nil {
				return err
			}
			if (d.Action == rollout.Rollback || d.Action == rollout.Pause) && !force {
				return fmt.Errorf("rollout %s: a gate failed (%s); refusing to advance without --force", r.Name, strings.Join(d.Reasons, "; "))
			}
			act, next := rollout.NextAction(r)
			intro := fmt.Sprintf("Manual %s of rollout `%s`, from step `%s`.\n\n**Reason:** %s", act, r.Name, stepLabel(r), reason)
			return a.rolloutPR(cmd, dir, org, r, act, next, intro, reason, base, dry, d)
		},
	}
	aev.add(advance)
	c.AddCommand(advance)

	for _, verb := range []struct {
		use     string
		aliases []string
		act     rollout.Action
		short   string
	}{
		{"pause <name>", nil, rollout.Pause, "Open a PR pausing the rollout (exposure stays; no further steps)"},
		{"rollback <name>", []string{"abort"}, rollout.Rollback, "Open a PR aborting the rollout: experiment paused, rings back on baseline.release"},
	} {
		cmd := &cobra.Command{
			Use: verb.use, Aliases: verb.aliases, Short: verb.short, Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
			RunE: func(cmd *cobra.Command, args []string) error {
				if strings.TrimSpace(reason) == "" {
					return errors.New("--reason is required")
				}
				dir, org, r, err := load(cmd, args[0])
				if err != nil {
					return err
				}
				intro := fmt.Sprintf("Manual %s of rollout `%s` at step `%s`.\n\n**Reason:** %s", verb.act, r.Name, stepLabel(r), reason)
				if verb.act == rollout.Rollback && r.Axis == policy.AxisTraffic && r.Experiment != "" {
					intro += fmt.Sprintf("\n\nFor an immediate stop before this merges, kill experiment `%s` (halo-server: POST /api/v1/experiments/%s/kill).", r.Experiment, r.Experiment)
				}
				return a.rolloutPR(cmd, dir, org, r, verb.act, -1, intro, reason, base, dry, rollout.Decision{})
			},
		}
		c.AddCommand(cmd)
	}
	for _, sub := range c.Commands() {
		switch sub.Name() {
		case "advance", "pause", "rollback":
			f := sub.Flags()
			f.StringVar(&reason, "reason", "", "why (required; recorded in the commit message and PR body)")
			f.StringVar(&base, "base", "", "PR base branch")
			f.BoolVar(&dry, "dry-run", false, "print the patch instead of opening a PR")
			if sub.Name() == "advance" {
				f.BoolVar(&force, "force", false, "advance even though a gate failed")
			}
		}
	}
	return c
}

func stepLabel(r *policy.Rollout) string {
	if r.Step == "" {
		return "(not started)"
	}
	return r.Step
}

// rolloutPR plans act and opens it as a PR (or prints the patch with --dry-run).
func (a *app) rolloutPR(cmd *cobra.Command, dir string, org *policy.Org, r *policy.Rollout, act rollout.Action, next int, intro, reason, base string, dry bool, d rollout.Decision) error {
	ch, err := rollout.Plan(dir, org, r, act, next)
	if err != nil {
		return err
	}
	if ch.Patch == "" {
		return fmt.Errorf("rollout %s: nothing to change for %s", r.Name, act)
	}
	manual := rollout.ManualSteps(org, r, act)
	if dry {
		return a.emit(map[string]any{"action": act, "patch": ch.Patch, "manual": manual}, func() {
			fmt.Fprint(a.out, ch.Patch)
			for _, m := range manual {
				fmt.Fprintln(a.out, a.yellow("manual:"), m)
			}
		})
	}
	url, err := promote.GHOpener{}.OpenPR(cmd.Context(), promote.PRRequest{
		RepoDir: dir, Base: base, Branch: rollout.Branch(r, act, next), Title: rollout.Title(r, act, next),
		Body: rollout.Body(intro, d, manual, ch.Patch), CommitBody: "Reason: " + reason, Files: ch.Files, Edit: ch.Edit,
	})
	if err != nil {
		return err
	}
	return a.emit(map[string]string{"pr": url}, func() { fmt.Fprintln(a.out, a.green("opened"), url) })
}

// bar renders pct as a 10-cell ASCII gauge.
func bar(pct float64) string {
	n := int(pct/10 + 0.5)
	if pct > 0 && n == 0 {
		n = 1
	}
	return "[" + strings.Repeat("#", n) + strings.Repeat(".", 10-n) + "]"
}

func (a *app) printTimeline(t rollout.Timeline, manual []string) {
	fmt.Fprintf(a.out, "%s %s  (%s axis, %s)\n", a.bold("Rollout"), a.bold(t.Rollout), t.Axis, t.Status)
	fmt.Fprintf(a.out, "Change:     %s\n", t.Change)
	if t.Experiment != "" {
		fmt.Fprintf(a.out, "Experiment: %s\n", t.Experiment)
	}
	fmt.Fprintln(a.out)
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  #\tSTART\tSTEP\tSTRATEGY\tTREATMENT\tEXPOSURE\tBAKE\tMIN N\tGATES\tON FAIL")
	for _, s := range t.Steps {
		mark := "  "
		if s.Live {
			mark = a.green("> ")
		}
		pct := s.Percent
		if s.Strategy == string(policy.StrategyHoldout) {
			pct = 100 - pct
		}
		n := "-"
		if s.MinSamples > 0 {
			n = fmt.Sprint(s.MinSamples)
		}
		gates := strings.Join(s.Gates, ", ")
		if gates == "" {
			gates = "-"
		}
		fmt.Fprintf(tw, "%s%d\t%s\t%s\t%s\t%s %3g%%\t%s\t%s\t%s\t%s\t%s\n", mark, s.Index+1, s.EarliestStart, s.Name, s.Strategy,
			bar(pct), pct, s.Exposure, orDash(s.Bake), n, gates, s.OnFailure)
	}
	tw.Flush()
	fmt.Fprintf(a.out, "\nEarliest completion: T+%s (sum of bakes; samples and approvals add time). Every step is a PR a human merges.\n", t.MinDuration)
	for _, m := range manual {
		fmt.Fprintln(a.out, a.yellow("On completion:"), m)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) gateStatus(s string) string {
	switch s {
	case rollout.GatePass:
		return a.green(s)
	case rollout.GateFail:
		return a.red(s)
	}
	return a.yellow(s)
}

func (a *app) printStatus(org *policy.Org, r *policy.Rollout, st rollout.State, d rollout.Decision, ev rolloutEvidence) {
	fmt.Fprintf(a.out, "%s %s  (%s axis, %s)\n", a.bold("Rollout"), a.bold(r.Name), r.Axis, r.EffectiveStatus())
	if st.Step < 0 {
		fmt.Fprintln(a.out, "Step:       not started")
	} else {
		s := r.Steps[st.Step]
		fmt.Fprintf(a.out, "Step:       %d/%d %s: %s\n", st.Step+1, len(r.Steps), s.Name, rollout.Exposure(org, r, s))
		switch {
		case !st.EnteredAt.IsZero():
			fmt.Fprintf(a.out, "Entered:    %s (%s ago)\n", st.EnteredAt.Format(time.RFC3339), rollout.Days(time.Since(st.EnteredAt).Truncate(time.Minute)))
		case ev.dataDir == "":
			fmt.Fprintln(a.out, "Entered:    unknown (pass --data-dir with the controller's data dir)")
		default:
			fmt.Fprintln(a.out, "Entered:    unknown (the controller has not observed this step yet)")
		}
	}
	if st.Halted != "" {
		fmt.Fprintf(a.out, "Halted:     %s by the controller; waiting for its PR to merge\n", a.red(st.Halted))
	}
	if len(d.Gates) > 0 {
		fmt.Fprintln(a.out)
		tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "GATE\tSTATUS\tVALUE\tTHRESHOLD")
		for _, g := range d.Gates {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.Gate, a.gateStatus(g.Status), g.Value, g.Threshold)
		}
		tw.Flush()
		if ev.ch.url == "" && slices.ContainsFunc(d.Gates, func(g rollout.GateResult) bool { return g.Value == "unknown" && g.Gate != "bake" }) {
			fmt.Fprintln(a.out, "(metric gates need --clickhouse)")
		}
	}
	next := string(d.Action)
	switch d.Action {
	case rollout.Advance:
		next = "advance to " + r.Steps[d.Next].Name + " (the controller opens a PR)"
	case rollout.Complete:
		next = "complete (the controller opens a PR)"
	case rollout.Rollback, rollout.Pause:
		next = a.red(next) + " (automatic)"
	}
	if d.AwaitingApproval {
		next = "awaiting approval: halo rollout advance " + r.Name + " --reason ..."
	}
	fmt.Fprintf(a.out, "\nNext:       %s\n", a.bold(next))
	for _, reason := range d.Reasons {
		fmt.Fprintf(a.out, "            - %s\n", reason)
	}
}

func (a *app) printSim(res rollout.SimResult, o rollout.SimOptions, recorded bool) {
	src := "scenario " + res.Scenario
	if recorded {
		src = "recorded evidence"
	}
	fmt.Fprintf(a.out, "%s %s (%s, tick %s, %d users/h, seed %d; PRs assumed merged at once)\n\n",
		a.bold("Simulating"), a.bold(res.Rollout), src, rollout.Days(o.Tick), o.UnitsPerHour, o.Seed)
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AT\tSTEP\tDECISION\tWHY")
	for _, e := range res.Events {
		act := string(e.Action)
		switch e.Action {
		case rollout.Advance, rollout.Complete:
			act = a.green(act)
			if e.Approved {
				act += " (approved)"
			}
		case rollout.Rollback, rollout.Pause:
			act = a.red(act)
		default:
			act = a.yellow(act)
		}
		why := strings.Join(e.Reasons, "; ")
		if len(why) > 110 {
			why = why[:107] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.At, e.Step, act, why)
	}
	tw.Flush()
	fmt.Fprintf(a.out, "\nOutcome: %s after %s\n", a.bold(string(res.Outcome)), res.Duration)
}
