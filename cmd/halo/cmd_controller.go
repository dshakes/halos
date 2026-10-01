package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/server"
)

func (a *app) cmdController() *cobra.Command {
	c := &cobra.Command{Use: "controller", Short: "Automated experiment loop (evaluate, kill on rollback, PRs, notify)"}
	var ch clickhouseFlags
	var dataDir, verdicts, base, slackFile, hookFile, secretFile string
	var once, noPR, killServed bool
	var interval time.Duration
	run := &cobra.Command{
		Use: "run", Short: "Evaluate running experiments and act on verdicts (never merges)", Args: cobra.NoArgs, Annotations: policyDirAnno,
		Long: "Evaluates every running experiment from ClickHouse evidence. rollback: trips the kill switch in\n" +
			"<data-dir>/killswitch.jsonl (served to gateways when <data-dir> is halo-server's --data-dir), opens a\n" +
			"PR pausing the experiment, notifies. Without --killswitch-served, messages say the kill is only recorded. promote/expired: opens a PR concluding it, notifies. Each action\n" +
			"happens once per experiment run (<data-dir>/controller-state.jsonl). PRs are opened from the git\n" +
			"checkout containing --policy-dir with gh. Run a single controller per data dir. Kills are also appended\n" +
			"to <data-dir>/audit.jsonl (hash chain shared with halo-server): do not run this against a data dir\n" +
			"a live halo-server is appending to (single writer); use the server's in-process controller there.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			if !once && interval < time.Minute {
				return errors.New("--interval must be at least 1m")
			}
			notifiers, err := controller.NotifiersFromFiles(slackFile, hookFile, secretFile)
			if err != nil {
				return err
			}
			state, err := controller.OpenStateLog(dataDir)
			if err != nil {
				return err
			}
			defer func() { _ = state.Close() }()
			kills, err := controller.OpenKillStore(dataDir)
			if err != nil {
				return err
			}
			defer func() { _ = kills.Close() }()
			// Offline kills must land in the same hash-chained audit log the
			// server uses (<data-dir>/audit.jsonl). Single writer: see server.AppendAuditOffline.
			audited := controller.KillFunc(func(ctx context.Context, experiment, by, reason string) (bool, error) {
				changed, err := kills.Kill(ctx, experiment, by, reason)
				if err != nil || !changed {
					return changed, err
				}
				// The kill stays applied (fail safe); the error surfaces the audit gap.
				if aerr := server.AppendAuditOffline(dataDir, by, "experiment.kill", experiment, map[string]string{"reason": reason}, time.Now()); aerr != nil {
					return changed, fmt.Errorf("kill of %q applied but audit append failed: %w", experiment, aerr)
				}
				return changed, nil
			})
			ctrl := &controller.Controller{
				Org:          func() (*policy.Org, error) { return a.load(dir) },
				Metrics:      ch.client(),
				Kill:         audited,
				Kills:        kills,
				Notifier:     notifiers,
				State:        state,
				VerdictsPath: verdicts,
				Log:          slog.New(slog.NewTextHandler(a.errw, nil)),
			}
			if !killServed {
				// Only the operator knows whether a halo-server with a kill key serves this file.
				ctrl.KillCaveat = "recorded in " + filepath.Join(dataDir, "killswitch.jsonl") +
					"; gateways enforce only if halo-server serves this data dir with a kill key"
			}
			if !noPR {
				ctrl.Writer = &controller.GitWriter{RepoDir: dir, Base: base, Opener: promote.GHOpener{}}
			}
			if once {
				if err := ctrl.Tick(cmd.Context()); err != nil {
					return fmt.Errorf("controller tick: %w", err)
				}
				return nil
			}
			ctrl.Run(cmd.Context(), interval)
			return nil
		},
	}
	ch.add(run)
	f := run.Flags()
	f.StringVar(&dataDir, "data-dir", "", "directory for controller-state.jsonl and killswitch.jsonl (required)")
	f.StringVar(&verdicts, "verdicts-file", "", "upsert each verdict into this JSON array file read by halo-server")
	f.StringVar(&base, "base", "", "PR base branch")
	f.StringVar(&slackFile, "notify-slack-url-file", "", "file holding a Slack incoming-webhook URL")
	f.StringVar(&hookFile, "notify-webhook-url-file", "", "file holding a generic webhook URL")
	f.StringVar(&secretFile, "notify-webhook-secret-file", "", "file holding the webhook HMAC-SHA256 secret (X-Halo-Signature)")
	f.BoolVar(&once, "once", false, "run a single tick and exit (CI/cron); non-zero exit if any experiment failed")
	f.BoolVar(&noPR, "no-pr", false, "do not open PRs (verdicts, kills and notifications only)")
	f.DurationVar(&interval, "interval", 5*time.Minute, "tick interval without --once")
	f.BoolVar(&killServed, "killswitch-served", false, "acknowledge that halo-server (with --killswitch-key-file) serves this --data-dir to gateways;\n"+
		"without it, rollback messages say the kill is only recorded, not enforced")
	// halo-server's older spellings, accepted for consistency; hidden.
	f.StringVar(&verdicts, "verdicts", "", "")
	f.DurationVar(&interval, "controller-interval", 5*time.Minute, "")
	_ = f.MarkDeprecated("verdicts", "use --verdicts-file")
	_ = f.MarkDeprecated("controller-interval", "use --interval")
	_ = run.MarkFlagRequired("data-dir")
	c.AddCommand(run)
	return c
}
