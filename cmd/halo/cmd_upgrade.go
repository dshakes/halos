package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/upgrade"
)

// evalHarness maps policy harness names to eval driver names.
var evalHarness = map[string]string{"claude-code": "claude", "codex": "codex", "gemini-cli": "gemini"}

// candidateSuite narrows the suite to current pin (control) vs candidate.
// CLI: the first variant on that harness (else its matrix harness, first
// model), at From and at To. Model: the
// suite's control variant, and the same with the candidate model id passed
// straight to the CLI (the gateway must pass unknown ids through: UNVERIFIED).
func candidateSuite(s *eval.Suite, c upgrade.Candidate) (*eval.Suite, error) {
	var base *eval.Variant
	for i, v := range s.Variants {
		if (c.Kind == upgrade.KindCLI && v.Harness == evalHarness[c.Harness]) || (c.Kind == upgrade.KindModel && v.Name == s.Control) {
			base = &s.Variants[i]
			break
		}
	}
	if base == nil && c.Kind == upgrade.KindCLI && s.Matrix != nil {
		for _, h := range s.Matrix.Harnesses {
			if h.Harness == evalHarness[c.Harness] {
				base = &eval.Variant{Harness: h.Harness, Model: h.Models[0], Settings: h.Settings, Dir: s.Dir}
				break
			}
		}
	}
	if base == nil {
		return nil, fmt.Errorf("suite %s has no variant or matrix harness to evaluate %s against", s.Name, c.Key())
	}
	ctl, cand := *base, *base
	ctl.Name, cand.Name = "current", "candidate"
	if c.Kind == upgrade.KindCLI {
		ctl.Version, cand.Version = c.From, c.To
	} else {
		cand.Model = c.To
	}
	cp := *s
	cp.Variants, cp.Control, cp.Matrix = []eval.Variant{ctl, cand}, "current", nil
	return &cp, cp.Validate()
}

func (a *app) cmdUpgrade() *cobra.Command {
	c := &cobra.Command{Use: "upgrade", Short: "Watch upstream CLIs and models; open eval-gated upgrade PRs (never merges)"}
	var cfgPath, npmURL string
	var dryRun, local bool
	var parallel int
	var every time.Duration
	watcher := func(cmd *cobra.Command) (*upgrade.Watcher, error) {
		dir, err := policyDir(cmd, nil)
		if err != nil {
			return nil, err
		}
		if cfgPath == "" {
			cfgPath = filepath.Join(dir, ".halos", "upgrade.yaml")
		}
		cfg, err := upgrade.LoadConfig(cfgPath)
		if err != nil {
			return nil, err
		}
		w := &upgrade.Watcher{PolicyDir: dir, Config: cfg, DryRun: dryRun,
			Registry: upgrade.NPM{URL: npmURL},
			Verifier: upgrade.ArtifactVerifier{Resolver: release.ArtifactResolver{NPMRegistry: npmURL}},
			PR:       promote.GHOpener{},
		}
		w.Eval = func(ctx context.Context, cand upgrade.Candidate) (*eval.Scorecard, error) {
			s, err := eval.LoadSuite(filepath.Join(dir, cfg.Suite))
			if err != nil {
				return nil, err
			}
			if s, err = candidateSuite(s, cand); err != nil {
				return nil, err
			}
			var r eval.Runner = &eval.DockerRunner{}
			if local {
				r = eval.LocalRunner{}
			}
			return runSuite(ctx, s, r, parallel, s.Seed)
		}
		return w, nil
	}
	show := func(cs []upgrade.Candidate) error {
		return a.emit(cs, func() { fmt.Fprint(a.out, upgrade.Table(cs)) })
	}
	check := &cobra.Command{
		Use: "check", Short: "Check once for new CLI versions and models", Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w, err := watcher(cmd)
			if err != nil {
				return err
			}
			cs, err := w.Check(cmd.Context())
			if perr := show(cs); perr != nil {
				return perr
			}
			return err
		},
	}
	watch := &cobra.Command{
		Use: "watch", Short: "Check on an interval until interrupted", Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if every < time.Minute {
				return fmt.Errorf("--every must be >= 1m")
			}
			w, err := watcher(cmd)
			if err != nil {
				return err
			}
			w.Watch(cmd.Context(), every, func(cs []upgrade.Candidate, err error) {
				fmt.Fprintf(a.errw, "%s upgrade check\n", time.Now().UTC().Format(time.RFC3339))
				if perr := show(cs); perr != nil {
					fmt.Fprintln(a.errw, "error:", perr)
				}
				if err != nil {
					fmt.Fprintln(a.errw, "error:", err)
				}
			})
			return nil
		},
	}
	for _, sub := range []*cobra.Command{check, watch} {
		sub.Flags().StringVar(&cfgPath, "config", "", "watcher config (default <policy-dir>/.halos/upgrade.yaml)")
		sub.Flags().StringVar(&npmURL, "npm-registry", "", "npm registry base URL (default https://registry.npmjs.org)")
		sub.Flags().BoolVar(&dryRun, "dry-run", false, "only report candidates: no eval, no branch, no PR")
		sub.Flags().BoolVar(&local, "local", false, "run evals on the host instead of Docker (no isolation; testing only)")
		sub.Flags().IntVar(&parallel, "parallel", 2, "concurrent eval trials")
	}
	watch.Flags().DurationVar(&every, "every", 6*time.Hour, "check interval")
	c.AddCommand(check, watch)
	return c
}
