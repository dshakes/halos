package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/yamledit"
)

var envKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func (a *app) findExp(org *policy.Org, name string) (*policy.Experiment, error) {
	for _, e := range org.Experiments {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, fmt.Errorf("unknown experiment %q", name)
}

func (a *app) cmdExp() *cobra.Command {
	exp := &cobra.Command{Use: "exp", Short: "Manage experiments"}

	exp.AddCommand(&cobra.Command{
		Use: "list", Short: "List experiments", Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			return a.emit(org.Experiments, func() {
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tTYPE\tAXIS\tSTATUS\tRINGS")
				for _, e := range org.Experiments {
					st := e.Status
					if st == "" {
						st = "draft"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Name, e.Type, e.Axis, st, strings.Join(e.Rings, ","))
				}
				tw.Flush()
			})
		},
	})

	exp.AddCommand(&cobra.Command{
		Use: "show <name>", Short: "Show an experiment", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, nil) // args[0] is the experiment name, not a dir
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			e, err := a.findExp(org, args[0])
			if err != nil {
				return err
			}
			return a.emit(e, func() {
				b, _ := yaml.Marshal(e)
				fmt.Fprint(a.out, string(b))
			})
		},
	})

	for _, verb := range []string{"start", "pause", "conclude"} {
		exp.AddCommand(&cobra.Command{
			Use: verb + " <name>", Short: fmt.Sprintf("Set experiment status to %s (edits the YAML in place)", promote.StatusTransitions[verb].To), Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
			RunE: func(cmd *cobra.Command, args []string) error {
				dir, err := policyDir(cmd, nil)
				if err != nil {
					return err
				}
				ref, err := yamledit.Find(dir, policy.KindExperiment, args[0])
				if err != nil {
					return err
				}
				cur, to, data, err := promote.TransitionStatus(ref, verb)
				if err != nil {
					return err
				}
				if err := ref.Save(data); err != nil {
					return err
				}
				return a.emit(map[string]string{"experiment": args[0], "from": cur, "status": to, "file": ref.Path}, func() {
					fmt.Fprintf(a.out, "%s %s: %q -> %q (%s)\n", a.green("ok"), args[0], cur, to, ref.Path)
				})
			},
		})
	}

	var ch clickhouseFlags
	var verdictsFile string
	analyze := &cobra.Command{
		Use: "analyze <name>", Short: "Evaluate experiment evidence from ClickHouse (promote|rollback|continue|expired)", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			e, err := a.findExp(org, args[0])
			if err != nil {
				return err
			}
			rep, err := promote.Evaluate(cmd.Context(), e, ch.client())
			if err != nil {
				return fmt.Errorf("analyze %s: %w", args[0], err)
			}
			if verdictsFile != "" {
				if err := promote.UpsertVerdict(verdictsFile, e.Name, rep, time.Now().UTC()); err != nil {
					return err
				}
			}
			return a.emit(rep, func() { a.printReport(e.Name, rep) })
		},
	}
	ch.add(analyze)
	analyze.Flags().StringVar(&verdictsFile, "verdicts-file", "", "upsert this verdict into a JSON array file read by halo-server")

	var pch clickhouseFlags
	var ring, rel, base string
	var dry bool
	prom := &cobra.Command{
		Use: "promote <name>", Short: "Open a PR pointing --ring at --release (never merges); requires a promote verdict", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			e, err := a.findExp(org, args[0])
			if err != nil {
				return err
			}
			rep, err := promote.Evaluate(cmd.Context(), e, pch.client())
			if err != nil {
				return fmt.Errorf("analyze %s: %w", args[0], err)
			}
			ee, err := yamledit.Find(dir, policy.KindExperiment, e.Name)
			if err != nil {
				return err
			}
			rr, err := yamledit.Find(dir, policy.KindRing, ring)
			if err != nil {
				return err
			}
			t := promote.Target{RepoDir: dir}
			if t.ExperimentFile, err = filepath.Rel(dir, ee.Path); err != nil {
				return err
			}
			if t.RingFile, err = filepath.Rel(dir, rr.Path); err != nil {
				return err
			}
			change, err := promote.PlanPromote(t, e, ring, rel)
			if err != nil {
				return err
			}
			if dry {
				fmt.Fprintf(a.out, "verdict: %s\n%s", rep.Verdict, change.Patch)
				return nil
			}
			url, err := promote.OpenPR(cmd.Context(), promote.GHOpener{}, t, change, e, rep, base)
			if err != nil {
				return err
			}
			return a.emit(map[string]string{"pr": url}, func() { fmt.Fprintln(a.out, a.green("opened"), url) })
		},
	}
	pch.add(prom)
	prom.Flags().StringVar(&ring, "ring", "", "ring to re-point (required)")
	prom.Flags().StringVar(&rel, "release", "", "release digest to pin (required)")
	prom.Flags().StringVar(&base, "base", "", "PR base branch")
	prom.Flags().BoolVar(&dry, "dry-run", false, "print the patch instead of opening a PR")
	_ = prom.MarkFlagRequired("ring")
	_ = prom.MarkFlagRequired("release")

	exp.AddCommand(analyze, prom)
	return exp
}

type clickhouseFlags struct{ url, db, user string }

func (f *clickhouseFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&f.url, "clickhouse", "", "ClickHouse HTTP URL, e.g. http://localhost:8123 (required)")
	c.Flags().StringVar(&f.db, "database", "", "ClickHouse database")
	c.Flags().StringVar(&f.user, "user", "", "ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD)")
	_ = c.MarkFlagRequired("clickhouse")
}

func (f *clickhouseFlags) client() *promote.ClickHouse {
	return &promote.ClickHouse{URL: f.url, Database: f.db, User: f.user, Password: os.Getenv("HALO_CLICKHOUSE_PASSWORD")}
}

func (a *app) printReport(name string, r promote.Report) {
	fmt.Fprintf(a.out, "%s: %s\n  %s\n", name, a.bold(string(r.Verdict)), r.Reason)
	fmt.Fprintf(a.out, "  %s (n=%d) vs %s (n=%d)  effect=%.4g p=%.4g\n", r.Control, r.NControl, r.Treatment, r.NTreatment, r.Effect, r.PValue)
	for _, g := range r.Guardrails {
		fmt.Fprintf(a.out, "  guardrail %s: %+v\n", g.Metric, g.Result)
	}
}

func (a *app) cmdEval() *cobra.Command {
	c := &cobra.Command{Use: "eval", Short: "Offline replay evals"}
	var local bool
	var parallel int
	var seed uint64
	var passEnv []string
	var network, memory, cpus string
	var ro evalRunFlags
	run := &cobra.Command{
		Use: "run <suite.yaml>", Short: "Run an eval suite and print the scorecard", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, k := range passEnv {
				if !envKeyRe.MatchString(k) {
					return fmt.Errorf("--pass-env %q: keys must be UPPER_SNAKE_CASE ([A-Z][A-Z0-9_]*)", k)
				}
			}
			if len(passEnv) > 0 && !local {
				fmt.Fprintf(a.errw, "warning: --pass-env %s reaches the agent step only, never setup/check; prefer a short-lived gateway token over a real provider key\n", strings.Join(passEnv, ","))
			}
			s, err := eval.LoadSuite(args[0])
			if err != nil {
				return err
			}
			if ro.matrix {
				if s, err = s.WithMatrix(); err != nil {
					return err
				}
			} else if len(s.Variants) == 0 {
				return fmt.Errorf("suite %s defines only a matrix; run it with --matrix", s.Name)
			}
			if !cmd.Flags().Changed("seed") && s.Seed != 0 {
				seed = s.Seed
			}
			var r eval.Runner = &eval.DockerRunner{PassEnv: passEnv, Network: network, Memory: memory, CPUs: cpus}
			if local {
				r = eval.LocalRunner{}
			}
			sc, err := runSuite(cmd.Context(), s, r, parallel, seed)
			if err != nil {
				return err
			}
			return a.writeScorecard(sc, ro)
		},
	}
	ro.add(run)
	run.Flags().BoolVar(&local, "local", false, "run on the host instead of Docker (no isolation; testing only)")
	run.Flags().IntVar(&parallel, "parallel", 2, "concurrent trials")
	run.Flags().Uint64Var(&seed, "seed", 1, "bootstrap seed (reproducible CIs)")
	run.Flags().StringSliceVar(&passEnv, "pass-env", nil, "host env vars (UPPER_SNAKE) forwarded into the agent step only")
	run.Flags().StringVar(&network, "network", "none", "docker network for trials (default none: no egress)")
	run.Flags().StringVar(&memory, "memory", "4g", "docker memory limit per trial")
	run.Flags().StringVar(&cpus, "cpus", "2", "docker CPU limit per trial")
	c.AddCommand(run, a.cmdEvalOnline())
	return c
}
