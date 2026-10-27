package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/roi"
)

// roiStoreFlags selects where delivery outcomes live: ClickHouse or a local
// JSONL file.
type roiStoreFlags struct {
	ch    clickhouseFlags
	store string
}

func (f *roiStoreFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&f.ch.url, "clickhouse", "", "ClickHouse HTTP URL (table halo_delivery_prs; AI spend from halo_metrics)")
	c.Flags().StringVar(&f.ch.db, "database", "", "ClickHouse database")
	c.Flags().StringVar(&f.ch.user, "user", "", "ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD)")
	c.Flags().StringVar(&f.store, "store", "", "local JSONL store instead of ClickHouse (no AI spend data)")
}

func (f *roiStoreFlags) open() (roi.Store, roi.CostSource, *promote.ClickHouse, error) {
	var ch *promote.ClickHouse
	if f.ch.url != "" {
		ch = f.ch.client()
	}
	st, cost, err := roi.Open(ch, f.store)
	return st, cost, ch, err
}

func (a *app) cmdROI() *cobra.Command {
	c := &cobra.Command{Use: "roi", Short: "Delivery ROI of a policy change: PR outcomes per experiment arm (ADR-0027)"}
	ingest := &cobra.Command{Use: "ingest", Short: "Import pull-request outcomes (read-only on the source)"}

	var gh roiStoreFlags
	var repos []string
	var since, tokenEnv, graphqlURL, hotfix string
	github := &cobra.Command{
		Use:   "github",
		Short: "Import pull requests from GitHub (GraphQL, read-only query)",
		Long: "Import pull requests created since --since from each --repo: author, opened/merged times, review rounds " +
			"(change requests + 1 once reviewed), lines changed, and the change-failure proxy (a merged revert " +
			"\"Reverts owner/repo#N\" or a merged PR labelled --hotfix-label that references #N). Titles and bodies are " +
			"read to find those references but never stored. The token comes only from the variable named by --token-env.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			from, err := roi.ParseTime(since)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			if from.IsZero() {
				return errors.New("--since is required")
			}
			st, _, _, err := gh.open()
			if err != nil {
				return err
			}
			g := &roi.GitHub{URL: graphqlURL, Token: os.Getenv(tokenEnv), HotfixLabel: hotfix}
			if g.Token == "" {
				return fmt.Errorf("github token: %s is not set", tokenEnv)
			}
			var all []roi.PR
			for _, r := range repos {
				prs, err := g.Fetch(cmd.Context(), r, from)
				if err != nil {
					return err
				}
				all = append(all, prs...)
			}
			if err := st.Put(cmd.Context(), all); err != nil {
				return err
			}
			return a.emit(map[string]any{"imported": len(all), "repos": repos, "since": from}, func() {
				fmt.Fprintf(a.out, "%s %d pull requests from %s since %s\n", a.green("imported"), len(all), strings.Join(repos, ", "), from.Format(time.DateOnly))
			})
		},
	}
	gh.add(github)
	github.Flags().StringSliceVar(&repos, "repo", nil, "owner/name (repeatable, required)")
	github.Flags().StringVar(&since, "since", "", "import PRs created at or after this date (YYYY-MM-DD or RFC 3339, required)")
	github.Flags().StringVar(&tokenEnv, "token-env", "HALO_GITHUB_TOKEN", "environment variable holding a read-only GitHub token")
	github.Flags().StringVar(&graphqlURL, "graphql-url", roi.GitHubGraphQL, "GraphQL endpoint (GitHub Enterprise Server: https://HOST/api/graphql)")
	github.Flags().StringVar(&hotfix, "hotfix-label", "hotfix", "label of a hotfix PR; it marks each PR it references (#N) as a change failure")
	_ = github.MarkFlagRequired("repo")
	_ = github.MarkFlagRequired("since")

	var fs roiStoreFlags
	file := &cobra.Command{
		Use:   "file <path.csv|path.jsonl>...",
		Short: "Import outcomes from a generic CSV/JSONL export (any SCM or tracker)",
		Long: "Each record is one change: repo, number, author (SCM login) or subject (Halos user id), opened_at, " +
			"merged_at (empty = not merged), review_rounds, additions, deletions, change_failure, bot, source. CSV needs a " +
			"header row naming those columns; JSONL uses the same keys. Times are RFC 3339 or YYYY-MM-DD.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, _, _, err := fs.open()
			if err != nil {
				return err
			}
			var all []roi.PR
			for _, p := range args {
				prs, err := roi.ReadFile(p)
				if err != nil {
					return err
				}
				all = append(all, prs...)
			}
			if err := st.Put(cmd.Context(), all); err != nil {
				return err
			}
			return a.emit(map[string]any{"imported": len(all), "files": args}, func() {
				fmt.Fprintf(a.out, "%s %d records from %s\n", a.green("imported"), len(all), strings.Join(args, ", "))
			})
		},
	}
	fs.add(file)
	ingest.AddCommand(github, file)

	var rs roiStoreFlags
	var o roiReportFlags
	report := &cobra.Command{
		Use:   "report",
		Short: "Estimate delivery effects per experiment arm (randomized) or compare rings (observational)",
		Long: "Maps PR authors to Halos subjects with --identities (CSV login,subject[,groups][,kind]), recovers each " +
			"developer's arm with the fleet's own assignment, and estimates per arm: PR cycle time, merged PRs per " +
			"developer-week, review rounds, change-failure rate and lines changed, with developer-clustered bootstrap " +
			"CIs, an SRM check, time slices for novelty, and cost per merged PR when ClickHouse has AI spend. Only " +
			"--experiment is randomized; --rings is labelled observational. Informational: nothing promotes on it.",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			st, cost, ch, err := rs.open()
			if err != nil {
				return err
			}
			rep, err := a.roiReport(cmd.Context(), &o, org, st, cost, ch)
			if err != nil {
				return err
			}
			return a.emit(rep, func() { a.printROI(rep) })
		},
	}
	rs.add(report)
	o.add(report)
	c.AddCommand(ingest, report)
	return c
}

type roiReportFlags struct {
	experiment, identities, since, until string
	rings                                []string
	slices, minDevs                      int
	mde                                  float64
	seed                                 uint64
}

func (f *roiReportFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&f.experiment, "experiment", "", "experiment whose variants are the arms (randomized)")
	c.Flags().StringSliceVar(&f.rings, "rings", nil, "compare rings instead, the first as baseline (observational)")
	c.Flags().StringVar(&f.identities, "identities", "", "identity roster CSV: login,subject[,groups][,kind] (required)")
	c.Flags().StringVar(&f.since, "since", "", "window start (YYYY-MM-DD or RFC 3339); default: the experiment's first telemetry in ClickHouse")
	c.Flags().StringVar(&f.until, "until", "", "window end (default now)")
	c.Flags().IntVar(&f.slices, "slices", 3, "time slices for the novelty check (< 2 = off)")
	c.Flags().IntVar(&f.minDevs, "min-developers", 10, "developers with data per arm before a metric is estimated")
	c.Flags().Float64Var(&f.mde, "mde", 0.10, "relative effect a null result must have been powered to detect")
	c.Flags().Uint64Var(&f.seed, "seed", 1, "bootstrap seed (reproducible CIs)")
	_ = c.MarkFlagRequired("identities")
}

func (a *app) roiReport(ctx context.Context, f *roiReportFlags, org *policy.Org, st roi.Store, cost roi.CostSource, ch *promote.ClickHouse) (*roi.Report, error) {
	ids, err := roi.LoadIdentities(f.identities)
	if err != nil {
		return nil, err
	}
	o := roi.Options{Org: org, Rings: f.rings, Slices: f.slices, MinDevelopers: f.minDevs, MDE: f.mde, Seed: f.seed}
	if f.experiment != "" {
		e, err := a.findExp(org, f.experiment)
		if err != nil {
			return nil, err
		}
		o.Experiment = e
	}
	if o.From, o.To, err = roi.Window(ctx, ch, o.Experiment, f.since, f.until, time.Now()); err != nil {
		return nil, fmt.Errorf("roi report: %w", err)
	}
	return roi.Analyze(ctx, st, cost, ids, o)
}

func (a *app) printROI(r *roi.Report) {
	name := r.Experiment
	if name == "" {
		name = strings.Join(r.Rings, " vs ")
	}
	fmt.Fprintf(a.out, "%s: %s, status %s\n  %s\n  window %s .. %s\n", name, a.bold(r.Design), r.Status, r.Claim,
		r.From.Format(time.DateOnly), r.To.Format(time.DateOnly))
	if r.SRM != nil {
		fmt.Fprintf(a.out, "  SRM: chi2 %.2f p %.3g mismatch %t\n", r.SRM.Chi2, r.SRM.PValue, r.SRM.Mismatch)
	}
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nARM\tDEVELOPERS\tACTIVE\tPRS\tMERGED\tCOST/MERGED PR")
	for _, arm := range r.Arms {
		c := "-"
		if arm.CostPerMergedPR > 0 {
			c = fmt.Sprintf("$%.2f (%s)", arm.CostPerMergedPR, r.CostSource)
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%s\n", arm.Name, arm.Developers, arm.Active, arm.PRs, arm.Merged, c)
	}
	fmt.Fprintf(tw, "\nMETRIC\tARM\t%s\tARM VALUE\tDIFF [95%% CI]\tREL\tSTATE\n", r.Control)
	for _, e := range r.Effects {
		if e.State == roi.StateInsufficientData {
			fmt.Fprintf(tw, "%s\t%s\t\t\t\t\t%s (n=%d/%d)\n", e.Metric, e.Arm, e.State, e.NC, e.NT)
			continue
		}
		state := e.State
		if e.Outcome != "" {
			state += ", " + e.Outcome
		}
		if e.Novelty {
			state += ", novelty"
		}
		fmt.Fprintf(tw, "%s\t%s\t%.3g\t%.3g\t%+.3g [%+.3g, %+.3g]\t%+.1f%%\t%s\n", e.Metric, e.Arm, e.Control, e.Treatment, e.Effect, e.CILo, e.CIHi, 100*e.Rel, state)
	}
	tw.Flush()
	for _, w := range r.Warnings {
		fmt.Fprintf(a.out, "%s %s\n", a.yellow("warning:"), w)
	}
}

// roiSection is the delivery-ROI Markdown for a promotion PR, from ClickHouse
// over [the experiment's first telemetry, now). It never blocks a promotion:
// any failure is a warning and the PR goes out without the section.
func (a *app) roiSection(ctx context.Context, ch *promote.ClickHouse, org *policy.Org, e *policy.Experiment, identities string) string {
	section, err := func() (string, error) {
		ids, err := roi.LoadIdentities(identities)
		if err != nil {
			return "", err
		}
		w, err := ch.Window(ctx, e.Name)
		if err != nil || w.Start.IsZero() {
			return "", err
		}
		st := roi.ClickHouseStore{CH: ch}
		return roi.PromotionSection(ctx, st, st, ids, org, e, w.Start, time.Now().UTC())
	}()
	if err != nil {
		fmt.Fprintf(a.errw, "warning: delivery ROI left out of the PR: %v\n", err)
	}
	return section
}
