package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/shadow"
	"github.com/dshakes/halos/internal/telemetry"
)

// evalRunFlags are `halo eval run`'s matrix/report/gate flags.
type evalRunFlags struct {
	matrix            bool
	report, scorecard string
	history, failOn   string
}

func (f *evalRunFlags) add(c *cobra.Command) {
	c.Flags().BoolVar(&f.matrix, "matrix", false, "run the suite's matrix (harness x model x provider) instead of its variants")
	c.Flags().StringVar(&f.report, "report", "", "also write the Markdown report (PR-comment ready) to this file")
	c.Flags().StringVar(&f.scorecard, "scorecard", "", "also write the scorecard JSON to this file")
	c.Flags().StringVar(&f.history, "history", "", "append a summary line to this scorecard history (JSONL)")
	c.Flags().StringVar(&f.failOn, "fail-on", "none", "exit 3 when the gate verdict is at least: block | hold | none")
}

// exitGate is the exit code when --fail-on trips.
const exitGate = 3

// runSuite loads the tasks, builds the judge (if the suite has one), runs
// every trial and builds the scorecard.
func runSuite(ctx context.Context, s *eval.Suite, r eval.Runner, parallel int, seed uint64) (*eval.Scorecard, error) {
	tasks, err := s.LoadTasks("")
	if err != nil {
		return nil, err
	}
	j, err := eval.NewJudge(s.Judge, s.Dir)
	if err != nil {
		return nil, err
	}
	trials, err := eval.RunSuiteWith(ctx, s, tasks, r, eval.Drivers(), eval.RunOptions{Parallel: parallel, Judge: j})
	if err != nil {
		return nil, fmt.Errorf("run suite %s: %w", s.Name, err)
	}
	return eval.BuildScorecard(s, trials, seed)
}

func (a *app) writeScorecard(sc *eval.Scorecard, f evalRunFlags) error {
	switch f.failOn {
	case "none", eval.GateBlock, eval.GateHold:
	default:
		return fmt.Errorf("--fail-on must be block, hold or none, got %q", f.failOn)
	}
	b, err := sc.JSON()
	if err != nil {
		return err
	}
	if f.scorecard != "" {
		if err := writeFile(f.scorecard, append(b, '\n'), 0o644); err != nil {
			return fmt.Errorf("write scorecard: %w", err)
		}
	}
	if f.report != "" {
		if err := writeFile(f.report, []byte(sc.Markdown()), 0o644); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	if f.history != "" {
		if err := eval.AppendHistory(f.history, eval.OfflineHistory(sc, time.Now())); err != nil {
			return err
		}
	}
	switch {
	case a.json:
		if _, err := a.out.Write(append(b, '\n')); err != nil {
			return err
		}
	case f.matrix:
		fmt.Fprint(a.out, sc.Table())
	default:
		fmt.Fprint(a.out, sc.Markdown())
	}
	if sc.Gate != nil && f.failOn != "none" && (sc.Gate.Verdict == eval.GateBlock || sc.Gate.Verdict == f.failOn) {
		return &exitErr{code: exitGate, err: fmt.Errorf("eval gate: %s", sc.Gate.Verdict)}
	}
	return nil
}

func (a *app) cmdEvalOnline() *cobra.Command {
	var pairs, rubric, history, experiment, otlp, otlpTokenFile, polDir string
	var keyFiles []string
	var allowPlain bool
	var jc eval.JudgeConfig
	var sample int
	var seed uint64
	c := &cobra.Command{
		Use:   "online",
		Short: "Grade sampled halo-shadow pairs with the judge rubric; emit halo.eval.* metrics and append history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := eval.LoadRubric(rubric)
			if err != nil {
				return err
			}
			j, err := eval.NewJudge(&jc, ".")
			if err != nil {
				return err
			}
			keys, err := readPairKeys(keyFiles)
			if err != nil {
				return err
			}
			skip, agentSkip := map[string]bool{}, map[string]bool{}
			if history != "" {
				if skip, agentSkip, err = eval.HistoryIDs(history); err != nil {
					return err
				}
			}
			controls := map[string]string{}
			if polDir != "" {
				org, err := a.load(polDir)
				if err != nil {
					return err
				}
				for _, e := range org.Experiments {
					for _, v := range e.Variants {
						if v.Control {
							controls[e.Name] = v.Name
						}
					}
				}
			}
			start := time.Now()
			rs, err := eval.RunOnline(cmd.Context(), eval.FilePairs{Path: pairs, Keys: keys, AllowPlaintext: allowPlain}, eval.OnlineOptions{
				Judge: j, Rubric: r, Sample: sample, Seed: seed, Experiment: experiment, Skip: skip, AgentSkip: agentSkip, ControlNames: controls,
			})
			if err != nil {
				return plaintextPairsHint(err)
			}
			if otlp != "" {
				x := &eval.OTLPExporter{URL: otlp}
				if otlpTokenFile != "" {
					b, err := os.ReadFile(otlpTokenFile) //nolint:gosec // operator-supplied path
					if err != nil {
						return fmt.Errorf("otlp token: %w", err)
					}
					x.Token = strings.TrimSpace(string(b))
				}
				if err := x.Export(cmd.Context(), rs, start, time.Now()); err != nil {
					return err
				}
			}
			if history != "" {
				var es []eval.HistoryEntry
				for i := range rs {
					es = append(es, eval.HistoryEntry{Time: time.Now().UTC(), Kind: "online", Online: &rs[i]})
				}
				if err := eval.AppendHistory(history, es...); err != nil {
					return err
				}
			}
			return a.emit(rs, func() { fmt.Fprint(a.out, eval.OnlineTable(rs)) })
		},
	}
	c.Flags().StringVar(&pairs, "pairs", "", "halo-shadow pair store (JSONL) (required)")
	c.Flags().StringSliceVar(&keyFiles, "pair-key-file", nil, "base64 32-byte pair key (repeatable: current and retired)")
	c.Flags().BoolVar(&allowPlain, "allow-plaintext-pairs", false, "with --pair-key-file, also read unsealed rows (a store written before sealing was turned on); off: such rows are refused")
	c.Flags().StringVar(&rubric, "rubric", "", "rubric YAML (required)")
	c.Flags().StringVar(&jc.URL, "judge-url", "", "gateway base URL for the judge (required)")
	c.Flags().StringVar(&jc.Wire, "judge-wire", eval.WireAnthropic, "judge wire: anthropic-messages | openai-responses")
	c.Flags().StringVar(&jc.Model, "judge-model", "", "pinned judge model id (required)")
	c.Flags().StringVar(&jc.APIKeyEnv, "judge-key-env", "", "env var holding the gateway credential")
	c.Flags().StringVar(&jc.Cache, "judge-cache", "", "directory caching judge verdicts")
	c.Flags().IntVar(&sample, "sample", 50, "max pairs graded per experiment (0 = all)")
	c.Flags().Uint64Var(&seed, "seed", 1, "sampling and bootstrap seed")
	c.Flags().StringVar(&experiment, "experiment", "", "only this experiment")
	c.Flags().StringVar(&polDir, "policy-dir", "", "policy repo: labels each experiment's control arm with its control variant name, so `halo exp analyze` matches the arms (default label: control)")
	c.Flags().StringVar(&history, "history", "", "scorecard history JSONL: skip already-graded pairs and append results")
	c.Flags().StringVar(&otlp, "otlp", "", "OTel collector OTLP/HTTP base URL for halo.eval.* metrics: the eval receiver (collector-config --eval-receiver, :4320)")
	c.Flags().StringVar(&otlpTokenFile, "otlp-token-file", "", "bearer token file for the collector's eval receiver ("+telemetry.EvalTokenEnv+"); never the gateway token, which would let eval jobs write trusted gateway evidence")
	for _, f := range []string{"pairs", "rubric", "judge-url", "judge-model"} {
		_ = c.MarkFlagRequired(f)
	}
	return c
}

func readPairKeys(files []string) ([][]byte, error) {
	var keys [][]byte
	for _, f := range files {
		k, err := shadow.ReadKeyFile(f)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (a *app) cmdEvalHarvest() *cobra.Command {
	var pairs, out, history, experiment string
	var keyFiles, sel, patterns, keep []string
	var allowPlain bool
	var o eval.HarvestOptions
	var dry bool
	c := &cobra.Command{
		Use:   "harvest",
		Short: "Turn shadow steps where the candidate regressed into redacted step-level eval cases (ADR-0020)",
		Long: "Reads the halo-shadow pair store, selects steps (the candidate diverged, made an invalid call, stopped early, lost on judge score, " +
			"or a stratified sample by depth) and writes one redacted case per step: the real prefix, the offered tools and production's action. " +
			"Redaction (credentials, JWTs, private keys, high-entropy strings, emails, --redact-pattern; only allowlisted request fields kept) " +
			"always runs and fails closed. Files are 0600. Replay them with `halo eval steps run`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" && !dry {
				return fmt.Errorf("--out is required (or --dry-run)")
			}
			keys, err := readPairKeys(keyFiles)
			if err != nil {
				return err
			}
			if o.Redactor, err = eval.NewRedactor(patterns, keep); err != nil {
				return err
			}
			if history != "" {
				if o.Scores, err = eval.HistoryScores(history); err != nil {
					return err
				}
			}
			o.Experiment, o.Select = experiment, sel
			res, err := eval.Harvest(cmd.Context(), eval.FilePairs{Path: pairs, Keys: keys, AllowPlaintext: allowPlain}, o)
			if err != nil {
				return plaintextPairsHint(err)
			}
			if !dry {
				if err := eval.WriteStepCases(out, res.Cases); err != nil {
					return err
				}
			}
			sum := map[string]any{"dryRun": dry, "out": out, "steps": res.Steps, "selected": len(res.Cases), "skipped": res.Skipped,
				"byReason": res.ByReason, "redactionRules": o.Redactor.Version(), "cases": res.Summary()}
			return a.emit(sum, func() {
				verb := "wrote"
				if dry {
					verb = "would write"
				}
				fmt.Fprintf(a.out, "%d steps read, %d selected, %d skipped (invalid expected action); redaction rules %s\n", res.Steps, len(res.Cases), res.Skipped, o.Redactor.Version())
				for _, r := range []string{eval.SelectDiverged, eval.SelectInvalidCall, eval.SelectPrematureStop, eval.SelectJudgeLoss, eval.SelectSample} {
					if n := res.ByReason[r]; n > 0 {
						fmt.Fprintf(a.out, "  %-15s %d\n", r, n)
					}
				}
				fmt.Fprintf(a.out, "%s %d cases to %s (0600). Review them before committing; replay with: halo eval steps run --suite %s --model ROUTE --url URL\n", verb, len(res.Cases), cmp.Or(out, "(nowhere)"), cmp.Or(out, "DIR"))
			})
		},
	}
	c.Flags().StringVar(&pairs, "pairs", "", "halo-shadow pair store (JSONL) (required)")
	c.Flags().StringSliceVar(&keyFiles, "pair-key-file", nil, "base64 32-byte pair key (repeatable: current and retired)")
	c.Flags().BoolVar(&allowPlain, "allow-plaintext-pairs", false, "with --pair-key-file, also read unsealed rows (a store written before sealing was turned on); off: such rows are refused")
	c.Flags().StringVar(&out, "out", "", "suite directory to write the cases into (created 0700)")
	c.Flags().StringVar(&experiment, "experiment", "", "only this experiment")
	c.Flags().StringSliceVar(&sel, "select", eval.DefaultSelect, "why a step becomes a case: diverged, invalid-call, premature-stop, judge-loss, sample")
	c.Flags().StringVar(&history, "history", "", "`halo eval online` history JSONL: judge scores for --select judge-loss")
	c.Flags().Float64Var(&o.JudgeLoss, "judge-loss", 0.2, "judge-loss: control minus candidate score above which a step is selected")
	c.Flags().IntVar(&o.PerDepth, "per-depth", 5, "sample: steps per depth bucket (0, 1-4, 5-19, 20+)")
	c.Flags().Uint64Var(&o.Seed, "seed", 1, "sampling seed")
	c.Flags().StringArrayVar(&patterns, "redact-pattern", nil, "extra RE2 regex to redact (repeatable)")
	c.Flags().StringSliceVar(&keep, "keep-field", nil, "extra top-level request field to keep (default allowlist: model, system, messages, tools, input, contents...)")
	c.Flags().BoolVar(&dry, "dry-run", false, "select and redact, print the summary, write nothing")
	_ = c.MarkFlagRequired("pairs")
	return c
}

func (a *app) cmdEvalSteps() *cobra.Command {
	c := &cobra.Command{Use: "steps", Short: "Step-level regression suites harvested from shadow traffic"}
	var suite, keyEnv, scorecard, rubric string
	var m eval.StepModel
	var jc eval.JudgeConfig
	var o eval.StepRunOptions
	run := &cobra.Command{
		Use:   "run",
		Short: "Replay each harvested step against a model route and score the next action (deterministic matcher, session-clustered CIs)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cases, err := eval.LoadStepCases(suite)
			if err != nil {
				return err
			}
			if keyEnv != "" {
				m.APIKey = os.Getenv(keyEnv)
			}
			if rubric != "" {
				if o.Rubric, err = eval.LoadRubric(rubric); err != nil {
					return err
				}
				if o.Judge, err = eval.NewJudge(&jc, "."); err != nil {
					return err
				}
			}
			sc, err := eval.RunSteps(cmd.Context(), suite, cases, &m, o)
			if err != nil {
				return err
			}
			if scorecard != "" {
				b, err := json.MarshalIndent(sc, "", "  ")
				if err != nil {
					return fmt.Errorf("encode scorecard: %w", err)
				}
				if err := writeFile(scorecard, append(b, '\n'), 0o644); err != nil {
					return fmt.Errorf("write scorecard: %w", err)
				}
			}
			return a.emit(sc, func() { fmt.Fprint(a.out, sc.Table()) })
		},
	}
	run.Flags().StringVar(&suite, "suite", "", "directory of harvested step cases (required)")
	run.Flags().StringVar(&m.Model, "model", "", "model route: a gateway model alias, or an upstream model id (required)")
	run.Flags().StringVar(&m.URL, "url", "", "gateway (or upstream) base URL; https, or http to loopback (required)")
	run.Flags().StringVar(&keyEnv, "key-env", "", "env var holding the credential (x-api-key, x-goog-api-key or Bearer, by wire)")
	run.Flags().IntVar(&o.Parallel, "parallel", 4, "concurrent model calls")
	run.Flags().Uint64Var(&o.Seed, "seed", 1, "bootstrap seed (reproducible CIs)")
	run.Flags().StringVar(&scorecard, "scorecard", "", "also write the scorecard JSON to this file")
	run.Flags().StringVar(&rubric, "rubric", "", "optional rubric YAML: a secondary judge score per step (never changes pass)")
	run.Flags().StringVar(&jc.URL, "judge-url", "", "gateway base URL for the judge (with --rubric)")
	run.Flags().StringVar(&jc.Wire, "judge-wire", eval.WireAnthropic, "judge wire: anthropic-messages | openai-responses")
	run.Flags().StringVar(&jc.Model, "judge-model", "", "pinned judge model id (with --rubric)")
	run.Flags().StringVar(&jc.APIKeyEnv, "judge-key-env", "", "env var holding the judge's gateway credential")
	for _, f := range []string{"suite", "model", "url"} {
		_ = run.MarkFlagRequired(f)
	}
	c.AddCommand(run)
	return c
}
