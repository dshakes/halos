package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/eval"
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
			var keys [][]byte
			for _, f := range keyFiles {
				k, err := readPairKey(f)
				if err != nil {
					return err
				}
				keys = append(keys, k)
			}
			skip := map[string]bool{}
			if history != "" {
				if skip, err = eval.GradedPairs(history); err != nil {
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
			rs, err := eval.RunOnline(cmd.Context(), eval.FilePairs{Path: pairs, Keys: keys}, eval.OnlineOptions{
				Judge: j, Rubric: r, Sample: sample, Seed: seed, Experiment: experiment, Skip: skip, ControlNames: controls,
			})
			if err != nil {
				return err
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

// readPairKey loads a base64 pair key, as halo-shadow's -pair-key-file does.
func readPairKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read pair key: %w", err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("pair key %s is not base64: %w", path, err)
	}
	return k, nil
}
