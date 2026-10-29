package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/copilot"
	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/impact"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/roi"
)

// copilotFlags configure the model and the per-run ceilings (ADR-0035).
type copilotFlags struct {
	offline, debug           bool
	model, url, wire, keyEnv string
	budget                   copilot.Budget
}

func (f *copilotFlags) add(c *cobra.Command) {
	fl := c.Flags()
	fl.BoolVar(&f.offline, "offline", false, "deterministic templates, no model call (air-gapped, tests)")
	fl.BoolVar(&f.debug, "debug", false, "log prompts and replies to stderr (default: token counts only)")
	fl.StringVar(&f.model, "model", copilot.DefaultModel, "pinned model id")
	fl.StringVar(&f.url, "llm-url", "", "provider or gateway base URL (default: the policy's gateway baseURL, e.g. a halo-proxy, else https://api.anthropic.com)")
	fl.StringVar(&f.wire, "wire", eval.WireAnthropic, "provider wire: anthropic-messages | openai-responses")
	fl.StringVar(&f.keyEnv, "api-key-env", "ANTHROPIC_API_KEY", "env var holding the provider credential (never printed)")
	fl.IntVar(&f.budget.MaxIterations, "max-iterations", 3, "model calls per run (hard ceiling)")
	fl.IntVar(&f.budget.MaxTokens, "max-tokens", 60000, "input+output tokens per run (hard ceiling)")
	fl.Float64Var(&f.budget.MaxCostUSD, "max-cost-usd", 2, "estimated spend per run in USD (hard ceiling)")
	fl.Float64Var(&f.budget.PriceInPerMTok, "price-in", 5, "USD per million input tokens, for the cost estimate")
	fl.Float64Var(&f.budget.PriceOutPerMTok, "price-out", 25, "USD per million output tokens, for the cost estimate")
}

// client builds the copilot client; offline needs no model or credential.
func (f *copilotFlags) client(a *app, org *policy.Org) (*copilot.Client, error) {
	c := &copilot.Client{Model: f.model, Budget: f.budget, Log: a.errw, Debug: f.debug}
	if f.offline {
		return c, nil
	}
	url := f.url
	if url == "" {
		url = "https://api.anthropic.com"
		if org != nil && org.Gateway != nil && org.Gateway.BaseURL != "" {
			url = org.Gateway.BaseURL // route through the org's gateway (halo-proxy or Kong)
		}
	}
	if f.keyEnv != "" && os.Getenv(f.keyEnv) == "" {
		return nil, fmt.Errorf("copilot: $%s is not set; export the provider credential there (or pass --api-key-env, or --offline)", f.keyEnv)
	}
	llm, err := eval.NewHTTPLLM(&eval.JudgeConfig{URL: url, Wire: f.wire, Model: f.model, APIKeyEnv: f.keyEnv})
	if err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}
	c.LLM = llm
	return c, nil
}

func (a *app) cmdCopilot() *cobra.Command {
	c := &cobra.Command{Use: "copilot", Short: "AI-assisted policy operations: the model drafts, Halos verifies, a human approves (ADR-0035)",
		Long: "The model proposes; Halos' validator, plan, impact preview, bypass-token check and internal/stats verify; a human\n" +
			"approves. Nothing is written without --apply, and --apply only commits to a new local branch: pushing, the PR and\n" +
			"merging are human steps. Each model call logs its token counts to stderr; --offline needs no model."}
	c.AddCommand(a.cmdCopilotDraft(), a.cmdCopilotExperiment(), a.cmdCopilotExplain(), a.cmdCopilotNext())
	return c
}

func (a *app) cmdCopilotDraft() *cobra.Command {
	var f copilotFlags
	var apply bool
	c := &cobra.Command{
		Use: "draft <intent>", Short: "Turn an intent into a verified policy diff (validate, plan, impact); --apply commits it to a local branch",
		Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		Example: `  halo copilot draft "move ring1-canary to Claude Code 2.1.300"
  halo copilot draft --offline "set claude-code version 2.1.300 in profile engineering" --apply`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			cl, err := f.client(a, org)
			if err != nil {
				return err
			}
			res, err := cl.Draft(cmd.Context(), dir, args[0])
			if err != nil {
				return err
			}
			out := map[string]any{"draft": res}
			var branch string
			if apply && res.OK {
				body := fmt.Sprintf("Intent: %s\n\nDrafted by halo copilot (%s); verified by validate, plan and the impact preview.", res.Intent, draftedBy(cl))
				if branch, _, _, err = copilot.Apply(cmd.Context(), nil, dir, res.Files, res.Intent, "halo copilot: "+firstLine(res.Summary), body); err != nil {
					return err
				}
				out["branch"] = branch
			}
			if err := a.emit(out, func() {
				a.printDraft(res.Intent, res.OK, res.Summary, res.Iterations, res.Stopped, res.Check, res.ModelRisks, res.Spend, cl)
			}); err != nil {
				return err
			}
			return a.finishApply(dir, res.OK, apply, branch)
		},
	}
	f.add(c)
	c.Flags().BoolVar(&apply, "apply", false, "commit the verified draft to a new local halos/copilot-* branch (never pushes)")
	return c
}

func draftedBy(c *copilot.Client) string {
	if c.Offline() {
		return "offline template"
	}
	return "model " + c.Model
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

// finishApply prints the human gate after an apply, or refuses with exit 2
// when the draft did not pass its checks.
func (a *app) finishApply(dir string, ok, apply bool, branch string) error {
	if !ok {
		return &exitErr{code: exitValidation, err: errors.New("copilot: the draft does not pass Halos' checks; nothing was written")}
	}
	if !apply {
		if !a.json {
			fmt.Fprintln(a.out, "\nnothing written; re-run with --apply to commit this to a local branch")
		}
		return nil
	}
	if !a.json {
		fmt.Fprintf(a.out, "\n%s committed to local branch %s\nhuman gate: git -C %s push -u origin %s && gh pr create --head %s --fill; then review and merge\n",
			a.green("ok"), branch, dir, branch, branch)
	}
	return nil
}

func (a *app) printDraft(intent string, ok bool, summary string, iters int, stopped string, chk *copilot.Check, modelRisks []string, sp copilot.Spend, c *copilot.Client) {
	fmt.Fprintf(a.out, "%s %s (%s, %d iteration(s))\n", a.bold("intent:"), intent, draftedBy(c), iters)
	if summary != "" {
		fmt.Fprintf(a.out, "%s %s\n", a.bold("summary:"), summary)
	}
	if chk != nil {
		if chk.Diff != "" {
			fmt.Fprintln(a.out, a.bold("\npolicy diff:"))
			fmt.Fprint(a.out, chk.Diff)
		}
		for _, p := range chk.Plans {
			if p.Changed {
				fmt.Fprintf(a.out, "%s ring %s: %s -> %s\n", a.bold("plan:"), p.Ring, p.From, p.To)
			}
		}
		if chk.Impact != nil {
			fmt.Fprint(a.out, "\n"+chk.Impact.Text("the current policy"))
		}
		for _, e := range chk.Errors {
			fmt.Fprintln(a.out, a.red("error:"), e)
		}
		for _, w := range chk.Warnings {
			fmt.Fprintln(a.out, a.yellow("warning:"), w)
		}
		for _, r := range chk.Risks {
			fmt.Fprintln(a.out, a.yellow("risk:"), r)
		}
	}
	for _, r := range modelRisks {
		fmt.Fprintln(a.out, a.yellow("risk (model):"), r)
	}
	if stopped != "" {
		fmt.Fprintln(a.out, a.red("stopped:"), stopped)
	}
	if ok {
		fmt.Fprintln(a.out, a.green("checks pass"))
	}
	if sp.Calls > 0 {
		fmt.Fprintf(a.out, "spend: %d call(s), %d input + %d output tokens, ~$%.4f\n", sp.Calls, sp.InputTokens, sp.OutputTokens, sp.CostUSD)
	}
}

func (a *app) cmdCopilotExperiment() *cobra.Command {
	var f copilotFlags
	var apply bool
	var s copilot.Sizing
	var name, axis, ring, control, treatment, metric, direction string
	c := &cobra.Command{
		Use: "experiment <hypothesis>", Short: "Design an experiment: arms and metrics proposed, sample size and duration computed by internal/stats",
		Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		Example: `  halo copilot experiment "opus-5-5 raises accept rate without hurting latency" --baseline 0.31 --mde 0.05 --daily-units 400
  halo copilot experiment --offline "cli-next raises accept rate" --name cli-next-accept --ring ring1-canary \
    --control engineering --treatment engineering-next --metric halo.edit.accept_rate --baseline 0.31 --mde 0.05`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			cl, err := f.client(a, org)
			if err != nil {
				return err
			}
			var d *copilot.Design
			if f.offline {
				if name == "" || ring == "" || control == "" || treatment == "" || metric == "" {
					return errors.New("--offline needs --name, --ring, --control, --treatment and --metric")
				}
				d = &copilot.Design{Name: name, Axis: policy.Axis(axis), Rings: []string{ring}, Rationale: "offline template",
					Variants: []policy.Variant{{Name: "control", Weight: 50, Profile: control, Control: true}, {Name: "treatment", Weight: 50, Profile: treatment}},
					Primary:  policy.MetricGoal{Metric: metric, Direction: direction},
					Guardrails: []policy.MetricGoal{
						{Metric: "halo.tool.error_rate", Direction: "decrease", MaxRegression: 0.10},
						{Metric: "halo.api.error_rate", Direction: "decrease", MaxRegression: 0.02},
						{Metric: "halo.latency.p95_ms", Direction: "decrease", MaxRegression: 0.10},
					}}
			}
			res, err := cl.Experiment(cmd.Context(), dir, args[0], d, s)
			if err != nil {
				return err
			}
			out := map[string]any{"experiment": res}
			var branch string
			if apply && res.OK {
				body := fmt.Sprintf("Hypothesis: %s\n\nDesigned by halo copilot (%s); sample size by internal/stats; status draft.", res.Hypothesis, draftedBy(cl))
				if branch, _, _, err = copilot.Apply(cmd.Context(), nil, dir, []copilot.File{*res.File}, res.Design.Name, "halo copilot: draft experiment "+res.Design.Name, body); err != nil {
					return err
				}
				out["branch"] = branch
			}
			if err := a.emit(out, func() {
				if st := res.Stats; st != nil {
					fmt.Fprintf(a.out, "%s %s\n", a.bold("experiment:"), res.Design.Name)
					fmt.Fprintf(a.out, "  sd %.4g%s, absolute MDE %.4g; %s\n", st.SD, map[bool]string{true: " (derived from the baseline rate)"}[st.SDDerived], st.AbsoluteMDE, st.Formula)
					fmt.Fprintf(a.out, "  per arm: %d, total: %d", st.PerArm, st.Total)
					if st.Days > 0 {
						fmt.Fprintf(a.out, ", about %d day(s)", st.Days)
					}
					fmt.Fprintf(a.out, "; maxDays %d\n", st.MaxDays)
				}
				for _, n := range res.Notes {
					fmt.Fprintln(a.out, "  note:", n)
				}
				var summary string
				if res.Design != nil {
					summary = res.Design.Rationale
				}
				a.printDraft(res.Hypothesis, res.OK, summary, res.Spend.Calls, res.Stopped, res.Check, nil, res.Spend, cl)
			}); err != nil {
				return err
			}
			return a.finishApply(dir, res.OK, apply, branch)
		},
	}
	f.add(c)
	fl := c.Flags()
	fl.BoolVar(&apply, "apply", false, "commit the experiment (status draft) to a new local halos/copilot-* branch (never pushes)")
	fl.Float64Var(&s.Baseline, "baseline", 0, "current mean of the primary metric (required)")
	fl.Float64Var(&s.SD, "sd", 0, "per-user standard deviation of the primary metric (default: sqrt(p(1-p)) for a rate)")
	fl.Float64Var(&s.MDE, "mde", 0.05, "relative minimum detectable effect (0.05 = 5%)")
	fl.Float64Var(&s.Alpha, "alpha", 0.05, "significance level")
	fl.Float64Var(&s.Power, "power", 0.8, "statistical power")
	fl.Float64Var(&s.DailyUnits, "daily-units", 0, "users entering the experiment per day (for the duration)")
	fl.StringVar(&name, "name", "", "offline: experiment name")
	fl.StringVar(&axis, "axis", string(policy.AxisClient), "offline: client | traffic")
	fl.StringVar(&ring, "ring", "", "offline: ring to draw users from")
	fl.StringVar(&control, "control", "", "offline: control profile")
	fl.StringVar(&treatment, "treatment", "", "offline: treatment profile")
	fl.StringVar(&metric, "metric", "", "offline: primary halo.* metric")
	fl.StringVar(&direction, "direction", "increase", "offline: increase | decrease")
	return c
}

func (a *app) cmdCopilotExplain() *cobra.Command {
	var f copilotFlags
	var diffBase, verdicts, scorecard, roiFile string
	c := &cobra.Command{
		Use:   "explain release <ring> | diff <git-ref> | experiment <name>",
		Short: "Explain a release, a policy diff or an experiment in plain language, citing only Halos outputs",
		Args:  cobra.ExactArgs(2), Annotations: policyDirAnno,
		Example: `  halo copilot explain diff main
  halo copilot explain release ring1-canary --diff main
  halo copilot explain experiment opus-5-5-canary --verdicts-file verdicts.json --offline`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			var facts []copilot.Fact
			switch args[0] {
			case "release":
				var base *policy.Org
				if diffBase != "" {
					bd, cleanup, err := impact.CheckoutAt(cmd.Context(), dir, diffBase)
					if err != nil {
						return err
					}
					defer cleanup()
					if base, err = a.load(bd); err != nil {
						return fmt.Errorf("policy at %s: %w", diffBase, err)
					}
				}
				facts, err = copilot.ReleaseFacts(base, org, args[1])
			case "diff":
				bd, cleanup, cerr := impact.CheckoutAt(cmd.Context(), dir, args[1])
				if cerr != nil {
					return cerr
				}
				defer cleanup()
				facts, err = copilot.DiffFacts(bd, dir)
			case "experiment":
				facts, err = a.experimentFacts(org, args[1], verdicts, scorecard, roiFile)
			default:
				return fmt.Errorf("explain %q: want release, diff or experiment", args[0])
			}
			if err != nil {
				return err
			}
			cl, err := f.client(a, org)
			if err != nil {
				return err
			}
			ex, err := cl.Explain(cmd.Context(), args[0]+" "+args[1], facts)
			if err != nil {
				return err
			}
			if err := a.emit(ex, func() {
				fmt.Fprintln(a.out, ex.Summary)
				for _, p := range ex.Points {
					fmt.Fprintf(a.out, "- %s [%s]\n", p.Text, strings.Join(p.Cites, ", "))
				}
				if ex.Stopped != "" {
					fmt.Fprintln(a.out, a.red("stopped:"), ex.Stopped)
				}
				if len(ex.Used) > 0 {
					fmt.Fprintln(a.out, a.bold("\nfacts used:"))
					for _, u := range ex.Used {
						fmt.Fprintf(a.out, "  %s = %s\n", u.Key, firstLine(u.Value))
					}
				}
			}); err != nil {
				return err
			}
			if ex.Summary == "" {
				return &exitErr{code: exitError, err: errors.New("copilot: no explanation passed the citation check")}
			}
			return nil
		},
	}
	f.add(c)
	c.Flags().StringVar(&diffBase, "diff", "", "release: git ref of the policy to compare with (default: an empty release)")
	c.Flags().StringVar(&verdicts, "verdicts-file", "", "experiment: verdicts JSON array (halo exp analyze --verdicts-file)")
	c.Flags().StringVar(&scorecard, "scorecard", "", "experiment: eval scorecard JSON")
	c.Flags().StringVar(&roiFile, "roi", "", "experiment: ROI report JSON (halo roi report --output json)")
	return c
}

// experimentFacts are the experiment's settings plus whatever evidence files
// were given.
func (a *app) experimentFacts(org *policy.Org, name, verdicts, scorecard, roiFile string) ([]copilot.Fact, error) {
	e, err := a.findExp(org, name)
	if err != nil {
		return nil, err
	}
	facts, err := copilot.Flatten("experiment", e)
	if err != nil {
		return nil, err
	}
	add := func(prefix string, v any) error {
		f, err := copilot.Flatten(prefix, v)
		facts = append(facts, f...)
		return err
	}
	if verdicts != "" {
		vs, err := copilot.ReadVerdicts(verdicts)
		if err != nil {
			return nil, err
		}
		for _, v := range vs {
			if v.Experiment == name {
				if err := add("verdict", v); err != nil {
					return nil, err
				}
			}
		}
	}
	if scorecard != "" {
		var sc eval.Scorecard
		if err := copilot.ReadJSON(scorecard, &sc); err != nil {
			return nil, err
		}
		sc.Trials = nil // per-trial detail is noise for an explanation
		if err := add("scorecard", sc); err != nil {
			return nil, err
		}
	}
	if roiFile != "" {
		var r roi.Report
		if err := copilot.ReadJSON(roiFile, &r); err != nil {
			return nil, err
		}
		if err := add("roi", r); err != nil {
			return nil, err
		}
	}
	return facts, nil
}

func (a *app) cmdCopilotNext() *cobra.Command {
	var verdicts, roiFile string
	var scorecards []string
	var sf serverFlags
	c := &cobra.Command{
		Use: "next", Short: "Suggest next steps from experiment verdicts, eval scorecards, ROI and budgets, each with evidence and the command",
		Long: "Deterministic rules over existing data; no model is called. Commands marked [human gate] change state:\n" +
			"a human runs them.",
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
			in := copilot.NextInput{Org: org, PolicyDir: dir, Scorecards: map[string]*eval.Scorecard{}}
			if verdicts != "" {
				if in.Verdicts, err = copilot.ReadVerdicts(verdicts); err != nil {
					return err
				}
			}
			for _, p := range scorecards {
				var sc eval.Scorecard
				if err := copilot.ReadJSON(p, &sc); err != nil {
					return err
				}
				in.Scorecards[p] = &sc
			}
			if roiFile != "" {
				in.ROI = &roi.Report{}
				if err := copilot.ReadJSON(roiFile, in.ROI); err != nil {
					return err
				}
			}
			srv, session, err := sf.resolve()
			if err != nil {
				return err
			}
			if srv != "" {
				res, err := getBudgets(cmd.Context(), http.DefaultClient, srv, session, "", "")
				if err != nil {
					return fmt.Errorf("copilot next: budgets: %w", err)
				}
				for _, b := range res.Budgets {
					in.Budgets = append(in.Budgets, copilot.BudgetState{Budget: b.Budget, Key: b.Key, Utilization: b.Utilization(), Exceeded: b.Exceeded(), Alert: b.Alert() > 0})
				}
			}
			sugg, err := copilot.Next(in)
			if err != nil {
				return err
			}
			return a.emit(map[string]any{"suggestions": sugg}, func() {
				if len(sugg) == 0 {
					fmt.Fprintln(a.out, "nothing to suggest from the data given")
					return
				}
				for i, s := range sugg {
					gate := ""
					if s.HumanGate {
						gate = " " + a.yellow("[human gate]")
					}
					fmt.Fprintf(a.out, "%d. %s%s\n", i+1, a.bold(s.Title), gate)
					for _, e := range s.Evidence {
						fmt.Fprintln(a.out, "   evidence:", e)
					}
					fmt.Fprintln(a.out, "   $", s.Command)
				}
			})
		},
	}
	c.Flags().StringVar(&verdicts, "verdicts-file", "", "verdicts JSON array (halo exp analyze --verdicts-file)")
	c.Flags().StringSliceVar(&scorecards, "scorecard", nil, "eval scorecard JSON (repeatable)")
	c.Flags().StringVar(&roiFile, "roi", "", "ROI report JSON (halo roi report --output json)")
	sf.add(c, "for budget counters")
	return c
}
