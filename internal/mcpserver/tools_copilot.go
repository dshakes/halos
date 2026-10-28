package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/copilot"
	"github.com/dshakes/halos/internal/impact"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// The copilot tools (ADR-0035). Over MCP the calling agent is the model, so
// none of them calls a provider: they run Halos' deterministic checks on what
// the agent proposes, compute statistics, and gather the facts it must cite.

type copilotDraftIn struct {
	Intent string         `json:"intent" jsonschema:"what the change should achieve, in the human's words"`
	Files  []copilot.File `json:"files" jsonschema:"whole new content of each policy-dir-relative .yaml file you change (read halos://policy/<path> first)"`
	Reason string         `json:"reason,omitempty" jsonschema:"why; required with dry_run false, recorded in the commit message"`
	DryRun *bool          `json:"dry_run,omitempty" jsonschema:"default true: run the checks and write nothing"`
}

type copilotOut struct {
	OK        bool           `json:"ok"`
	DryRun    bool           `json:"dry_run"`
	Check     *copilot.Check `json:"check"`
	Branch    string         `json:"branch,omitempty"`
	Commit    string         `json:"commit,omitempty"`
	Stats     *copilot.Stats `json:"stats,omitempty"`
	File      *copilot.File  `json:"file,omitempty"`
	Notes     []string       `json:"notes,omitempty"`
	NextSteps []string       `json:"next_steps"`
}

type copilotExperimentIn struct {
	Hypothesis string              `json:"hypothesis"`
	Name       string              `json:"name" jsonschema:"new experiment name, lowercase letters, digits, . and -"`
	Axis       string              `json:"axis,omitempty" jsonschema:"client (arms are profiles, default) or traffic (arms are model routes)"`
	Rings      []string            `json:"rings"`
	Variants   []policy.Variant    `json:"variants" jsonschema:"two or more arms, exactly one with control true"`
	Primary    policy.MetricGoal   `json:"primary" jsonschema:"primary halo.* metric and direction"`
	Guardrails []policy.MetricGoal `json:"guardrails,omitempty" jsonschema:"halo.* metrics with direction and maxRegression"`
	Baseline   float64             `json:"baseline" jsonschema:"current mean of the primary metric (ask the human; never guess)"`
	SD         float64             `json:"sd,omitempty" jsonschema:"per-user sd; omit for a rate metric to derive sqrt(p(1-p))"`
	MDE        float64             `json:"mde,omitempty" jsonschema:"relative minimum detectable effect, default 0.05"`
	Alpha      float64             `json:"alpha,omitempty"`
	Power      float64             `json:"power,omitempty"`
	DailyUnits float64             `json:"daily_units,omitempty" jsonschema:"users entering per day, for the duration"`
	Reason     string              `json:"reason,omitempty" jsonschema:"why; required with dry_run false"`
	DryRun     *bool               `json:"dry_run,omitempty" jsonschema:"default true: compute and check, write nothing"`
}

type copilotExplainIn struct {
	Kind   string `json:"kind" jsonschema:"release | diff | experiment"`
	Target string `json:"target" jsonschema:"ring name, git ref, or experiment name"`
	Diff   string `json:"diff,omitempty" jsonschema:"release only: git ref of the policy to compare with (default: an empty release)"`
}

const copilotGate = "human gate: show the human the diff, plan, impact and risks above and wait for an explicit yes before dry_run false"

// commitCopilot commits verified files to a local branch, or explains why not.
func (s *srv) commitCopilot(ctx context.Context, dry *bool, reason, cli, slug, subject string, files []copilot.File, out *copilotOut) error {
	r, err := needUnlessDry(dry, reason)
	if err != nil {
		return err
	}
	write, err := s.mayWrite(dry, cli)
	if err != nil {
		return err
	}
	if !write {
		if out.OK {
			out.NextSteps = []string{copilotGate}
		}
		return nil
	}
	if !out.OK {
		return fmt.Errorf("refusing to commit: the checks fail (%s)", strings.Join(out.Check.Errors, "; "))
	}
	b, c, _, err := copilot.Apply(ctx, nil, s.dir, files, slug, subject, "Reason: "+r)
	if err != nil {
		return err
	}
	out.Branch, out.Commit = b, c
	out.NextSteps = []string{fmt.Sprintf("human gate: %s && %s; then review and merge", shJoin("git", "-C", s.dir, "push", "-u", "origin", b), shJoin("gh", "pr", "create", "--head", b, "--fill"))}
	return nil
}

func (s *srv) copilotDraft(ctx context.Context, _ *mcp.CallToolRequest, in copilotDraftIn) (*mcp.CallToolResult, copilotOut, error) {
	out := copilotOut{DryRun: isDry(in.DryRun)}
	if strings.TrimSpace(in.Intent) == "" {
		return nil, out, errors.New("intent is required")
	}
	chk, err := copilot.Verify(s.dir, in.Files)
	if err != nil {
		return nil, out, err
	}
	out.OK, out.Check = chk.OK, chk
	if !chk.OK {
		out.NextSteps = []string{"fix every error in check.errors and call copilot_draft again with the complete files; never add a permission-bypass setting"}
	}
	err = s.commitCopilot(ctx, in.DryRun, in.Reason, "halo copilot draft --apply "+sh(in.Intent), in.Intent, "halo copilot: "+firstLineOf(in.Intent), in.Files, &out)
	return nil, out, err
}

func (s *srv) copilotExperiment(ctx context.Context, _ *mcp.CallToolRequest, in copilotExperimentIn) (*mcp.CallToolResult, copilotOut, error) {
	out := copilotOut{DryRun: isDry(in.DryRun)}
	axis := policy.Axis(in.Axis)
	if axis == "" {
		axis = policy.AxisClient
	}
	if in.MDE == 0 {
		in.MDE = 0.05
	}
	d := &copilot.Design{Name: in.Name, Axis: axis, Rings: in.Rings, Variants: in.Variants, Primary: in.Primary, Guardrails: in.Guardrails, Rationale: in.Hypothesis}
	if d.Guardrails == nil {
		d.Guardrails = []policy.MetricGoal{}
	}
	res, err := (&copilot.Client{}).Experiment(ctx, s.dir, in.Hypothesis, d, copilot.Sizing{Baseline: in.Baseline, SD: in.SD, MDE: in.MDE, Alpha: in.Alpha, Power: in.Power, DailyUnits: in.DailyUnits})
	if err != nil {
		return nil, out, err
	}
	out.OK, out.Check, out.Stats, out.File, out.Notes = res.OK, res.Check, res.Stats, res.File, res.Notes
	if !res.OK {
		out.NextSteps = []string{"fix every error in check.errors (rings and profiles must exist) and call copilot_experiment again"}
		return nil, out, nil
	}
	err = s.commitCopilot(ctx, in.DryRun, in.Reason, "halo copilot experiment --apply ...", in.Name, "halo copilot: draft experiment "+in.Name, []copilot.File{*res.File}, &out)
	if err == nil && out.Branch != "" {
		out.NextSteps = append(out.NextSteps, "after merge, starting the experiment is another human gate: start_experiment "+in.Name)
	}
	return nil, out, err
}

func firstLineOf(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func (s *srv) copilotExplain(ctx context.Context, _ *mcp.CallToolRequest, in copilotExplainIn) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	var facts []copilot.Fact
	switch in.Kind {
	case "release":
		var base *policy.Org
		if in.Diff != "" {
			bd, cleanup, err := impact.CheckoutAt(ctx, s.dir, in.Diff)
			if err != nil {
				return nil, nil, err
			}
			defer cleanup()
			if base, err = policy.Load(bd); err != nil {
				return nil, nil, fmt.Errorf("policy at %s: %w", in.Diff, err)
			}
		}
		facts, err = copilot.ReleaseFacts(base, org, in.Target)
	case "diff":
		bd, cleanup, cerr := impact.CheckoutAt(ctx, s.dir, in.Target)
		if cerr != nil {
			return nil, nil, cerr
		}
		defer cleanup()
		facts, err = copilot.DiffFacts(bd, s.dir)
	case "experiment":
		var e *policy.Experiment
		if e, err = findExp(org, in.Target); err != nil {
			return nil, nil, err
		}
		if facts, err = copilot.Flatten("experiment", e); err == nil && s.ClickHouse != nil {
			rep, aerr := promote.Evaluate(ctx, e, s.ClickHouse)
			if aerr != nil {
				return nil, nil, fmt.Errorf("analyze %s: %w", e.Name, aerr)
			}
			var vf []copilot.Fact
			vf, err = copilot.Flatten("verdict", rep)
			facts = append(facts, vf...)
		}
	default:
		return nil, nil, fmt.Errorf("kind %q: want release, diff or experiment", in.Kind)
	}
	if err != nil {
		return nil, nil, err
	}
	return nil, map[string]any{"facts": facts, "next_steps": []string{
		"explain in plain language using ONLY these facts; cite the fact keys after each claim, and say what the facts do not show"}}, nil
}

func (s *srv) copilotNext(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	in := copilot.NextInput{Org: org, PolicyDir: s.dir}
	if s.ClickHouse != nil {
		for _, e := range org.Experiments {
			if e.Status != "running" {
				continue
			}
			rep, err := promote.Evaluate(ctx, e, s.ClickHouse)
			if err != nil {
				return nil, nil, fmt.Errorf("analyze %s: %w", e.Name, err)
			}
			in.Verdicts = append(in.Verdicts, copilot.Verdict{Experiment: e.Name, Report: rep})
		}
	}
	sugg, err := copilot.Next(in)
	if err != nil {
		return nil, nil, err
	}
	m, err := toMap(map[string]any{"suggestions": sugg})
	if err != nil {
		return nil, nil, err
	}
	m["next_steps"] = []string{"present each suggestion with its evidence; commands marked humanGate are run by a human (or, for policy edits, by the matching dry_run write tool after an explicit yes)"}
	return nil, m, nil
}

func (s *srv) addCopilotTools(m *mcp.Server) {
	ann := &mcp.ToolAnnotations{DestructiveHint: boolp(false)}
	mcp.AddTool(m, &mcp.Tool{Name: "copilot_draft", Annotations: ann,
		Description: "Check a policy draft you wrote (ADR-0035): writes the whole files over a copy of the policy and runs the bypass-token scan (comments included), validation, a release plan per ring and the impact preview. Fix check.errors and call again. dry_run (default true) writes nothing; false needs --allow-writes, a reason and passing checks, and commits to a new local halos/copilot-* branch. Never pushes or merges."},
		s.copilotDraft)
	mcp.AddTool(m, &mcp.Tool{Name: "copilot_experiment", Annotations: ann,
		Description: "Design an experiment (ADR-0035): you give arms, rings and metrics; internal/stats computes the per-arm sample size and duration from the human's baseline, sd and MDE; Halos renders experiments/<name>.yaml (status draft) and checks it like copilot_draft. Same dry_run and write rules."},
		s.copilotExperiment)
	mcp.AddTool(m, &mcp.Tool{Name: "copilot_explain", Annotations: readOnly,
		Description: "Facts for a plain-language explanation of a release (ring), a policy diff (git ref) or an experiment: keyed Halos outputs (plan, file diffs, impact, settings, a verdict when ClickHouse is configured). Explain only from these and cite the keys. Read-only."},
		s.copilotExplain)
	mcp.AddTool(m, &mcp.Tool{Name: "copilot_next", Annotations: readOnly,
		Description: "Suggested next steps from policy and (with --clickhouse) live verdicts, each with its evidence and the exact command; commands that change state are marked humanGate. Deterministic, read-only."},
		s.copilotNext)
}
