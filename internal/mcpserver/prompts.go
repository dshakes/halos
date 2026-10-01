package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func addPrompts(m *mcp.Server) {
	add := func(name, desc string, args []*mcp.PromptArgument, tmpl string, keys ...string) {
		m.AddPrompt(&mcp.Prompt{Name: name, Description: desc, Arguments: args},
			func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				vals := make([]any, len(keys))
				for i, k := range keys {
					vals[i] = req.Params.Arguments[k]
				}
				return &mcp.GetPromptResult{Description: desc, Messages: []*mcp.PromptMessage{
					{Role: "user", Content: &mcp.TextContent{Text: fmt.Sprintf(tmpl, vals...)}}}}, nil
			})
	}
	arg := func(n, d string) *mcp.PromptArgument {
		return &mcp.PromptArgument{Name: n, Description: d, Required: true}
	}

	add("plan-cli-upgrade", "Plan a harness CLI version upgrade as a ring-by-ring rollout.",
		[]*mcp.PromptArgument{arg("harness", "e.g. claude-code"), arg("version", "target CLI version")},
		"Plan an upgrade of %[1]s to %[2]s using the Halos tools. Steps: (1) list_rings and list_experiments; "+
			"(2) propose the YAML edits (new profile or version bump, plus an A/B experiment in ring1) as a diff, do not apply yet; "+
			"(3) validate, then plan against the current release tarball; (4) explain_release_diff and call out risky changes; "+
			"(5) list the eval suite to run and the guardrails to watch. STOP and ask a human before starting any experiment. "+
			"Never publish, retag or merge; those are human steps.", "harness", "version")
	add("plan-model-upgrade", "Plan a model alias change with a canary experiment.",
		[]*mcp.PromptArgument{arg("from_model", "current model"), arg("to_model", "candidate model")},
		"Plan moving from model %[1]s to %[2]s. Use harness_matrix to check which harnesses can lock models, list_rings to pick "+
			"the first ring, and draft an experiment (axis: traffic, guardrails on error rate, cost and latency). Validate the draft, "+
			"use eval_scorecard on any existing scorecard as evidence, and present the plan for human approval before start_experiment.",
		"from_model", "to_model")
	add("triage-experiment", "Diagnose an experiment whose guardrail is failing.",
		[]*mcp.PromptArgument{arg("experiment", "experiment name")},
		"Experiment %[1]s has a failing guardrail. Call show_experiment and analyze_experiment, identify which metric regressed "+
			"and in which variant, and say whether the evidence justifies a rollback. If yes, call propose_rollback with dry_run "+
			"true first, show the diff and a one-paragraph reason, and wait for a human to confirm before applying.", "experiment")
}
