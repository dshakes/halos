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
	add("onboard", "Onboard onto Halos: try it, my machine, or my company. Dry run every write; approval before each; nothing outward.",
		[]*mcp.PromptArgument{{Name: "path", Description: "try | machine | company (ask when empty)"}},
		"Onboard me onto Halos, path: %[1]s (ask which if empty: try it, my machine, my company). Hard rules: call doctor first "+
			"and relay each fix verbatim; show every write as a dry run and wait for a yes before dry_run false (one yes per step); "+
			"never print or ask for a credential value (doctor and detect_harnesses only say whether a variable is set); never "+
			"publish, enroll, retag, push, merge or deploy, hand me the command and stop. Try it: doctor, then I run `halo quickstart` "+
			"(Docker, mock IdP and models) and you walk me through the tour it prints. My machine: detect_harnesses; confirm CLIs "+
			"(default: those found, at their versions), provider (default: suggested_provider) and whether to use a local halo-proxy; "+
			"init_policy dry run, show halos.yaml and validation, then write; plan; local_install dry run with show true, explain what "+
			"lands where, then write (admin paths: give me the sudo command) and re-run to prove it is idempotent; local_proxy and its "+
			"start command; verify_harness per CLI, dry run then real, assume_auth true if the CLI is logged in. My company: interview "+
			"(org, CLIs and versions, provider and models, gateway kind and URL, OIDC issuer, client id, admin groups, delivery "+
			"channels, registry, policy repo URL, console URL, safety, rollout), onboard_company dry run then write, validate, plan, "+
			"harness_matrix, eval_scorecard, commit on a branch and open a PR after I approve the push, then list the remaining human "+
			"steps from the generated README and stop.", "path")
	add("triage-experiment", "Diagnose an experiment whose guardrail is failing.",
		[]*mcp.PromptArgument{arg("experiment", "experiment name")},
		"Experiment %[1]s has a failing guardrail. Call show_experiment and analyze_experiment, identify which metric regressed "+
			"and in which variant, and say whether the evidence justifies a rollback. If yes, call propose_rollback with dry_run "+
			"true first, show the diff and a one-paragraph reason, and wait for a human to confirm before applying.", "experiment")
}
