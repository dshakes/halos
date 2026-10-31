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
		"Onboard me onto Halos, path: %[1]s (ask which if empty: try it, my machine, my company).\n"+
			"Every tool answers with next_steps ({tool|command, why, args}); follow them. An error names the field, type, example and allowed values to retry with.\n"+
			"Hard rules: relay each doctor fix verbatim; every write is a dry run first (dry_run defaults to true): show it and wait for one yes per step before dry_run false "+
			"(needs a server started with --allow-writes, else give me the CLI command from the error); never print or ask for a credential value; never publish, "+
			"enroll, retag, push, merge or deploy: hand me the command and stop.\n"+
			"Try it: doctor; I run `halo quickstart` (Docker) and you walk me through its tour.\n"+
			"My machine: doctor -> detect_harnesses -> init_policy {\"org\":\"acme\"} (dry run: show halos.yaml and validation; defaults are the CLIs found and suggested_provider) -> "+
			"yes -> init_policy {\"org\":\"acme\",\"dry_run\":false} -> validate -> plan {\"ring\":\"<first of list_rings>\"} -> "+
			"local_install {\"dry_run\":true,\"show\":true} (explain what lands where; admin paths: give me the sudo command), yes, write, re-run to prove it is idempotent -> "+
			"local_proxy {} -> verify_harness {\"harness\":\"claude-code\"} dry run, then real (assume_auth true if the CLI is logged in). Stop when verify passes.\n"+
			"My company: doctor -> onboard_company {\"org\":\"acme\"} (dry run; ONLY org is required; `assumed` lists every default it filled and `placeholders` the example.com ones to replace: ask me for "+
			"issuer, gateway, registry, policy_repo, portal_url, delivery [devcontainer|mdm|halod], tools {\"claude-code\":\"2.1.280\"}, provider, admin_groups) -> yes -> same call with the real answers and dry_run false "+
			"(refused while placeholders remain) -> validate -> plan -> harness_matrix -> eval_scorecard. Then list the remaining human steps from the generated README and stop; "+
			"committing on a branch and opening the PR are mine to approve.\n"+
			"Stop and ask me when: a tool errors twice with the same message, doctor reports a fail you cannot fix, a write would replace a file you did not create, or any step needs a credential.", "path")
	add("autopilot", "Drive the whole Halos lifecycle hands-off (onboard, draft, validate, plan, eval, start, wait, promote or roll back), stopping only at the human gates.",
		[]*mcp.PromptArgument{{Name: "goal", Description: "what to roll out, e.g. 'claude-code 2.1.300 to ring1' or 'opus-5-5 as the default model' (ask when empty)"}},
		"Goal: %[1]s (ask what to roll out if empty). Follow this guide exactly; it is also the resource "+guideURI+".\n\n"+
			"Call sequence (every answer's next_steps names the next call; an error names the field, type, example and allowed values):\n"+
			"status -> validate -> plan {\"ring\":\"ring1-canary\"} -> release_build {\"ring\":\"ring1-canary\"} -> eval_run {\"suite\":\"evals/smoke.yaml\"} (dry run) -> "+
			"GATE: show me the diff, plan and scorecard -> start_experiment {\"name\":\"<experiment>\",\"reason\":\"<why>\",\"dry_run\":false} after my yes -> "+
			"wait_for / analyze_experiment {\"name\":\"<experiment>\"} -> propose_promotion or propose_rollback (opens a PR; dry run first) -> "+
			"GATE: I merge. Rolling back (kill_switch, propose_rollback) is the only direction you may take without asking.\n"+
			"Stop conditions: a human gate, validate errors, a failing guardrail or eval, a write refused (give me the command), or the same error twice. "+
			"Never publish, retag, merge or deploy.\n\n"+autopilotGuide, "goal")
	add("copilot", "Halos Copilot: turn an intent into a verified policy change; you draft, Halos checks, a human approves.",
		[]*mcp.PromptArgument{{Name: "intent", Description: "what to change, e.g. 'move ring1-canary to Claude Code 2.1.300' (ask when empty)"}},
		"Intent: %[1]s (ask what to change if empty). You are the drafter; Halos is the gate (ADR-0035). Loop: read the policy "+
			"(halos://policy/<path> resources, list_rings, list_experiments); write the WHOLE new content of each YAML file you change; "+
			"call copilot_draft with dry_run true; fix every check.errors entry and call again (at most 3 rounds, then stop and show "+
			"the human what still fails). For an experiment, ask the human for the baseline, sd (or a rate metric) and MDE, never guess "+
			"them, and call copilot_experiment: the sample size and duration come from Halos, not from you. Never write "+
			"bypassPermissions or danger-full-access. When the checks pass, show the diff, the plan, the impact and the risks, explain "+
			"them citing copilot_explain fact keys, and wait for an explicit yes before calling again with dry_run false and a reason "+
			"(that only commits a local branch). Push, PR, merge, release and starting an experiment are human steps: give the commands "+
			"and stop. copilot_next lists what to do after.", "intent")
	add("triage-experiment", "Diagnose an experiment whose guardrail is failing.",
		[]*mcp.PromptArgument{arg("experiment", "experiment name")},
		"Experiment %[1]s has a failing guardrail. Call show_experiment and analyze_experiment, identify which metric regressed "+
			"and in which variant, and say whether the evidence justifies a rollback. If yes, call propose_rollback with dry_run "+
			"true first, show the diff and a one-paragraph reason, and wait for a human to confirm before applying.", "experiment")
}
