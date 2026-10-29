package mcpserver

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/shadow"
	"github.com/dshakes/halos/internal/upgrade"
)

type matrixIn struct {
	Suite string `json:"suite" jsonschema:"eval suite YAML under the policy dir that defines a matrix"`
}

type upgradeIn struct {
	Config string `json:"config,omitempty" jsonschema:"upgrade watcher config under the policy dir (default .halos/upgrade.yaml)"`
}

// policyFile resolves rel under the policy dir, refusing anything outside it,
// including through a symlink (the same containment as policy resources).
func (s *srv) policyFile(rel, def string) (string, error) {
	if rel == "" {
		rel = def
	}
	p := rel
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.dir, rel)
	}
	return resolveWithin(s.dir, p)
}

type harvestIn struct {
	Pairs          string   `json:"pairs" jsonschema:"halo-shadow pair store (JSONL): absolute, or relative to the policy dir"`
	PairKeyFiles   []string `json:"pair_key_files,omitempty" jsonschema:"base64 pair key FILES (current and retired); paths only, never key values"`
	Out            string   `json:"out,omitempty" jsonschema:"suite directory under the policy dir (default evals/steps)"`
	Experiment     string   `json:"experiment,omitempty" jsonschema:"only this experiment"`
	Select         []string `json:"select,omitempty" jsonschema:"diverged, invalid-call, premature-stop, judge-loss, sample (default the first three)"`
	History        string   `json:"history,omitempty" jsonschema:"halo eval online history JSONL (judge scores for judge-loss)"`
	JudgeLoss      float64  `json:"judge_loss,omitempty" jsonschema:"judge-loss threshold, control minus candidate score (default 0.2)"`
	PerDepth       int      `json:"per_depth,omitempty" jsonschema:"sample: steps per depth bucket (default 5)"`
	Seed           uint64   `json:"seed,omitempty" jsonschema:"sampling seed"`
	RedactPatterns []string `json:"redact_patterns,omitempty" jsonschema:"extra RE2 regexes to redact"`
	KeepFields     []string `json:"keep_fields,omitempty" jsonschema:"extra top-level request fields to keep"`
	DryRun         *bool    `json:"dry_run,omitempty" jsonschema:"default true: select and redact, return the summary, write nothing; false writes the cases (needs --allow-writes)"`
	Reason         string   `json:"reason,omitempty" jsonschema:"why this harvest; required when dry_run is false"`
}

type harvestOut struct {
	DryRun         bool               `json:"dry_run"`
	Written        bool               `json:"written"`
	Reason         string             `json:"reason,omitempty"`
	Out            string             `json:"out"`
	Command        string             `json:"command"`
	Steps          int                `json:"steps"`
	Selected       int                `json:"selected"`
	Skipped        int                `json:"skipped"`
	ByReason       map[string]int     `json:"by_reason"`
	RedactionRules string             `json:"redaction_rules"`
	Cases          []eval.CaseSummary `json:"cases"`
	NextSteps      []string           `json:"next_steps"`
}

func (s *srv) addEvalTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "eval_matrix", Description: "Expand an eval suite's harness x model x provider matrix into the cells `halo eval run --matrix` would run. Runs nothing.", Annotations: readOnly}, s.evalMatrix)
	mcp.AddTool(m, &mcp.Tool{Name: "eval_harvest", Annotations: &mcp.ToolAnnotations{DestructiveHint: boolp(false), IdempotentHint: true},
		Description: "Turn halo-shadow steps where the candidate regressed (diverged, invalid call, premature stop, judge loss, or a depth-stratified sample) into redacted step-level eval cases (`halo eval harvest`). Returns provenance and expected tool names only, never request content. dry_run (default true) writes nothing; false writes 0600 case files under the policy dir and needs --allow-writes plus a reason. Redaction always runs and fails closed."},
		s.evalHarvest)
	mcp.AddTool(m, &mcp.Tool{Name: "upgrade_candidates", Description: "List new upstream CLI versions (npm) and provider models that `halo upgrade check` would evaluate, with install-artifact verification. Reads the network; writes nothing, runs no eval, opens no PR.", Annotations: readOnly}, s.upgradeCandidates)
}

func (s *srv) evalMatrix(_ context.Context, _ *mcp.CallToolRequest, in matrixIn) (*mcp.CallToolResult, map[string]any, error) {
	p, err := s.policyFile(in.Suite, "")
	if err != nil {
		return nil, nil, err
	}
	su, err := eval.LoadSuite(p)
	if err != nil {
		return nil, nil, err
	}
	mx, err := su.WithMatrix()
	if err != nil {
		return nil, nil, err
	}
	return nil, map[string]any{"suite": mx.Name, "baseline": mx.Control, "repeats": mx.Repeats, "k": mx.K, "cells": mx.Variants}, nil
}

// abs resolves an operator path: absolute as given, else under the policy dir.
func (s *srv) abs(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.dir, p)
}

func (s *srv) evalHarvest(ctx context.Context, _ *mcp.CallToolRequest, in harvestIn) (*mcp.CallToolResult, harvestOut, error) {
	out := harvestOut{DryRun: isDry(in.DryRun), ByReason: map[string]int{}, Cases: []eval.CaseSummary{}, NextSteps: []string{}}
	if in.Pairs == "" {
		return nil, out, errors.New("pairs is required")
	}
	dst, err := s.policyFile(in.Out, filepath.Join("evals", "steps"))
	if err != nil {
		return nil, out, err
	}
	out.Out = dst
	args := []string{"halo", "eval", "harvest", "--pairs", s.abs(in.Pairs), "--out", dst}
	o := eval.HarvestOptions{Experiment: in.Experiment, Select: in.Select, JudgeLoss: in.JudgeLoss, PerDepth: in.PerDepth, Seed: in.Seed}
	var keys [][]byte
	for _, f := range in.PairKeyFiles {
		k, err := shadow.ReadKeyFile(s.abs(f))
		if err != nil {
			return nil, out, err
		}
		keys = append(keys, k)
		args = append(args, "--pair-key-file", s.abs(f))
	}
	if o.Redactor, err = eval.NewRedactor(in.RedactPatterns, in.KeepFields); err != nil {
		return nil, out, err
	}
	if in.History != "" {
		if o.Scores, err = eval.HistoryScores(s.abs(in.History)); err != nil {
			return nil, out, err
		}
		args = append(args, "--history", s.abs(in.History))
	}
	if in.Experiment != "" {
		args = append(args, "--experiment", in.Experiment)
	}
	if len(in.Select) > 0 {
		args = append(args, "--select", strings.Join(in.Select, ","))
	}
	for _, p := range in.RedactPatterns {
		args = append(args, "--redact-pattern", p)
	}
	for _, f := range in.KeepFields {
		args = append(args, "--keep-field", f)
	}
	out.Command = shJoin(args...)
	if out.Reason, err = needUnlessDry(in.DryRun, in.Reason); err != nil {
		return nil, out, err
	}
	write, err := s.mayWrite(in.DryRun, out.Command)
	if err != nil {
		return nil, out, err
	}
	res, err := eval.Harvest(ctx, eval.FilePairs{Path: s.abs(in.Pairs), Keys: keys}, o)
	if err != nil {
		return nil, out, err
	}
	out.Steps, out.Selected, out.Skipped, out.ByReason, out.RedactionRules, out.Cases = res.Steps, len(res.Cases), res.Skipped, res.ByReason, o.Redactor.Version(), res.Summary()
	if len(res.Cases) == 0 {
		out.NextSteps = []string{"no step matched the selection: widen select (e.g. sample) or wait for more shadow traffic"}
		return nil, out, nil
	}
	if !write {
		out.NextSteps = []string{"show the human the selection above; on a yes, call eval_harvest again with dry_run false (needs --allow-writes) or have them run: " + out.Command}
		return nil, out, nil
	}
	if err := eval.WriteStepCases(dst, res.Cases); err != nil {
		return nil, out, err
	}
	out.Written = true
	out.NextSteps = []string{
		"the human reviews the redacted case files in " + dst + " before anything is committed: they hold real prompts and terminal output",
		"replay them against the candidate route: " + shJoin("halo", "eval", "steps", "run", "--suite", dst) + " --model ROUTE --url GATEWAY_URL --key-env VAR",
	}
	return nil, out, nil
}

func (s *srv) upgradeCandidates(ctx context.Context, _ *mcp.CallToolRequest, in upgradeIn) (*mcp.CallToolResult, map[string]any, error) {
	p, err := s.policyFile(in.Config, filepath.Join(".halos", "upgrade.yaml"))
	if err != nil {
		return nil, nil, err
	}
	cfg, err := upgrade.LoadConfig(p)
	if err != nil {
		return nil, nil, err
	}
	w := upgrade.Watcher{PolicyDir: s.dir, Config: cfg, DryRun: true,
		Registry: upgrade.NPM{}, Verifier: upgrade.ArtifactVerifier{Resolver: release.ArtifactResolver{}}}
	if s.Upgrade != nil {
		w.Registry, w.Models, w.Verifier = s.Upgrade.Registry, s.Upgrade.Models, s.Upgrade.Verifier
	}
	cs, err := w.Candidates(ctx)
	if err != nil {
		return nil, nil, err
	}
	return nil, map[string]any{"candidates": cs}, nil
}
