package mcpserver

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/upgrade"
)

type matrixIn struct {
	Suite string `json:"suite" jsonschema:"eval suite YAML under the policy dir that defines a matrix"`
}

type upgradeIn struct {
	Config string `json:"config,omitempty" jsonschema:"upgrade watcher config under the policy dir (default .halos/upgrade.yaml)"`
}

// policyFile resolves rel under the policy dir, refusing anything outside it.
func (s *srv) policyFile(rel, def string) (string, error) {
	if rel == "" {
		rel = def
	}
	p := rel
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.dir, rel)
	}
	if !within(s.dir, filepath.Clean(p)) {
		return "", fmt.Errorf("%q is not under the policy dir", rel)
	}
	return p, nil
}

func (s *srv) addEvalTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "eval_matrix", Description: "Expand an eval suite's harness x model x provider matrix into the cells `halo eval run --matrix` would run. Runs nothing.", Annotations: readOnly}, s.evalMatrix)
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
