package eval

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func matrixSuite(t *testing.T) *Suite {
	t.Helper()
	s, err := LoadSuite("testdata/suites/matrix.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMatrixCells(t *testing.T) {
	s := matrixSuite(t)
	if len(s.Variants) != 0 {
		t.Fatal("matrix-only suite must have no variants until expanded")
	}
	m, err := s.WithMatrix()
	if err != nil {
		t.Fatal(err)
	}
	var names, models []string
	for _, v := range m.Variants {
		names, models = append(names, v.Name), append(models, v.Model)
	}
	want := "claude@2.1.312/sonnet/anthropic claude@2.1.312/sonnet/bedrock codex@0.100.0/gpt-5/anthropic gemini@0.35.0/gemini-2.5-pro/anthropic"
	if strings.Join(names, " ") != want {
		t.Fatalf("cells:\n%s\nwant\n%s", strings.Join(names, " "), want)
	}
	if models[1] != "sonnet-bedrock" || m.Variants[1].Provider != "bedrock" {
		t.Fatalf("bedrock alias not applied: %+v", m.Variants[1])
	}
	if m.Control != "claude@2.1.312/sonnet/anthropic" || m.Matrix.Baseline != m.Control {
		t.Fatalf("control %q", m.Control)
	}
	bad := *s
	mx := *s.Matrix
	mx.Baseline = "nope"
	bad.Matrix = &mx
	if _, err := bad.WithMatrix(); err == nil || !strings.Contains(err.Error(), "cells:") {
		t.Fatalf("unknown baseline: %v", err)
	}
}

// matrixTrials is a deterministic run: bedrock matches the baseline, codex
// regresses one task and costs more, gemini is flaky-free but slower.
func matrixTrials(m *Suite) []Trial {
	outcome := map[string]map[string][]bool{
		"claude@2.1.312/sonnet/anthropic":        {"fix": {true, true, true}, "flag": {true, true, true}, "rename": {true, false, true}},
		"claude@2.1.312/sonnet/bedrock":          {"fix": {true, true, true}, "flag": {true, true, true}, "rename": {true, true, false}},
		"codex@0.100.0/gpt-5/anthropic":          {"fix": {true, true, true}, "flag": {false, false, false}, "rename": {true, true, true}},
		"gemini@0.35.0/gemini-2.5-pro/anthropic": {"fix": {true, true, true}, "flag": {true, true, true}, "rename": {true, true, true}},
	}
	cost := map[string]float64{"claude@2.1.312/sonnet/anthropic": 0.20, "claude@2.1.312/sonnet/bedrock": 0.21, "codex@0.100.0/gpt-5/anthropic": 0.35, "gemini@0.35.0/gemini-2.5-pro/anthropic": 0.12}
	var out []Trial
	for _, v := range m.Variants {
		for ti, task := range []string{"fix", "flag", "rename"} {
			for r, p := range outcome[v.Name][task] {
				wall := int64(30_000 + 5_000*ti + 1_000*r)
				if strings.HasPrefix(v.Name, "gemini") {
					wall *= 2
				}
				out = append(out, Trial{Task: task, Variant: v.Name, Repeat: r, Pass: p, CostUSD: cost[v.Name],
					WallMs: wall, Tokens: int64(20_000 + 1_000*ti), ToolCalls: 12 + ti, Seed: trialSeed(m.Seed, task, r)})
			}
		}
	}
	return out
}

func TestMatrixReportGolden(t *testing.T) {
	m, err := matrixSuite(t).WithMatrix()
	if err != nil {
		t.Fatal(err)
	}
	sc, err := BuildScorecard(m, matrixTrials(m), m.Seed)
	if err != nil {
		t.Fatal(err)
	}
	got := sc.Markdown() + "\n<!-- terminal table -->\n```\n" + sc.Table() + "```\n"
	const golden = "testdata/golden/matrix.md"
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test -run MatrixReportGolden -update)", err)
	}
	if got != string(want) {
		t.Fatalf("matrix report differs from %s (rerun with -update if intended):\n%s", golden, got)
	}
	if sc.Gate.Verdict != GateBlock {
		t.Fatalf("codex regressed a task: gate %+v", sc.Gate)
	}
	// Reproducible: the same seed gives byte-identical JSON.
	sc2, _ := BuildScorecard(m, matrixTrials(m), m.Seed)
	a, _ := sc.JSON()
	b, _ := sc2.JSON()
	if string(a) != string(b) {
		t.Fatal("scorecard JSON is not deterministic for a fixed seed")
	}
}
