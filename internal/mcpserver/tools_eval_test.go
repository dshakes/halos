package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/upgrade"
)

type fixedRegistry map[string]string

func (f fixedRegistry) Latest(_ context.Context, pkg string) (string, error) { return f[pkg], nil }

type fixedModels []string

func (f fixedModels) List(context.Context) ([]string, error) { return f, nil }

type okVerifier struct{}

func (okVerifier) Verify(context.Context, string, string) (int, error) { return 6, nil }

func TestEvalMatrixAndUpgradeCandidates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy")
	if err := os.CopyFS(dir, os.DirFS(example)); err != nil {
		t.Fatal(err)
	}
	suite := filepath.Join(dir, ".halos", "m.yaml")
	if err := os.WriteFile(suite, []byte(`name: m
tasks: [x]
matrix:
  harnesses: [{harness: claude, version: "2.1.312", models: [sonnet]}, {harness: codex, version: "0.60.0", models: [codex-default]}]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := connect(t, Options{PolicyDir: dir, Upgrade: &upgrade.Watcher{
		Registry: fixedRegistry{"@anthropic-ai/claude-code": "2.1.330", "@openai/codex": "0.60.0", "@google/gemini-cli": "0.13.0"},
		Models:   map[string]upgrade.ModelLister{"orchestrator-openai": fixedModels{"gpt-5-codex", "gpt-5.1-codex"}},
		Verifier: okVerifier{},
	}})

	m, err := call(t, cs, "eval_matrix", map[string]any{"suite": ".halos/m.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if m["baseline"] != "claude@2.1.312/sonnet" || len(m["cells"].([]any)) != 2 {
		t.Fatalf("matrix: %v", m)
	}
	if _, err := call(t, cs, "eval_matrix", map[string]any{"suite": "../../etc/passwd"}); err == nil || !strings.Contains(err.Error(), "not under the policy dir") {
		t.Fatalf("escape: %v", err)
	}

	u, err := call(t, cs, "upgrade_candidates", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	c := u["candidates"].([]any)
	if len(c) != 2 || c[0].(map[string]any)["to"] != "2.1.330" || c[1].(map[string]any)["to"] != "gpt-5.1-codex" {
		t.Fatalf("candidates: %v", u)
	}
	if _, err := os.Stat(filepath.Join(dir, ".halos", "upgrade-state.json")); !os.IsNotExist(err) {
		t.Fatal("upgrade_candidates must not write state")
	}
}
