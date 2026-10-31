package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyTest(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	if !toolNames(t, cs)["policy_test"] {
		t.Fatal("policy_test not registered on a read-only server")
	}
	out, err := call(t, cs, "policy_test", map[string]any{"ring": "ring3-ga"})
	if err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true || out["failed"] != float64(0) || len(out["results"].([]any)) < 5 || len(out["next_steps"].([]any)) == 0 {
		t.Fatalf("policy_test: %v", out)
	}
	if _, err := call(t, cs, "policy_test", map[string]any{"ring": "nope"}); err == nil {
		t.Fatal("unknown ring accepted")
	}
	if _, err := call(t, cs, "policy_test", map[string]any{"max_impact": 150}); err == nil {
		t.Fatal("max_impact 150 accepted")
	}
}

// A failing check is a result with ok false and next_steps, not a tool error.
func TestPolicyTestReportsFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(example)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "rings", "ring3-ga.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "profile: engineering", "profile: nope", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := call(t, connect(t, Options{PolicyDir: dir}), "policy_test", nil)
	if err != nil || out["ok"] != false || out["failed"].(float64) < 1 || len(out["next_steps"].([]any)) == 0 {
		t.Fatalf("%v %v", out, err)
	}
}
