package mcpserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCopilotDraftTool(t *testing.T) {
	dir := copyExample(t)
	eng, err := os.ReadFile(filepath.Join(dir, "profiles", "engineering.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	good := strings.Replace(string(eng), "version: 2.1.280", "version: 2.1.300", 1)
	evil := good + "# defaultMode: bypassPermissions\n"
	files := func(c string) []any { return []any{map[string]any{"path": "profiles/engineering.yaml", "content": c}} }

	ro := connect(t, Options{PolicyDir: dir})
	out, err := call(t, ro, "copilot_draft", map[string]any{"intent": "bump claude-code", "files": files(good)})
	if err != nil {
		t.Fatal(err)
	}
	chk, _ := out["check"].(map[string]any)
	if out["ok"] != true || !strings.Contains(chk["diff"].(string), "2.1.300") || !strings.Contains(strings.Join(steps(out), " "), "human gate") {
		t.Fatalf("%v", out)
	}
	// writes need --allow-writes, even when the checks pass
	if _, err := call(t, ro, "copilot_draft", map[string]any{"intent": "x", "files": files(good), "dry_run": false, "reason": "r"}); err == nil || !strings.Contains(err.Error(), "--allow-writes") {
		t.Fatalf("write without --allow-writes: %v", err)
	}

	rw := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	// a bypass token from the agent is a check error and is never committed
	out, err = call(t, rw, "copilot_draft", map[string]any{"intent": "x", "files": files(evil)})
	if err != nil || out["ok"] != false || !strings.Contains(strings.Join(strs(out["check"].(map[string]any)["errors"]), " "), "bypassPermissions") {
		t.Fatalf("%v %v", err, out)
	}
	if _, err := call(t, rw, "copilot_draft", map[string]any{"intent": "x", "files": files(evil), "dry_run": false, "reason": "r"}); err == nil || !strings.Contains(err.Error(), "refusing to commit") {
		t.Fatalf("bypass committed: %v", err)
	}
	if _, err := call(t, rw, "copilot_draft", map[string]any{"intent": "x", "files": files(good), "dry_run": false}); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("no reason: %v", err)
	}
	out, err = call(t, rw, "copilot_draft", map[string]any{"intent": "bump claude-code", "files": files(good), "dry_run": false, "reason": "new CLI"})
	if err != nil || !strings.HasPrefix(out["branch"].(string), "halos/copilot-") {
		t.Fatalf("%v %v", err, out)
	}
	msg, _ := exec.Command("git", "-C", dir, "log", "-1", "--format=%B", out["branch"].(string)).Output()
	if !strings.Contains(string(msg), "Reason: new CLI") {
		t.Fatalf("commit message %s", msg)
	}
}

func TestCopilotExperimentExplainNextTools(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	out, err := call(t, cs, "copilot_experiment", map[string]any{
		"hypothesis": "cli-next raises accept rate", "name": "cli-next-accept", "rings": []string{"ring1-canary"},
		"variants": []any{map[string]any{"name": "control", "weight": 50, "profile": "engineering", "control": true}, map[string]any{"name": "next", "weight": 50, "profile": "engineering-next"}},
		"primary":  map[string]any{"metric": "halo.edit.accept_rate", "direction": "increase"},
		"baseline": 0.3, "mde": 0.1, "daily_units": 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := out["stats"].(map[string]any)
	if out["ok"] != true || st["perArm"] != float64(3663) || st["days"] != float64(15) {
		t.Fatalf("%v", out)
	}

	out, err = call(t, cs, "copilot_explain", map[string]any{"kind": "release", "target": "ring1-canary"})
	if err != nil || !strings.Contains(strings.Join(steps(out), " "), "cite the fact keys") {
		t.Fatalf("%v %v", err, out)
	}
	if facts, _ := out["facts"].([]any); len(facts) < 3 {
		t.Fatalf("facts %v", out["facts"])
	}
	if _, err := call(t, cs, "copilot_explain", map[string]any{"kind": "nope", "target": "x"}); err == nil {
		t.Fatal("unknown kind must fail")
	}

	out, err = call(t, cs, "copilot_next", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := out["suggestions"].([]any); len(s) == 0 {
		t.Fatalf("%v", out)
	}

	res, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "copilot", Arguments: map[string]string{"intent": "bump"}})
	if err != nil || !strings.Contains(res.Messages[0].Content.(*mcp.TextContent).Text, "copilot_draft") {
		t.Fatalf("prompt: %v", err)
	}
}

func steps(out map[string]any) []string { return strs(out["next_steps"]) }

func strs(v any) []string {
	a, _ := v.([]any)
	s := make([]string, 0, len(a))
	for _, e := range a {
		s = append(s, e.(string))
	}
	return s
}
