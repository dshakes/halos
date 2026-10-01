package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToggleToolsRegistration(t *testing.T) {
	r := toolNames(t, connect(t, Options{PolicyDir: example}))
	if !r["list_toggles"] || !r["evaluate_toggle"] || r["propose_toggle_change"] {
		t.Fatalf("read-only server tools: %v", r)
	}
	if w := toolNames(t, connect(t, Options{PolicyDir: example, AllowWrites: true})); !w["propose_toggle_change"] {
		t.Fatal("propose_toggle_change missing with --allow-writes")
	}
}

func TestListAndEvaluateToggle(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	out, err := call(t, cs, "list_toggles", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := out["toggles"].([]any); len(rows) != 3 {
		t.Fatalf("list_toggles = %v", out)
	}
	out, err = call(t, cs, "evaluate_toggle", map[string]any{"user": "dana@acme.com", "groups": []string{"acme-platform-eng"}, "ring": "ring1-canary", "name": "format-hook"})
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := out["decisions"].([]any)
	if len(ds) != 1 || ds[0].(map[string]any)["on"] != true {
		t.Fatalf("format-hook for the group: %v", out)
	}
	out, err = call(t, cs, "evaluate_toggle", map[string]any{"user": "dana@acme.com", "ring": "ring1-canary", "name": "format-hook", "killed": []string{"format-hook"}})
	if err != nil {
		t.Fatal(err)
	}
	if d := out["decisions"].([]any)[0].(map[string]any); d["on"] != false || d["killed"] != true {
		t.Fatalf("killed what-if: %v", d)
	}
	for _, args := range []map[string]any{{"user": ""}, {"user": "u", "name": "nope"}, {"user": "u", "ring": "nope"}} {
		if _, err := call(t, cs, "evaluate_toggle", args); err == nil {
			t.Errorf("%v: expected error", args)
		}
	}
}

func TestProposeToggleChange(t *testing.T) {
	dir := copyExample(t)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	out, err := call(t, cs, "propose_toggle_change", map[string]any{"name": "github-mcp", "reason": "ramp", "rule": "ring1-ten-percent", "percent": 25, "default": false, "expires": "2027-03-31"})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := out["patch"].(string)
	if out["dry_run"] != true || !strings.Contains(p, "-    percent: 10") || !strings.Contains(p, "+    percent: 25") || !strings.Contains(p, `+expires: "2027-03-31"`) {
		t.Fatalf("dry-run patch:\n%s", p)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "toggles/github-mcp.yaml")); strings.Contains(string(b), "percent: 25") {
		t.Fatal("dry run modified the working tree")
	}

	out, err = call(t, cs, "propose_toggle_change", map[string]any{"name": "github-mcp", "reason": "ramp to 25 percent", "rule": "0", "percent": 25, "dry_run": false})
	if err != nil {
		t.Fatal(err)
	}
	br, _ := out["branch"].(string)
	if out["applied"] != true || br == "" {
		t.Fatalf("not applied: %v", out)
	}
	ctx := context.Background()
	if b, _ := git(ctx, dir, "show", br+":toggles/github-mcp.yaml"); !strings.Contains(b, "percent: 25") {
		t.Fatalf("branch lacks the edit:\n%s", b)
	}
	if msg, _ := git(ctx, dir, "log", "-1", "--format=%B", br); !strings.Contains(msg, "Reason: ramp to 25 percent") {
		t.Fatalf("reason not in commit message: %q", msg)
	}
	if files, _ := git(ctx, dir, "show", "--name-only", "--format=", br); files != "toggles/github-mcp.yaml" {
		t.Fatalf("commit touched %q", files)
	}
}

func TestProposeToggleChangeErrors(t *testing.T) {
	cs := connect(t, Options{PolicyDir: copyExample(t), AllowWrites: true})
	for name, args := range map[string]map[string]any{
		"missing reason":       {"name": "github-mcp", "reason": " ", "default": true},
		"nothing to change":    {"name": "github-mcp", "reason": "x"},
		"percent without rule": {"name": "github-mcp", "reason": "x", "percent": 5},
		"percent out of range": {"name": "github-mcp", "reason": "x", "rule": "0", "percent": 101},
		"unknown rule":         {"name": "github-mcp", "reason": "x", "rule": "nope", "percent": 5},
		"unknown toggle":       {"name": "nope", "reason": "x", "default": true},
		"bad expiry":           {"name": "github-mcp", "reason": "x", "expires": "tomorrow"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := call(t, cs, "propose_toggle_change", args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
