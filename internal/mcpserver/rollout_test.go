package mcpserver

import (
	"os/exec"
	"strings"
	"testing"
)

func TestRolloutTools(t *testing.T) {
	ro := toolNames(t, connect(t, Options{PolicyDir: example}))
	if !ro["list_rollouts"] || !ro["rollout_status"] || ro["propose_rollout_advance"] || ro["propose_rollout_rollback"] {
		t.Fatalf("read-only tool set wrong: %v", ro)
	}
	dir := copyExample(t)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})

	out, err := call(t, cs, "list_rollouts", nil)
	if err != nil || len(out["rollouts"].([]any)) != 3 {
		t.Fatalf("list_rollouts: %v %v", out, err)
	}
	out, err = call(t, cs, "rollout_status", map[string]any{"name": "opus-5-5-upgrade"})
	if err != nil {
		t.Fatal(err)
	}
	if d := out["decision"].(map[string]any); d["action"] != "hold" || out["step"] != "canary-5" {
		t.Fatalf("rollout_status: %v", out)
	}

	tests := []struct {
		name, tool string
		args       map[string]any
		patch      []string // substrings of the patch
		err        string
	}{
		{"advance needs a reason", "propose_rollout_advance", map[string]any{"name": "opus-5-5-upgrade", "reason": " "}, nil, "reason is required"},
		{"unknown rollout", "propose_rollout_advance", map[string]any{"name": "nope", "reason": "r"}, nil, `unknown rollout "nope"`},
		{"advance dry run", "propose_rollout_advance", map[string]any{"name": "opus-5-5-upgrade", "reason": "r"}, []string{"+step: canary-25", "+    weight: 25"}, ""},
		{"rollback dry run", "propose_rollout_rollback", map[string]any{"name": "opus-5-5-upgrade", "reason": "r"}, []string{"+status: aborted", "+status: paused"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := call(t, cs, tc.tool, tc.args)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out["dry_run"] != true || out["applied"] == true {
				t.Fatalf("not a dry run: %v", out)
			}
			for _, p := range tc.patch {
				if !strings.Contains(out["patch"].(string), p) {
					t.Fatalf("patch lacks %q:\n%s", p, out["patch"])
				}
			}
		})
	}

	// dry_run=false commits to a new local branch only; the checkout is untouched.
	out, err = call(t, cs, "propose_rollout_rollback", map[string]any{"name": "opus-5-5-upgrade", "reason": "p95 regression", "dry_run": false})
	if err != nil || out["applied"] != true || !strings.HasPrefix(out["branch"].(string), "halos/rollout-opus-5-5-upgrade-rollback") {
		t.Fatalf("commit: %v %v", out, err)
	}
	msg, err := exec.Command("git", "-C", dir, "log", "-1", "--format=%B", out["branch"].(string)).Output()
	if err != nil || !strings.Contains(string(msg), "Reason: p95 regression") {
		t.Fatalf("commit message %q %v", msg, err)
	}
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(st) != 0 {
		t.Fatalf("working tree changed: %s", st)
	}
}
