package mcpserver

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Every MCP write tool: dry_run is the default, reason is required, and a real
// (dry_run=false) call only adds a new local halos/ branch. Origin, main, HEAD
// and tags never change: nothing is pushed, merged, tagged or published.
func TestWriteToolsNeverPushMergeOrTag(t *testing.T) {
	dir := copyExample(t)
	origin := filepath.Join(t.TempDir(), "origin.git")
	for _, args := range [][]string{{"init", "-q", "--bare", origin}, {"-C", dir, "remote", "add", "origin", origin}, {"-C", dir, "push", "-q", "origin", "HEAD:refs/heads/main"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	ctx := context.Background()
	snap := func() (remote, head, tags string) {
		t.Helper()
		remote, _ = git(ctx, dir, "ls-remote", origin)
		head, _ = git(ctx, dir, "rev-parse", "--symbolic-full-name", "HEAD")
		h, _ := git(ctx, dir, "rev-parse", "HEAD")
		tags, _ = git(ctx, dir, "tag", "--list")
		return remote, head + " " + h, tags
	}
	branches := func() map[string]bool {
		out, _ := git(ctx, dir, "for-each-ref", "--format=%(refname)", "refs/heads")
		m := map[string]bool{}
		for _, b := range strings.Fields(out) {
			m[b] = true
		}
		return m
	}
	remote0, head0, tags0 := snap()

	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"pause_experiment", map[string]any{"name": "opus-5-5-canary"}},
		{"conclude_experiment", map[string]any{"name": "opus-5-5-canary"}},
		{"propose_rollback", map[string]any{"experiment": "opus-5-5-canary", "ring": "ring1-canary", "release": "sha256:" + strings.Repeat("ab", 32)}},
		{"propose_toggle_change", map[string]any{"name": "github-mcp", "rule": "0", "percent": 25}},
		{"propose_rollout_rollback", map[string]any{"name": "opus-5-5-upgrade"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			with := func(extra map[string]any) map[string]any {
				m := map[string]any{}
				for k, v := range tc.args {
					m[k] = v
				}
				for k, v := range extra {
					m[k] = v
				}
				return m
			}
			before := branches()
			for _, r := range []any{nil, "", "   "} {
				args := with(nil)
				if r != nil {
					args["reason"] = r
				}
				args["dry_run"] = false
				if _, err := call(t, cs, tc.tool, args); err == nil {
					t.Fatalf("reason %q accepted", r)
				}
			}
			out, err := call(t, cs, tc.tool, with(map[string]any{"reason": "r"}))
			if err != nil || out["dry_run"] != true || out["applied"] == true {
				t.Fatalf("default call is not a dry run: %v %v", out, err)
			}
			if len(branches()) != len(before) {
				t.Fatal("dry run created a branch")
			}
			out, err = call(t, cs, tc.tool, with(map[string]any{"reason": "r", "dry_run": false}))
			if err != nil || out["applied"] != true {
				t.Fatalf("apply: %v %v", out, err)
			}
			br, _ := out["branch"].(string)
			after := branches()
			if !strings.HasPrefix(br, "halos/") || !after["refs/heads/"+br] || len(after) != len(before)+1 {
				t.Fatalf("branch %q; refs %v -> %v", br, before, after)
			}
			if remote, head, tags := snap(); remote != remote0 || head != head0 || tags != tags0 {
				t.Fatalf("origin/HEAD/tags changed:\nremote %q -> %q\nhead %q -> %q\ntags %q -> %q", remote0, remote, head0, head, tags0, tags)
			}
		})
	}
	for n := range toolNames(t, cs) {
		for _, bad := range []string{"push", "merge", "publish", "retag", "tag"} {
			if strings.Contains(n, bad) {
				t.Errorf("tool %s looks like a %s tool", n, bad)
			}
		}
	}
}
