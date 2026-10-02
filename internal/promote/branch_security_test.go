package promote

import (
	"context"
	"strings"
	"testing"
)

// A branch prefix that is not a plain halos/<name> is refused before git runs:
// no option injection into git argv ("-x", "--receive-pack=..."), no refspec
// (":"), no way to name main or another namespace.
func TestBranchPrefixValidated(t *testing.T) {
	edit := func(ReadFunc) (map[string][]byte, error) { return map[string][]byte{"ring.yaml": []byte("x")}, nil }
	for _, tc := range []struct {
		branch string
		ok     bool
	}{
		{"halos/request-r1", true},
		{"halos/toggle-github-mcp-abc_d", true},
		{"halos/rollout-opus-5-5-upgrade-canary-25", true},
		{"halos/upgrade-claude-code-2.1.3", true},
		{"main", false},
		{"refs/heads/main", false},
		{"halos/../main", false},
		{"halos/x:refs/heads/main", false},
		{"halos/x:main", false},
		{"-x", false},
		{"--receive-pack=touch pwned", false},
		{"halos/--exec=sh", false},
		{"halos/", false},
		{"halos//x", false},
		{"halos/.hidden", false},
		{"halos/x.lock/y", false},
		{"halos/x@{1}", false},
		{"halos/x y", false},
		{"halos/x\nmain", false},
		{"", false},
	} {
		var calls []string
		run := func(_ context.Context, _, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil, nil
		}
		_, _, err := CommitOnBranch(context.Background(), run, t.TempDir(), BranchCommit{Branch: tc.branch, Subject: "s", Edit: edit})
		if !tc.ok {
			if err == nil || len(calls) != 0 {
				t.Errorf("%q: err=%v, git ran %q; want refused before any git call", tc.branch, err, calls)
			}
			continue
		}
		if len(calls) == 0 {
			t.Errorf("%q: refused (%v)", tc.branch, err)
		}
	}
}

// PushBranch (the only push in Halos) pushes a fresh halos/ branch under its
// own name: origin main never moves and no tag is pushed.
func TestPushBranchNeverUpdatesMain(t *testing.T) {
	ctx := context.Background()
	dir := gitRepo(t)
	mainBefore, err := Run(ctx, dir, "git", "ls-remote", "origin", "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	br, err := PushBranch(ctx, nil, dir, BranchCommit{Branch: "halos/request-r1", Subject: "s",
		Edit: func(ReadFunc) (map[string][]byte, error) {
			return map[string][]byte{"ring.yaml": []byte("changed\n")}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if mainAfter, _ := Run(ctx, dir, "git", "ls-remote", "origin", "refs/heads/main"); string(mainAfter) != string(mainBefore) {
		t.Fatalf("push updated origin main: %s -> %s", mainBefore, mainAfter)
	}
	if !strings.HasPrefix(br, "halos/request-r1-") {
		t.Fatalf("branch %q", br)
	}
	if heads, _ := Run(ctx, dir, "git", "ls-remote", "--heads", "origin", br); !strings.Contains(string(heads), "refs/heads/"+br) {
		t.Fatalf("branch %s not pushed under its own name: %s", br, heads)
	}
	// No tags are ever pushed.
	if tags, _ := Run(ctx, dir, "git", "ls-remote", "--tags", "origin"); len(tags) != 0 {
		t.Fatalf("tags pushed: %s", tags)
	}
}
