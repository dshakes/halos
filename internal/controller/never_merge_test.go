package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/promote"
)

// The controller's only write path is GitWriter -> promote.GHOpener. Every
// command it runs is a local commit on a fresh halos/ branch, a push of that
// branch, its local deletion and `gh pr create`: never a merge, a tag, a
// force-push or a push to the base branch.
func TestGitWriterNeverMergesOrPushesBase(t *testing.T) {
	repo := t.TempDir()
	f := filepath.Join(repo, "policy", "experiments", "a.yaml")
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(expYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	gh := promote.GHOpener{Exec: func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch {
		case name == "gh":
			return []byte("https://gh/pr/9\n"), nil
		case len(args) > 1 && args[0] == "show": // committed content for Edit
			return os.ReadFile(filepath.Join(dir, strings.TrimPrefix(args[1], "HEAD:./")))
		}
		return nil, nil
	}}
	w := &GitWriter{RepoDir: repo, Subdir: "policy", Base: "main", Opener: gh}
	ctx := context.Background()
	if _, err := w.ProposeStatus(ctx, "exp-a", "paused", "Pause exp-a", "evidence"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ProposeRollout(ctx, func(string) (*promote.Change, error) {
		return &promote.Change{Files: map[string][]byte{"experiments/a.yaml": []byte("x\n")}, Patch: "p"}, nil
	}, "halos/rollout-r-advance", "Advance r", func(p string) string { return p }); err != nil {
		t.Fatal(err)
	}
	if len(calls) == 0 {
		t.Fatal("no commands recorded")
	}
	for _, c := range calls {
		f := strings.Fields(c)
		ok := false
		switch f[0] + " " + f[1] {
		case "git rev-parse", "git show", "git add", "git commit":
			ok = true
		case "git worktree":
			ok = f[2] == "add" || f[2] == "remove" // a temp checkout, never the user's
		case "git push": // exactly: push origin <fresh halos/ branch>
			ok = len(f) == 4 && f[2] == "origin" && strings.HasPrefix(f[3], "halos/")
		case "git branch":
			ok = len(f) == 4 && f[2] == "-D" && strings.HasPrefix(f[3], "halos/")
		case "gh pr":
			ok = f[2] == "create" && !strings.Contains(c, "--auto")
		}
		if !ok {
			t.Errorf("unexpected command: %.200s", c)
		}
	}
}
