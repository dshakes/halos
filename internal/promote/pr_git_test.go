package promote

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/yamledit"
)

// gitRepo makes a clone of a bare origin with one commit on main.
func gitRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	origin, dir := filepath.Join(root, "origin.git"), filepath.Join(root, "work")
	run := func(dir string, args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(root, "init", "-q", "--bare", "-b", "main", origin)
	run(root, "clone", "-q", origin, dir)
	run(dir, "config", "user.name", "t")
	run(dir, "config", "user.email", "t@t")
	run(dir, "checkout", "-q", "-b", "main")
	for f, c := range map[string]string{"ring.yaml": ringYAML, "other.txt": "o\n"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(dir, "add", ".")
	run(dir, "commit", "-qm", "init")
	run(dir, "push", "-q", "-u", "origin", "main")
	return dir
}

// realGit runs git for real and records gh (which fails while ghErr is set).
func realGit(ghErr *error, gh *[]string) GHOpener {
	return GHOpener{Exec: func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		if name == "gh" {
			*gh = append(*gh, strings.Join(args, " "))
			if *ghErr != nil {
				return nil, *ghErr
			}
			return []byte("https://github.com/o/r/pull/1\n"), nil
		}
		return Run(ctx, dir, name, args...)
	}}
}

func TestGHOpenerRealGit(t *testing.T) {
	ctx := context.Background()
	dir := gitRepo(t)
	ghErr := errors.New("gh: network down")
	var gh []string
	o := realGit(&ghErr, &gh)
	req := PRRequest{RepoDir: dir, Base: "main", Branch: "halos/request-r1", Title: "t", CommitBody: "Reason: r",
		Files: map[string][]byte{"ring.yaml": []byte(strings.Replace(ringYAML, "sha256:old", "sha256:new", 1))}}

	// Staged, unrelated changes stay staged and are never committed.
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("staged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, dir, "git", "add", "other.txt"); err != nil {
		t.Fatal(err)
	}
	// First attempt: branch created, committed and pushed, then gh fails.
	if _, err := o.OpenPR(ctx, req); err == nil {
		t.Fatal("want gh failure")
	}
	// The user's checkout is untouched: still on main, index and tree as left.
	if br, _ := Run(ctx, dir, "git", "rev-parse", "--abbrev-ref", "HEAD"); strings.TrimSpace(string(br)) != "main" {
		t.Fatalf("checkout switched to %s", br)
	}
	if st, _ := Run(ctx, dir, "git", "status", "--porcelain"); string(st) != "M  other.txt\n" {
		t.Fatalf("user's index/tree changed: %q", st)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ring.yaml")); strings.Contains(string(b), "sha256:new") {
		t.Fatal("user's working tree modified")
	}
	if wts, _ := Run(ctx, dir, "git", "worktree", "list"); strings.Count(string(wts), "\n") != 1 {
		t.Fatalf("temporary worktree left behind:\n%s", wts)
	}
	// Retry succeeds despite the leftover branch.
	ghErr = nil
	url, err := o.OpenPR(ctx, req)
	if err != nil || url != "https://github.com/o/r/pull/1" {
		t.Fatalf("retry: %q %v", url, err)
	}
	if len(gh) != 2 || gh[0] == gh[1] {
		t.Fatalf("retry must use a fresh branch: %q", gh)
	}
	// Local branches are deleted after the push (also when gh failed).
	if br, _ := Run(ctx, dir, "git", "branch", "--list", "halos/*"); len(br) != 0 {
		t.Fatalf("local branches left behind: %s", br)
	}
	files, err := Run(ctx, dir, "git", "show", "--name-only", "--format=%B", "origin/"+strings.Fields(gh[1][strings.Index(gh[1], "--head ")+7:])[0])
	if err != nil || !strings.Contains(string(files), "Reason: r") || strings.Contains(string(files), "other.txt") {
		t.Fatalf("commit: %s %v", files, err)
	}
	remote, _ := Run(ctx, dir, "git", "ls-remote", "--heads", "origin")
	if strings.Count(string(remote), "halos/request-r1-") != 2 {
		t.Fatalf("pushed branches: %s", remote)
	}
}

func TestTransitionStatus(t *testing.T) {
	tests := []struct {
		verb, status, want string
		ok                 bool
	}{
		{"start", "", "running", true},
		{"start", "draft", "running", true},
		{"start", "running", "", false},
		{"pause", "running", "paused", true},
		{"pause", "draft", "", false},
		{"conclude", "paused", "concluded", true},
		{"conclude", "concluded", "", false},
		{"explode", "running", "", false},
	}
	for _, tc := range tests {
		src := "kind: Experiment\nname: e\n"
		if tc.status != "" {
			src += "status: " + tc.status + " # c\n"
		}
		m, err := yamledit.Parse([]byte(src), policy.KindExperiment, "e")
		if err != nil {
			t.Fatal(err)
		}
		from, to, data, err := TransitionStatus(&yamledit.Doc{Data: []byte(src), Mapping: m}, tc.verb)
		if (err == nil) != tc.ok || to != tc.want || from != tc.status && tc.verb != "explode" {
			t.Errorf("%s from %q: %q->%q %v", tc.verb, tc.status, from, to, err)
		}
		if tc.ok && !strings.Contains(string(data), "status: "+tc.want+"\n") && !strings.Contains(string(data), "status: "+tc.want+" # c\n") {
			t.Errorf("%s: data %q", tc.verb, data)
		}
	}
}

// A PRRequest carrying Edit re-applies the change to HEAD's copy of the file:
// the user's uncommitted edits to that same file must not ride into the PR.
func TestOpenPREditAppliesToHEAD(t *testing.T) {
	ctx := context.Background()
	dir := gitRepo(t)
	var ghErr error
	var gh []string
	o := realGit(&ghErr, &gh)
	// Uncommitted local edit to the very file the PR changes.
	dirty := ringYAML + "# local scratch — must not be committed\n"
	if err := os.WriteFile(filepath.Join(dir, "ring.yaml"), []byte(dirty), 0o644); err != nil {
		t.Fatal(err)
	}
	edit := func(read ReadFunc) (map[string][]byte, error) {
		b, err := read("ring.yaml")
		if err != nil {
			return nil, err
		}
		return map[string][]byte{"ring.yaml": []byte(strings.Replace(string(b), "sha256:old", "sha256:new", 1))}, nil
	}
	preview, _ := edit(func(string) ([]byte, error) { return []byte(dirty), nil })
	if _, err := o.OpenPR(ctx, PRRequest{RepoDir: dir, Base: "main", Branch: "halos/promote-x", Title: "t",
		Files: preview, Edit: edit}); err != nil {
		t.Fatal(err)
	}
	head := strings.Fields(gh[0][strings.Index(gh[0], "--head ")+7:])[0]
	got, err := Run(ctx, dir, "git", "show", "origin/"+head+":ring.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "sha256:new") || strings.Contains(string(got), "local scratch") {
		t.Fatalf("PR commit must be HEAD + edit only:\n%s", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ring.yaml")); string(b) != dirty {
		t.Fatal("user's working tree modified")
	}
}

func TestCommitOnBranchFailureLeavesNoBranch(t *testing.T) {
	ctx := context.Background()
	dir := gitRepo(t)
	_, _, err := CommitOnBranch(ctx, nil, dir, BranchCommit{Branch: "halos/x", Subject: "s",
		Edit: func(ReadFunc) (map[string][]byte, error) { return nil, errors.New("edit failed") }})
	if err == nil || !strings.Contains(err.Error(), "edit failed") {
		t.Fatalf("got %v", err)
	}
	if br, _ := Run(ctx, dir, "git", "branch", "--list", "halos/*"); len(br) != 0 {
		t.Fatalf("branch left behind: %s", br)
	}
	// A failed push also deletes the local branch.
	if _, err := Run(ctx, dir, "git", "remote", "set-url", "origin", filepath.Join(t.TempDir(), "gone")); err != nil {
		t.Fatal(err)
	}
	_, err = PushBranch(ctx, nil, dir, BranchCommit{Branch: "halos/y", Subject: "s",
		Edit: func(ReadFunc) (map[string][]byte, error) { return map[string][]byte{"new.txt": []byte("x\n")}, nil }})
	if err == nil || !strings.Contains(err.Error(), "push") {
		t.Fatalf("got %v", err)
	}
	if br, _ := Run(ctx, dir, "git", "branch", "--list", "halos/*"); len(br) != 0 {
		t.Fatalf("branch left behind after failed push: %s", br)
	}
}
