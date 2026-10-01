package promote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/fsutil"
)

// RunFunc runs a command in dir and returns stdout (see Run).
type RunFunc func(ctx context.Context, dir, name string, args ...string) ([]byte, error)

// ReadFunc returns the committed (HEAD) content of a dir-relative file.
type ReadFunc func(rel string) ([]byte, error)

// BranchCommit describes one commit onto a new branch.
type BranchCommit struct {
	Branch  string // prefix; a random suffix is always appended
	Subject string
	Body    string // optional second message paragraph
	// Edit returns the new content (dir-relative, slash-separated path ->
	// data) of every file to change. It is given the committed version of any
	// file via read, so uncommitted edits in the user's checkout never land in
	// the commit.
	Edit func(read ReadFunc) (map[string][]byte, error)
}

// CommitOnBranch commits bc.Edit's files onto a new local branch starting at
// HEAD and returns the branch (with its random suffix) and the commit. It works
// in a temporary `git worktree add -b` checkout that is removed afterwards, so
// the user's branch, index and working tree are never touched. It never pushes.
// run nil means Run.
func CommitOnBranch(ctx context.Context, run RunFunc, dir string, bc BranchCommit) (branch, commit string, err error) {
	if run == nil {
		run = Run
	}
	git := func(d string, args ...string) (string, error) {
		out, err := run(ctx, d, "git", args...)
		return strings.TrimSpace(string(out)), err
	}
	prefix, err := git(dir, "rev-parse", "--show-prefix") // dir relative to the repo root
	if err != nil {
		return "", "", fmt.Errorf("promote: %s must be a git repository: %w", dir, err)
	}
	var sfx [3]byte
	if _, err := rand.Read(sfx[:]); err != nil {
		return "", "", fmt.Errorf("promote: branch suffix: %w", err)
	}
	branch = bc.Branch + "-" + hex.EncodeToString(sfx[:])

	tmp, err := os.MkdirTemp("", "halo-worktree-*")
	if err != nil {
		return "", "", fmt.Errorf("promote: worktree temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }() // best effort temp cleanup
	wt := filepath.Join(tmp, "wt")
	if _, err := git(dir, "worktree", "add", "--quiet", "-b", branch, wt, "HEAD"); err != nil {
		return "", "", fmt.Errorf("promote: create branch %s: %w", branch, err)
	}
	// Runs after the worktree removal below (LIFO): a failed commit leaves no branch.
	created := branch // the named result is "" by the time an error return defers run
	defer func() {
		if err != nil {
			_, _ = run(context.WithoutCancel(ctx), dir, "git", "branch", "-D", created) // best effort; err already says what failed
		}
	}()
	defer func() {
		if _, rerr := run(context.WithoutCancel(ctx), dir, "git", "worktree", "remove", "--force", wt); rerr != nil && err == nil {
			err = fmt.Errorf("promote: remove worktree: %w", rerr)
		}
	}()

	files, err := bc.Edit(func(rel string) ([]byte, error) {
		out, err := run(ctx, dir, "git", "show", "HEAD:./"+rel) // "./" = relative to dir
		if err != nil {
			return nil, fmt.Errorf("read committed %s: %w", rel, err)
		}
		return out, nil
	})
	if err != nil {
		return "", "", err
	}
	names := make([]string, 0, len(files))
	for n, data := range files {
		rel := path.Join(prefix, n)
		p := filepath.Join(wt, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", "", fmt.Errorf("promote: write %s: %w", n, err)
		}
		if err := fsutil.WriteAtomic(p, data, fsutil.ExistingPerm(p, 0o644)); err != nil {
			return "", "", fmt.Errorf("promote: write %s: %w", n, err)
		}
		names = append(names, rel)
	}
	sort.Strings(names)
	msg := []string{"commit", "-m", bc.Subject}
	if bc.Body != "" {
		msg = append(msg, "-m", bc.Body)
	}
	for _, s := range [][]string{
		append([]string{"add", "--"}, names...),
		append(append(msg, "--"), names...), // pathspec: never commits anything else
	} {
		if _, err := git(wt, s...); err != nil {
			return "", "", fmt.Errorf("promote: %w", err)
		}
	}
	if commit, err = git(wt, "rev-parse", "HEAD"); err != nil {
		return "", "", fmt.Errorf("promote: %w", err)
	}
	return branch, commit, nil
}

// PushBranch runs CommitOnBranch, pushes the branch to origin and then deletes
// the local branch whether or not the push succeeded, so a long-lived clone
// (halo-server's policy writer) never accumulates branches. run nil means Run.
func PushBranch(ctx context.Context, run RunFunc, dir string, bc BranchCommit) (string, error) {
	if run == nil {
		run = Run
	}
	branch, _, err := CommitOnBranch(ctx, run, dir, bc)
	if err != nil {
		return "", err
	}
	_, perr := run(ctx, dir, "git", "push", "origin", branch)
	// Best effort: after a push, failing the PR over a stray local ref would
	// only orphan the remote branch on retry.
	_, _ = run(context.WithoutCancel(ctx), dir, "git", "branch", "-D", branch)
	if perr != nil {
		return "", fmt.Errorf("promote: %w", perr)
	}
	return branch, nil
}
