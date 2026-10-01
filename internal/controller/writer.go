package controller

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/promote"
	"github.com/halos-dev/halos/internal/yamledit"
)

// Writer opens a policy-repo PR setting an experiment's status. It must never merge.
type Writer interface {
	ProposeStatus(ctx context.Context, experiment, status, title, body string) (prURL string, err error)
}

// GitWriter implements Writer with promote.PlanStatus and a promote.PROpener
// (GHOpener: branch in a temp worktree, git push, gh pr create). It is the one
// "set experiment status + open PR" implementation: `halo controller run` uses
// it on the CI checkout; halo-server's server.GitPolicyWriter uses it on its
// dedicated clone after syncing that clone to origin (under its own lock).
// It never touches RepoDir's branch, index or working tree.
type GitWriter struct {
	RepoDir string // git checkout (or any dir inside one)
	Subdir  string // policy root inside RepoDir
	Base    string // PR base branch; "" = repo default
	Opener  promote.PROpener
}

func (w *GitWriter) ProposeStatus(ctx context.Context, experiment, status, title, body string) (string, error) {
	dir := filepath.Join(w.RepoDir, w.Subdir)
	doc, err := yamledit.Find(dir, policy.KindExperiment, experiment)
	if err != nil {
		return "", fmt.Errorf("status PR: find experiment %s: %w", experiment, err)
	}
	rel, err := filepath.Rel(dir, doc.Path)
	if err != nil {
		return "", fmt.Errorf("status PR: %w", err)
	}
	exp := &policy.Experiment{Meta: policy.Meta{Name: experiment}}
	ch, err := promote.PlanStatus(promote.Target{RepoDir: dir, ExperimentFile: filepath.ToSlash(rel)}, exp, status)
	if err != nil {
		return "", fmt.Errorf("status PR: plan %s -> %s: %w", experiment, status, err)
	}
	if ch.Patch == "" {
		return "", fmt.Errorf("status PR: experiment %q already has status %q", experiment, status)
	}
	body += "\n\n```diff\n" + ch.Patch + "```\n\nOpened by Halos; a human must review and merge.\n"
	url, err := w.Opener.OpenPR(ctx, promote.PRRequest{
		RepoDir: dir, Base: w.Base, Branch: "halos/status-" + status + "-" + experiment,
		Title: title, Body: body, Files: ch.Files, Edit: ch.Edit,
	})
	if err != nil {
		return "", fmt.Errorf("status PR: open PR for %s: %w", experiment, err)
	}
	return url, nil
}
