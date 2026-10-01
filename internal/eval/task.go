// Package eval is Halos's offline replay harness: it runs a suite of
// coding tasks against harness variants (CLI version x model x settings) in
// isolated environments, scores each run with the task's own success check,
// and renders a scorecard with bootstrap CIs and a paired comparison.
//
// Task format (evals/tasks/<name>/task.yaml) and rough Harbor mapping:
//
//	id          -> Harbor task name
//	repo        -> environment/ (Dockerfile COPY/clone of the project under test)
//	setup       -> environment build/setup steps
//	prompt      -> instruction.md
//	check       -> tests/test.sh  (exit 0 = pass; we do not read a reward file)
//	timeout     -> [agent] timeout
//	budget_usd  -> no Harbor equivalent; passed to the CLI's spend cap
//	tags        -> metadata tags
package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultTimeout applies when a task sets none.
const DefaultTimeout = 10 * time.Minute

// Task is one eval task.
type Task struct {
	ID        string        `yaml:"id" json:"id"`
	Repo      string        `yaml:"repo" json:"repo"` // git URL, or directory relative to the task dir
	Setup     []string      `yaml:"setup,omitempty" json:"setup,omitempty"`
	Prompt    string        `yaml:"prompt" json:"prompt"`
	Check     string        `yaml:"check" json:"check"` // shell command, exit 0 = pass
	Timeout   time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	BudgetUSD float64       `yaml:"budget_usd,omitempty" json:"budgetUSD,omitempty"`
	MaxTurns  int           `yaml:"max_turns,omitempty" json:"maxTurns,omitempty"`
	Tags      []string      `yaml:"tags,omitempty" json:"tags,omitempty"`

	// Dir is the directory holding task.yaml; set by LoadTask.
	Dir string `yaml:"-" json:"-"`
}

// Validate checks required fields.
func (t *Task) Validate() error {
	switch {
	case t.ID == "":
		return fmt.Errorf("task: id is required")
	case t.Repo == "":
		return fmt.Errorf("task %s: repo is required", t.ID)
	case strings.TrimSpace(t.Prompt) == "":
		return fmt.Errorf("task %s: prompt is required", t.ID)
	case strings.TrimSpace(t.Check) == "":
		return fmt.Errorf("task %s: check is required", t.ID)
	case t.Timeout < 0 || t.BudgetUSD < 0 || t.MaxTurns < 0:
		return fmt.Errorf("task %s: timeout, budget_usd and max_turns must be >= 0", t.ID)
	}
	return nil
}

// LoadTask reads <dir>/task.yaml.
func LoadTask(dir string) (*Task, error) {
	p := filepath.Join(dir, "task.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("load task: %w", err)
	}
	var t Task
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if t.Timeout == 0 {
		t.Timeout = DefaultTimeout
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if err := checkRepo(t.Repo); err != nil {
		return nil, fmt.Errorf("%s: task %s: %w", p, t.ID, err)
	}
	t.Dir = dir
	return &t, nil
}

// isRemote reports whether repo is a git URL rather than a local directory.
func isRemote(repo string) bool {
	return strings.Contains(repo, "://") || strings.HasPrefix(repo, "git@")
}

// checkRepo rejects anything but an https:// or git@ ssh URL, or a relative
// path (syntax only; symlink containment is checked by RepoDir at use time).
func checkRepo(repo string) error {
	switch {
	case strings.HasPrefix(repo, "-"):
		return fmt.Errorf("repo %q: must not start with '-'", repo)
	case strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "git@"):
		return nil
	case strings.Contains(repo, "://") || strings.Contains(repo, "::"):
		return fmt.Errorf("repo %q: only https:// and git@ URLs are allowed", repo)
	case filepath.IsAbs(repo) || strings.HasPrefix(repo, "~"):
		return fmt.Errorf("repo %q: absolute paths are not allowed", repo)
	}
	return nil
}

// resolveWithin joins rel onto root and returns the symlink-resolved path,
// failing unless it stays inside the symlink-resolved root.
func resolveWithin(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("%q: absolute paths are not allowed", rel)
	}
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", root, err)
	}
	p, err := filepath.EvalSymlinks(filepath.Join(r, rel))
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", rel, err)
	}
	if p != r && !strings.HasPrefix(p, r+string(filepath.Separator)) {
		return "", fmt.Errorf("%q escapes %s", rel, root)
	}
	return p, nil
}

// RepoDir resolves a local repo path against the task dir, refusing paths
// (including via symlinks) that leave it.
func (t *Task) RepoDir() (string, error) {
	if err := checkRepo(t.Repo); err != nil {
		return "", fmt.Errorf("task %s: %w", t.ID, err)
	}
	if isRemote(t.Repo) {
		return "", fmt.Errorf("task %s: repo is remote", t.ID)
	}
	p, err := resolveWithin(t.Dir, t.Repo)
	if err != nil {
		return "", fmt.Errorf("task %s: repo: %w", t.ID, err)
	}
	return p, nil
}

// gitCloneArgs is the hardened clone argv: protocol allowlist (https/ssh
// only, so file://, ext:: and local paths are refused) and `--` so a URL can
// never be parsed as an option.
func gitCloneArgs(url, dir string) []string {
	return []string{"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
		"clone", "--quiet", "--depth", "1", "--", url, dir}
}
