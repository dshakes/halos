package promote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/yamledit"
)

// Target locates the policy-repo files a change edits, relative to RepoDir.
type Target struct {
	RepoDir        string
	RingFile       string // YAML containing the Ring document
	ExperimentFile string // YAML containing the Experiment document
}

// Change is a proposed edit to the policy repo: new file contents plus a
// human-readable unified diff.
type Change struct {
	Files map[string][]byte // repo-relative path -> new content
	Patch string
	// Edit re-applies just this change to whatever read returns (see
	// BranchCommit.Edit), e.g. to the committed version of each file.
	Edit func(read ReadFunc) (map[string][]byte, error)
}

// PlanPromote points ring at release and marks the experiment concluded.
// release is required: promotion of a traffic-axis experiment (a model route
// change) is edited by a human in the gateway config, not here.
func PlanPromote(t Target, exp *policy.Experiment, ring, release string) (*Change, error) {
	if release == "" {
		return nil, errors.New("promote: release digest is required to plan a promotion")
	}
	return plan(t, exp, ring, release, "concluded")
}

// PlanRollback pauses the experiment and, when release is non-empty, re-points
// ring at it (the last known-good release).
func PlanRollback(t Target, exp *policy.Experiment, ring, release string) (*Change, error) {
	return plan(t, exp, ring, release, "paused")
}

// PlanStatus only sets the experiment's status (e.g. paused, concluded).
func PlanStatus(t Target, exp *policy.Experiment, status string) (*Change, error) {
	return plan(t, exp, "", "", status)
}

func plan(t Target, exp *policy.Experiment, ring, release, status string) (*Change, error) {
	type edit struct {
		file string
		kind policy.Kind
		name string
		key  string
		val  string
	}
	edits := []edit{{t.ExperimentFile, policy.KindExperiment, exp.Name, "status", status}}
	if release != "" {
		edits = append([]edit{{t.RingFile, policy.KindRing, ring, "release", release}}, edits...)
	}
	apply := func(read ReadFunc) (map[string][]byte, error) {
		files := map[string][]byte{}
		for _, e := range edits {
			old, ok := files[e.file]
			if !ok {
				b, err := read(e.file)
				if err != nil {
					return nil, fmt.Errorf("promote: read %s: %w", e.file, err)
				}
				old = b
			}
			nw, err := setField(old, e.kind, e.name, e.key, e.val)
			if err != nil {
				return nil, fmt.Errorf("promote: %s: %w", e.file, err)
			}
			files[e.file] = nw
		}
		return files, nil
	}
	files, err := apply(func(f string) ([]byte, error) { return os.ReadFile(filepath.Join(t.RepoDir, f)) })
	if err != nil {
		return nil, err
	}
	ch := &Change{Files: files, Edit: apply}
	var patch strings.Builder
	for _, f := range sortedKeys(ch.Files) {
		old, err := os.ReadFile(filepath.Join(t.RepoDir, f))
		if err != nil {
			return nil, fmt.Errorf("promote: read %s: %w", f, err)
		}
		patch.WriteString(UnifiedDiff(f, string(old), string(ch.Files[f])))
	}
	ch.Patch = patch.String()
	return ch, nil
}

func sortedKeys(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// setField sets a top-level scalar key on the document of the given kind and
// name inside a (possibly multi-document) YAML file by byte splice, so
// comments, formatting and the other documents are preserved.
func setField(content []byte, kind policy.Kind, name, key, val string) ([]byte, error) {
	m, err := yamledit.Parse(content, kind, name)
	if err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if m == nil {
		return nil, fmt.Errorf("no %s document named %q", kind, name)
	}
	return (&yamledit.Doc{Path: string(kind) + "/" + name, Data: content, Mapping: m}).SetField(key, val)
}

// StatusTransitions are the experiment status verbs (halo exp start|pause|conclude
// and the MCP tools): the status each sets and the statuses it may leave.
var StatusTransitions = map[string]struct {
	To   string
	From []string
}{
	"start":    {"running", []string{"", "draft", "paused"}},
	"pause":    {"paused", []string{"running"}},
	"conclude": {"concluded", []string{"running", "paused"}},
}

// TransitionStatus checks verb against the experiment document's current
// status and returns the edited file content (d is not written).
func TransitionStatus(d *yamledit.Doc, verb string) (from, to string, data []byte, err error) {
	tr, ok := StatusTransitions[verb]
	if !ok {
		return "", "", nil, fmt.Errorf("unknown experiment verb %q", verb)
	}
	name := ""
	if _, n := yamledit.Scalar(d.Mapping, "name"); n != nil {
		name = n.Value
	}
	if _, sv := yamledit.Scalar(d.Mapping, "status"); sv != nil {
		from = sv.Value
	}
	if !slices.Contains(tr.From, from) {
		return from, "", nil, fmt.Errorf("cannot %s experiment %q: status is %q", verb, name, from)
	}
	data, err = d.SetField("status", tr.To)
	return from, tr.To, data, err
}

// UnifiedDiff renders a single-hunk unified diff (common prefix/suffix
// trimmed, 3 lines of context). Empty when nothing changed.
func UnifiedDiff(path, old, nw string) string {
	if old == nw {
		return ""
	}
	a, b := strings.SplitAfter(old, "\n"), strings.SplitAfter(nw, "\n")
	a, b = trimEmpty(a), trimEmpty(b)
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	s := 0
	for s < len(a)-p && s < len(b)-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	c0 := max(p-3, 0)
	c1 := min(s, 3)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n@@ -%d,%d +%d,%d @@\n", path, path,
		c0+1, len(a)-s+c1-c0, c0+1, len(b)-s+c1-c0)
	line := func(prefix string, l string) {
		sb.WriteString(prefix + l)
		if !strings.HasSuffix(l, "\n") {
			sb.WriteString("\n\\ No newline at end of file\n")
		}
	}
	for _, l := range a[c0:p] {
		line(" ", l)
	}
	for _, l := range a[p : len(a)-s] {
		line("-", l)
	}
	for _, l := range b[p : len(b)-s] {
		line("+", l)
	}
	for _, l := range a[len(a)-s : len(a)-s+c1] {
		line(" ", l)
	}
	return sb.String()
}

func trimEmpty(x []string) []string {
	if n := len(x); n > 0 && x[n-1] == "" {
		return x[:n-1]
	}
	return x
}

// ApplyRollback writes a rollback change straight into the working tree
// (atomically per file). Only rollbacks may be applied directly; promotions go
// through OpenPR.
func ApplyRollback(repoDir string, ch *Change) error {
	for _, f := range sortedKeys(ch.Files) {
		p := filepath.Join(repoDir, f)
		if err := fsutil.WriteAtomic(p, ch.Files[f], fsutil.ExistingPerm(p, 0o644)); err != nil {
			return fmt.Errorf("promote: apply %s: %w", f, err)
		}
	}
	return nil
}

// PRRequest is what a PROpener needs to publish a change for review.
type PRRequest struct {
	RepoDir string
	Base    string // base branch; empty = repo default
	Branch  string
	Title   string
	Body    string
	// CommitBody is an optional extra commit-message paragraph (e.g. the reason).
	CommitBody string
	Files      map[string][]byte
	// Edit, when set, re-applies the change to the committed (HEAD) version of
	// each file, so uncommitted working-tree edits never ride into the PR.
	// Files is then only the preview.
	Edit func(ReadFunc) (map[string][]byte, error)
}

// PROpener publishes a change as a pull request. Implementations must never
// merge.
type PROpener interface {
	OpenPR(ctx context.Context, req PRRequest) (url string, err error)
}

// OpenPR builds the PR for a promotion verdict and hands it to the opener. It
// is the only path by which a promotion reaches the policy repo; a human
// merges.
func OpenPR(ctx context.Context, o PROpener, t Target, ch *Change, exp *policy.Experiment, rep Report, base string) (string, error) {
	if rep.Verdict != Promote {
		return "", fmt.Errorf("promote: refusing to open a promotion PR for verdict %q", rep.Verdict)
	}
	body := fmt.Sprintf("Automated promotion proposal for experiment `%s`.\n\n"+
		"- Verdict: **%s** (%s)\n- Control: `%s` (n=%d), treatment: `%s` (n=%d)\n- Primary effect: %+.4g (p=%.4f)\n",
		exp.Name, rep.Verdict, rep.Reason, rep.Control, rep.NControl, rep.Treatment, rep.NTreatment, rep.Effect, rep.PValue)
	for _, g := range rep.Guardrails {
		body += fmt.Sprintf("- Guardrail `%s`: %s (regression %.1f%%)\n", g.Metric, g.Result.Status, 100*g.Result.Regression)
	}
	body += "\n```diff\n" + ch.Patch + "```\n\nThis PR was opened by Halos and must be reviewed and merged by a human.\n"
	return o.OpenPR(ctx, PRRequest{
		RepoDir: t.RepoDir, Base: base,
		Branch: "halos/promote-" + exp.Name,
		Title:  fmt.Sprintf("Promote %s: %s", exp.Name, rep.Treatment),
		Body:   body, Files: ch.Files,
	})
}

// Run runs name in dir and returns stdout; errors carry the trimmed stderr.
// It is the one command runner for git/gh in promote and its callers.
func Run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		sub := ""
		if len(args) > 0 {
			sub = " " + args[0]
		}
		return out, fmt.Errorf("%s%s: %w: %s", name, sub, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// GHOpener opens PRs with git and the gh CLI. It commits the given files onto a
// uniquely suffixed branch (so a retry after a partial failure never collides)
// in a temporary worktree (see CommitOnBranch), so the user's checkout, branch
// and index are never touched, pushes the branch, and runs `gh pr create`. It
// never merges.
//
// UNVERIFIED against a real GitHub; tests use real git and a recording gh.
type GHOpener struct {
	// Exec runs a command in dir and returns stdout; default Run.
	Exec func(ctx context.Context, dir, name string, args ...string) ([]byte, error)
}

func (g GHOpener) run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	if g.Exec != nil {
		return g.Exec(ctx, dir, name, args...)
	}
	return Run(ctx, dir, name, args...)
}

func prEdit(r PRRequest) func(ReadFunc) (map[string][]byte, error) {
	if r.Edit != nil {
		return r.Edit
	}
	return func(ReadFunc) (map[string][]byte, error) { return r.Files, nil }
}

func (g GHOpener) OpenPR(ctx context.Context, r PRRequest) (string, error) {
	branch, err := PushBranch(ctx, g.run, r.RepoDir, BranchCommit{
		Branch: r.Branch, Subject: r.Title, Body: r.CommitBody,
		Edit: prEdit(r),
	})
	if err != nil {
		return "", err
	}
	args := []string{"pr", "create", "--title", r.Title, "--body", r.Body, "--head", branch}
	if r.Base != "" {
		args = append(args, "--base", r.Base)
	}
	out, err := g.run(ctx, r.RepoDir, "gh", args...)
	if err != nil {
		return "", fmt.Errorf("promote: gh pr create: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
