package copilot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/impact"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/release"
)

// File is one whole policy file a draft writes (slash path relative to the
// policy dir).
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// RingPlan is one ring's release change, as `halo plan` reports it.
type RingPlan struct {
	Ring    string `json:"ring"`
	Changed bool   `json:"changed"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Diff    string `json:"diff,omitempty"`
}

// Check is the deterministic verdict on a candidate policy. OK means no
// errors: it is the only thing that lets a draft be applied.
type Check struct {
	OK       bool           `json:"ok"`
	Errors   []string       `json:"errors"`
	Warnings []string       `json:"warnings"`
	Diff     string         `json:"diff"` // unified diff of the policy files
	Plans    []RingPlan     `json:"plans"`
	Impact   *impact.Report `json:"impact,omitempty"`
	Risks    []string       `json:"risks"` // deterministic risk notes
}

// impactSamples and impactExamples match `halo plan --diff`'s policy estimate.
const (
	impactSamples  = 1000
	impactExamples = 5
	maxFiles       = 20
	maxFileBytes   = 256 << 10
)

// checkPath admits only a clean, relative .yaml/.yml path with no hidden or
// parent segments: a draft can never write outside the policy dir.
func checkPath(p string) error {
	switch ext := path.Ext(p); {
	case p == "" || strings.ContainsAny(p, "\\:\x00") || path.IsAbs(p) || path.Clean(p) != p:
		return fmt.Errorf("path %q must be a clean relative slash path", p)
	case ext != ".yaml" && ext != ".yml":
		return fmt.Errorf("path %q must be a .yaml or .yml file", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || strings.HasPrefix(seg, ".") {
			return fmt.Errorf("path %q has a parent or hidden segment", p)
		}
	}
	return nil
}

func checkFiles(files []File) error {
	if len(files) == 0 || len(files) > maxFiles {
		return fmt.Errorf("want 1 to %d files, got %d", maxFiles, len(files))
	}
	seen := map[string]bool{}
	for _, f := range files {
		if err := checkPath(f.Path); err != nil {
			return err
		}
		if seen[f.Path] {
			return fmt.Errorf("path %q appears twice", f.Path)
		}
		seen[f.Path] = true
		if strings.TrimSpace(f.Content) == "" || len(f.Content) > maxFileBytes {
			return fmt.Errorf("file %s: content must be non-empty and at most %d bytes", f.Path, maxFileBytes)
		}
	}
	return nil
}

// Verify writes files over a copy of the policy at dir and runs every check
// a human change faces: the invariant-1 bypass-token scan over every byte
// written (comments included), load and validation, a release build and diff
// per ring against the current policy, and the impact preview. Check errors
// are findings (fed back to the model); the error return is for failures to
// run the checks at all.
func Verify(dir string, files []File) (*Check, error) {
	base, err := policy.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("copilot: the current policy must load before drafting against it: %w", err)
	}
	chk := &Check{Errors: []string{}, Warnings: []string{}, Plans: []RingPlan{}, Risks: []string{}}
	if err := checkFiles(files); err != nil {
		chk.Errors = append(chk.Errors, err.Error())
		return chk, nil
	}
	for _, f := range files {
		if tok := policy.BypassToken(f.Content); tok != "" {
			chk.Errors = append(chk.Errors, fmt.Sprintf("%s: contains permission-bypass token %q, forbidden by invariant 1 (comments included)", f.Path, tok))
		}
	}
	if chk.Diff, err = fileDiff(dir, files); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "halo-copilot-*")
	if err != nil {
		return nil, fmt.Errorf("copilot: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }() // best effort temp cleanup
	if err := copyPolicy(dir, tmp); err != nil {
		return nil, err
	}
	for _, f := range files {
		p := filepath.Join(tmp, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, fmt.Errorf("copilot: %w", err)
		}
		if err := os.WriteFile(p, []byte(f.Content), 0o600); err != nil {
			return nil, fmt.Errorf("copilot: %w", err)
		}
	}
	cand, err := policy.Load(tmp)
	if err != nil {
		chk.Errors = append(chk.Errors, "load: "+strings.ReplaceAll(err.Error(), tmp, "."))
		return chk.done(), nil
	}
	for _, i := range cand.Validate() {
		if i.Severity == policy.SeverityError {
			chk.Errors = append(chk.Errors, "validate: "+i.String())
		} else {
			chk.Warnings = append(chk.Warnings, "validate: "+i.String())
		}
	}
	if len(chk.Errors) > 0 {
		return chk.done(), nil
	}
	plans, rep, errs := Compare(base, cand)
	chk.Plans, chk.Impact = plans, rep
	chk.Errors = append(chk.Errors, errs...)
	return chk.done(), nil
}

func (c *Check) done() *Check {
	c.OK = len(c.Errors) == 0
	for _, p := range c.Plans {
		if p.Changed {
			c.Risks = append(c.Risks, fmt.Sprintf("ring %s gets a new release (%s -> %s)", p.Ring, short(p.From), short(p.To)))
		}
	}
	if c.Impact != nil {
		kinds := make([]string, 0, len(c.Impact.ByKind))
		for k := range c.Impact.ByKind {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			if n := c.Impact.ByKind[k]; n.Any > 0 {
				c.Risks = append(c.Risks, fmt.Sprintf("%d of %d %s members change (ring %d, variant %d, settings %d; policy estimate)", n.Any, n.Total, k, n.Ring, n.Variant, n.Settings))
			}
		}
	}
	if len(c.Warnings) > 0 {
		c.Risks = append(c.Risks, fmt.Sprintf("%d validation warnings to review", len(c.Warnings)))
	}
	return c
}

func short(d string) string {
	if d == "" {
		return "none"
	}
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

// Compare builds every ring of cand and diffs it against base's build of the
// same ring (a ring new in cand diffs against an empty release), then
// previews the impact over the policy estimate `halo plan --diff` uses.
func Compare(base, cand *policy.Org) ([]RingPlan, *impact.Report, []string) {
	plans := []RingPlan{}
	var errs []string
	for _, r := range cand.Rings {
		cur, _, err := release.BuildRing(cand, r.Name, release.Options{Version: "0.0.0-dev", Org: cand.Name})
		if err != nil {
			errs = append(errs, fmt.Sprintf("plan: build ring %s: %v", r.Name, err))
			continue
		}
		prev := &release.Release{}
		if b, _, err := release.BuildRing(base, r.Name, release.Options{Version: "0.0.0-dev", Org: base.Name}); err == nil {
			prev = b
		}
		d := release.Diff(prev, cur)
		plans = append(plans, RingPlan{Ring: r.Name, Changed: d != "", From: prev.Digest, To: cur.Digest, Diff: d})
	}
	rep := impact.Compute(base, cand, impact.PolicyMembers(impactSamples, base, cand), impactExamples)
	rep.Source = "policy"
	return plans, &rep, errs
}

// fileDiff is the unified diff of files against their working-tree versions
// (an absent file diffs from empty).
func fileDiff(dir string, files []File) (string, error) {
	var sb strings.Builder
	for _, f := range sorted(files) {
		old, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("copilot: read %s: %w", f.Path, err)
		}
		sb.WriteString(promote.UnifiedDiff(f.Path, string(old), f.Content))
	}
	return sb.String(), nil
}

func sorted(files []File) []File {
	out := append([]File(nil), files...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// copyPolicy copies dir's regular files into dst, skipping hidden
// directories (.git) and anything that is not a regular file (symlinks).
func copyPolicy(dir, dst string) error {
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // walks the operator-owned policy repo
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		return fmt.Errorf("copilot: copy policy %s: %w", dir, err)
	}
	return nil
}

// noSymlinks refuses a path whose existing components under dir include a
// symlink: a commit must land on the file the human reviewed.
func noSymlinks(dir, rel string) error {
	cur := dir
	for _, seg := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("copilot: %w", err)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("copilot: %s goes through a symlink; refusing to write it", rel)
		}
	}
	return nil
}

// Apply re-runs Verify and, only when it passes, commits files to a new
// local halos/copilot-<slug>-<random> branch (promote.CommitOnBranch: a
// temporary worktree, so the user's checkout is untouched). It refuses a
// file with uncommitted changes: the draft was made against the working
// tree, the commit is made against HEAD. It never pushes or opens a PR.
func Apply(ctx context.Context, run promote.RunFunc, dir string, files []File, slug, subject, body string) (branch, commit string, chk *Check, err error) {
	if chk, err = Verify(dir, files); err != nil {
		return "", "", nil, err
	}
	if !chk.OK {
		return "", "", chk, fmt.Errorf("copilot: refusing to apply: %d check errors: %s", len(chk.Errors), strings.Join(chk.Errors, "; "))
	}
	for _, f := range files {
		if err := noSymlinks(dir, f.Path); err != nil {
			return "", "", chk, err
		}
	}
	out := make(map[string][]byte, len(files))
	edit := func(read promote.ReadFunc) (map[string][]byte, error) {
		for _, f := range files {
			wt, werr := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
			head, herr := read(f.Path)
			switch {
			case werr != nil && !errors.Is(werr, fs.ErrNotExist):
				return nil, fmt.Errorf("copilot: read %s: %w", f.Path, werr)
			case herr != nil && werr == nil:
				return nil, fmt.Errorf("copilot: %s exists but is not committed; commit it first", f.Path)
			case herr == nil && (werr != nil || !bytes.Equal(head, wt)):
				return nil, fmt.Errorf("copilot: %s has uncommitted changes; commit or discard them first", f.Path)
			}
			out[f.Path] = []byte(f.Content)
		}
		return out, nil
	}
	branch, commit, err = promote.CommitOnBranch(ctx, run, dir, promote.BranchCommit{
		Branch: "halos/copilot-" + Slug(slug), Subject: subject, Body: body, Edit: edit,
	})
	if err != nil {
		return "", "", chk, err
	}
	return branch, commit, chk, nil
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slug is a branch- and file-name-safe form of s (at most 40 bytes).
func Slug(s string) string {
	s = strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = strings.TrimRight(s[:40], "-")
	}
	if s == "" {
		return "draft"
	}
	return s
}
