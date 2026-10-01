// Package intent turns intent-level requests ("upgrade claude-code to X",
// "canary this model", "enable this MCP server for 10%") into the low-level
// policy documents that express them, as file changes in the policy repo. It
// writes nothing itself beyond Change.Apply, never publishes and never merges:
// the change is reviewed and merged by a human like any other policy edit.
package intent

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/yamledit"
)

// Change is a set of whole-file writes under Dir (repo-relative, slash paths).
type Change struct {
	Dir   string
	Files map[string][]byte
	// Notes are follow-ups for the human (printed after the file list).
	Notes []string
	// Done lists side effects already performed, e.g. a published release.
	Done []string
}

func newChange(dir string) *Change { return &Change{Dir: dir, Files: map[string][]byte{}} }

func (c *Change) abs(rel string) string { return filepath.Join(c.Dir, filepath.FromSlash(rel)) }

// Paths splits the change's files into created and changed, sorted.
func (c *Change) Paths() (created, changed []string) {
	for _, rel := range sortedKeys(c.Files) {
		if _, err := os.Stat(c.abs(rel)); err == nil {
			changed = append(changed, rel)
		} else {
			created = append(created, rel)
		}
	}
	return created, changed
}

// Patch is the change as a unified diff.
func (c *Change) Patch() string {
	var b strings.Builder
	for _, rel := range sortedKeys(c.Files) {
		old, _ := os.ReadFile(c.abs(rel)) // missing = new file
		b.WriteString(promote.UnifiedDiff(rel, string(old), string(c.Files[rel])))
	}
	return b.String()
}

// Apply writes every file atomically.
func (c *Change) Apply() error {
	for _, rel := range sortedKeys(c.Files) {
		p := c.abs(rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fmt.Errorf("intent: write %s: %w", rel, err)
		}
		if err := fsutil.WriteAtomic(p, c.Files[rel], fsutil.ExistingPerm(p, 0o644)); err != nil {
			return fmt.Errorf("intent: write %s: %w", rel, err)
		}
	}
	return nil
}

// Validate loads and validates the policy as it would be after Apply.
func (c *Change) Validate() ([]policy.Issue, error) {
	org, err := c.Load()
	if err != nil {
		return nil, err
	}
	return org.Validate(), nil
}

// Load loads the policy as it would be after Apply, from a scratch copy of
// the repo's YAML (the repo itself is untouched).
func (c *Change) Load() (*policy.Org, error) {
	tmp, err := os.MkdirTemp("", "halo-intent-")
	if err != nil {
		return nil, fmt.Errorf("intent: load: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }() // scratch copy
	err = filepath.WalkDir(c.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != c.Dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, _ := filepath.Rel(c.Dir, p)
		b, err := os.ReadFile(p) //nolint:gosec // walks the operator-owned policy repo
		if err != nil {
			return err
		}
		return writeFile(tmp, rel, b)
	})
	if err != nil {
		return nil, fmt.Errorf("intent: load: copy %s: %w", c.Dir, err)
	}
	for rel, b := range c.Files {
		if err := writeFile(tmp, filepath.FromSlash(rel), b); err != nil {
			return nil, fmt.Errorf("intent: load: %w", err)
		}
	}
	org, err := policy.Load(tmp)
	if err != nil {
		return nil, fmt.Errorf("intent: the change does not load: %w", err)
	}
	return org, nil
}

// writeFile writes rel under root, refusing any rel that escapes it.
func writeFile(root, rel string, b []byte) error {
	if !filepath.IsLocal(rel) {
		return fmt.Errorf("path %q escapes the policy repo", rel)
	}
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644) //nolint:gosec // rel is checked local to root above
}

// Repo is a loaded policy repo plus its root document.
type Repo struct {
	Dir  string
	Root *policy.Root
	Org  *policy.Org
}

// Open loads dir.
func Open(dir string) (*Repo, error) {
	root, err := policy.ReadRoot(dir)
	if err != nil {
		return nil, err
	}
	org, err := policy.Load(dir)
	if err != nil {
		return nil, err
	}
	return &Repo{Dir: dir, Root: root, Org: org}, nil
}

// Simple reports whether halos.yaml uses simple mode.
func (r *Repo) Simple() bool { return r.Root.Enabled() }

// GA is the default ring.
func (r *Repo) GA() (*policy.Ring, error) {
	for _, g := range r.Org.Rings {
		if g.Membership.Default {
			return g, nil
		}
	}
	return nil, fmt.Errorf("intent: no default (GA) ring")
}

func (r *Repo) has(kind policy.Kind, name string) bool {
	_, err := yamledit.Find(r.Dir, kind, name)
	return err == nil
}

// docYAML marshals a policy document of kind with a leading comment.
func docYAML(kind policy.Kind, comment string, v any) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("# yaml-language-server: $schema=https://halos.dev/schemas/" + strings.ToLower(string(kind)) + ".schema.json\n")
	for _, l := range strings.Split(strings.TrimSpace(comment), "\n") {
		b.WriteString(strings.TrimRight("# "+l, " ") + "\n")
	}
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("intent: marshal %s: %w", kind, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("intent: marshal %s: %w", kind, err)
	}
	return b.Bytes(), nil
}

// slug makes s a valid policy name fragment.
func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

func ringNames(org *policy.Org) []string {
	out := make([]string, 0, len(org.Rings))
	for _, r := range org.Rings {
		out = append(out, r.Name)
	}
	return out
}

func validName(kind, n string) error {
	if !policy.ValidName(n) {
		return fmt.Errorf("intent: %s name %q is not a valid policy name (lowercase letters, digits, . _ -; max 63)", kind, n)
	}
	return nil
}
