// Package supplychain handles agent extension artifacts (skills, plugins,
// hooks, slash commands, agent definitions) as content-addressed trees
// (ADR-0028): reading them from the policy repo, fetching pinned remote
// sources (git commit, OCI digest), computing their digest, and the static
// scan run by `halo validate` and `halo release build`.
//
// It has no internal dependencies so policy, release and halod can all use it.
package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Tree is an artifact's content: slash-separated relative path -> bytes.
type Tree map[string][]byte

// Limits on one artifact. A skill or hook is a handful of small text files;
// anything near these is not one.
const (
	MaxFiles = 512
	MaxBytes = 8 << 20
)

// component is one path element: portable on every OS halod runs on (no
// spaces, no Windows-reserved characters, no "~" short-name aliases).
var component = regexp.MustCompile(`^[A-Za-z0-9._@+-]+$`)

// CheckPath reports whether p is a clean, relative, portable artifact path.
func CheckPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") {
		return fmt.Errorf("artifact path %q must be relative and non-empty", p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == "." || c == ".." || !component.MatchString(c) || strings.HasSuffix(c, ".") {
			return fmt.Errorf("artifact path %q has an invalid component %q (want [A-Za-z0-9._@+-], no . or .. and no trailing dot)", p, c)
		}
	}
	return nil
}

// Listing is the canonical text an artifact digest covers: one
// "<sha256 hex>  <path>\n" line per file, sorted by path in byte order. It is
// exactly what `sha256sum` prints for the sorted file list, so the digest can
// be reproduced without Halos (see docs/adr/0028).
func Listing(sums map[string]string) []byte {
	paths := make([]string, 0, len(sums))
	for p := range sums {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b strings.Builder
	for _, p := range paths {
		b.WriteString(sums[p] + "  " + p + "\n")
	}
	return []byte(b.String())
}

// DigestOf is "sha256:<hex>" of Listing(sums).
func DigestOf(sums map[string]string) string {
	sum := sha256.Sum256(Listing(sums))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Sums maps each path to the sha256 hex of its content.
func (t Tree) Sums() map[string]string {
	out := make(map[string]string, len(t))
	for p, b := range t {
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:])
	}
	return out
}

// Digest is the artifact digest: DigestOf(t.Sums()).
func (t Tree) Digest() string { return DigestOf(t.Sums()) }

// Check enforces non-emptiness, path rules and size limits.
func (t Tree) Check() error {
	if len(t) == 0 {
		return errors.New("artifact has no files")
	}
	if len(t) > MaxFiles {
		return fmt.Errorf("artifact has %d files, more than %d", len(t), MaxFiles)
	}
	total := 0
	for p, b := range t {
		if err := CheckPath(p); err != nil {
			return err
		}
		total += len(b)
	}
	if total > MaxBytes {
		return fmt.Errorf("artifact is %d bytes, more than %d", total, MaxBytes)
	}
	return nil
}

// ReadPath reads a file (keyed by its base name) or a directory tree. .git
// directories are skipped; symlinks and other non-regular files are refused,
// so a checkout cannot point the artifact outside itself.
func ReadPath(root string) (Tree, error) {
	fi, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	t := Tree{}
	if fi.Mode().IsRegular() {
		if fi.Size() > MaxBytes {
			return nil, fmt.Errorf("%s is %d bytes, more than %d", root, fi.Size(), MaxBytes)
		}
		b, err := os.ReadFile(root)
		if err != nil {
			return nil, err
		}
		t[filepath.Base(root)] = b
		return t, t.Check()
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a regular file or directory", root)
	}
	// Reads go through an os.Root, so a symlink swapped in after the walk
	// saw a regular file still cannot read outside root.
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }() // read-only
	total := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file (symlinks are refused)", p)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if total += int(info.Size()); total > MaxBytes || len(t) >= MaxFiles {
			return fmt.Errorf("%s exceeds the artifact limits (%d files, %d bytes)", root, MaxFiles, MaxBytes)
		}
		b, err := r.ReadFile(rel)
		if err != nil {
			return err
		}
		t[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	return t, t.Check()
}
