package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/halos-dev/halos/internal/harness"
	_ "github.com/halos-dev/halos/internal/harness/all" // managed paths and binaries come from the adapters
)

// layout is halod's fixed, root-owned footprint per OS. Nothing here is
// configurable from the (network-delivered) manifest.
type layout struct {
	Config, State string
	Bin           string // verified binary artifacts
	NPM           string // npm --prefix for verified npm-tgz artifacts
	Shim          string // symlinks to Bin/NPM entries ("" = none, e.g. windows)
}

var layouts = map[string]layout{
	"darwin": {
		Config: "/Library/Halos/etc/halod.yaml", State: "/Library/Halos/var/state.json",
		Bin: "/Library/Halos/bin", NPM: "/Library/Halos/npm", Shim: "/usr/local/bin",
	},
	"linux": {
		Config: "/etc/halos/halod.yaml", State: "/var/lib/halos/state.json",
		Bin: "/usr/local/lib/halos/bin", NPM: "/usr/local/lib/halos/npm", Shim: "/usr/local/bin",
	},
	"windows": {
		Config: `C:\Program Files\Halos\etc\halod.yaml`, State: `C:\Program Files\Halos\var\state.json`,
		Bin: `C:\Program Files\Halos\bin`, NPM: `C:\Program Files\Halos\npm`,
	},
}

// managedDirs is harness h's allowlist of admin config directories halod may
// write under (any depth) on goos, from the adapter's harness.Meta. A signed
// manifest naming anything else is refused: the release key alone must not be
// enough to write arbitrary files as root.
func managedDirs(h, goos string) []string {
	m, _ := harness.MetaOf(h)
	return m.ManagedDirs[harness.OS(goos)]
}

// managedFiles are h's single-file patterns (path.Match) on goos.
func managedFiles(h, goos string) []string {
	m, _ := harness.MetaOf(h)
	return m.ManagedFiles[harness.OS(goos)]
}

func harnessNames() []string { return harness.Names() }

// binaryFor is the executable halod probes with --version for harness h.
func binaryFor(h string) (string, bool) {
	m, _ := harness.MetaOf(h)
	return m.Binary, m.Binary != ""
}

// allowedPath reports whether harness h may manage p on goos. p must already
// be clean and absolute; ".." and "." components are refused outright.
func allowedPath(h, goos, p string) error {
	if goos == "windows" {
		return allowedWindows(h, p)
	}
	if !path.IsAbs(p) || path.Clean(p) != p || strings.Contains(p, "\\") {
		return fmt.Errorf("path %q is not clean and absolute", p)
	}
	for _, d := range managedDirs(h, goos) {
		if strings.HasPrefix(p, d+"/") {
			return nil
		}
	}
	for _, pat := range managedFiles(h, goos) {
		if ok, _ := path.Match(pat, p); ok {
			return nil
		}
	}
	return fmt.Errorf("path %q is outside %s's managed locations on %s", p, h, goos)
}

func allowedWindows(h, p string) error {
	rest, ok := strings.CutPrefix(p, `C:\`)
	if !ok || strings.Contains(p, "/") {
		return fmt.Errorf("path %q is not an absolute C:\\ path", p)
	}
	for _, c := range strings.Split(rest, `\`) {
		if c == "" || c == "." || c == ".." || strings.ContainsAny(c, `:*?"<>|`) {
			return fmt.Errorf("path %q has an invalid component %q", p, c)
		}
	}
	for _, d := range managedDirs(h, "windows") {
		if strings.HasPrefix(strings.ToLower(p), strings.ToLower(d)+`\`) {
			return nil
		}
	}
	return fmt.Errorf("path %q is outside %s's managed locations on windows", p, h)
}

// allowedAny is allowedPath for any known harness (stale-file removal, where
// the owning harness is no longer known).
func allowedAny(goos, p string) bool {
	for _, h := range harnessNames() {
		if allowedPath(h, goos, p) == nil {
			return true
		}
	}
	return false
}

// checkChain verifies p (if it exists) and every existing ancestor is owned by
// root/SYSTEM and not writable by group/other, and that no component is a
// symlink planted by a non-root user. Missing trailing components are fine:
// halod creates them itself. Because every existing directory on the way is
// root-controlled, a non-root user cannot race the subsequent write.
func checkChain(p string) error {
	p = filepath.Clean(p)
	var chain []string
	for c := p; ; c = filepath.Dir(c) {
		chain = append(chain, c)
		if filepath.Dir(c) == c {
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		fi, err := os.Lstat(chain[i]) //nolint:gosec // Lstat of halod-owned path chain; symlinks are checked, not followed
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lstat %s: %w", chain[i], err)
		}
		if err := checkTrusted(chain[i], fi); err != nil {
			return err
		}
	}
	return nil
}
