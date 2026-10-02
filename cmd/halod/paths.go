package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // managed paths and binaries come from the adapters
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
	if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsAny(p, "\\\x00") {
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
		// Win32 strips trailing dots and spaces (".. " becomes "..") and maps
		// DOS device names (NUL, CON.json) to devices: refuse both. '~' is
		// refused so no component can be an 8.3 short name (MANAGE~1.JSO)
		// aliasing another entry, which would defeat stale-file tracking.
		if c == "" || c == "." || c == ".." || strings.ContainsAny(c, ":*?\"<>|~\x00") ||
			strings.TrimRight(c, ". ") != c || windowsDevice(c) {
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

// windowsDevice reports a DOS device name, with or without an extension.
func windowsDevice(c string) bool {
	base, _, _ := strings.Cut(strings.ToUpper(strings.TrimRight(c, " ")), ".")
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9'
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

// selfExe is the running halod, symlinks resolved.
func selfExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate halod binary: %w", err)
	}
	return filepath.EvalSymlinks(exe)
}

// checkExe refuses an exe that exists on any path a non-root user could
// replace it: the resolved binary and every ancestor must be root/SYSTEM-owned
// and not group/other-writable. Same rules (and test escape hatch) as checkChain.
// halod runs as root, so a user-writable binary would be a local privilege escalation.
func checkExe(exe string) error {
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("halod binary %s: %w", exe, err)
	}
	if err := checkChain(real); err != nil {
		return fmt.Errorf("insecure halod binary %s: %w", real, err)
	}
	return nil
}
