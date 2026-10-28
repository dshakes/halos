package main

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"sort"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/release"
)

// maxPostureFile bounds a settings file halod reads for posture (ADR-0032).
const maxPostureFile = 1 << 20

// postureDrift adds to st.Drift every per-user setting that weakens a shipped
// harness's managed sandbox or egress posture (ADR-0032), as
// "posture:<harness>: <problem>; fix: <fix>". Managed files themselves are
// already restored byte for byte; what is left is the user's own config,
// which halod reports and never rewrites.
func (a *Agent) postureDrift(rel *release.Release, st *Status) {
	if a.User == "" {
		return
	}
	home := a.userHome()
	if home == "" {
		return
	}
	names := make([]string, 0, len(rel.Manifest.Harnesses))
	for n := range rel.Manifest.Harnesses {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, f := range harness.ReadPosture(n, harness.OS(a.Cfg.OS), home, a.readSettings).Findings {
			st.Drift = append(st.Drift, "posture:"+n+": "+f.Problem+"; fix: "+f.Fix)
		}
	}
}

// readSettings reads a settings file for posture checks (readUserFile, up to
// maxPostureFile). Contents are parsed for a few keys and never echoed.
func (a *Agent) readSettings(p string) ([]byte, error) { return a.readUserFile(p, maxPostureFile) }

// readUserFile reads a file the console user owns. halod runs as root, so only
// a regular file (not a symlink: it could point at a root-only file) up to max
// bytes is read, opened without blocking (a FIFO swapped in after the Lstat
// cannot hang the cycle). A missing file is an error wrapping fs.ErrNotExist.
func (a *Agent) readUserFile(p string, max int64) ([]byte, error) {
	p = a.path(p)
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", p, max)
	}
	f, err := os.OpenFile(p, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: over %d bytes", p, max)
	}
	return b, nil
}

// homeDir is the user's home directory ("" when unknown).
func homeDir(name string) string {
	if u, err := user.Lookup(name); err == nil {
		return u.HomeDir
	}
	return ""
}
