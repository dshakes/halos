package promote

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// SyncClone hard-resets dir to a pristine origin/<base>: it refuses unless dir
// is the root of its own git work tree (the reset is destructive and must never
// hit a parent repo), then fetches base and force-checks it out, removing
// untracked files. run is promote.Run or a stand-in.
func SyncClone(ctx context.Context, run RunFunc, dir, base string) error {
	out, err := run(ctx, dir, "git", "rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("policy clone %s: %w", dir, err)
	}
	top := strings.TrimSpace(string(out))
	a, errA := filepath.EvalSymlinks(top)
	b, errB := filepath.EvalSymlinks(dir)
	if errA != nil || errB != nil || a != b {
		return fmt.Errorf("policy clone %s is not a git work tree root (%s); refusing to reset it", dir, top)
	}
	if _, err := run(ctx, dir, "git", "fetch", "origin", base); err != nil {
		return fmt.Errorf("sync policy clone %s: fetch: %w", dir, err)
	}
	return ResetClone(ctx, run, dir, base)
}

// ResetClone force-checks-out origin/<base> in dir and cleans untracked files
// (no fetch, no work-tree-root guard; call SyncClone first).
func ResetClone(ctx context.Context, run RunFunc, dir, base string) error {
	for _, args := range [][]string{{"checkout", "-f", "-B", base, "origin/" + base}, {"clean", "-fd"}} {
		if _, err := run(ctx, dir, "git", args...); err != nil {
			return fmt.Errorf("reset policy clone %s: %w", dir, err)
		}
	}
	return nil
}
