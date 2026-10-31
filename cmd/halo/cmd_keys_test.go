package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeConfigHome points $HOME and os.UserConfigDir at temp dirs on every OS and returns both.
func fakeConfigHome(t *testing.T) (home, cfg string) {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("AppData", filepath.Join(h, "AppData"))
	cfg, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no user config dir on this platform: %v", err)
	}
	return h, cfg
}

// gitRepo is a temp dir with a .git directory (enough for the work-tree check).
func gitRepo(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestKeysGenerateDefaultsToUserConfigDir(t *testing.T) {
	_, cfg := fakeConfigHome(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	code, out, errs := halo(t, "keys", "generate", "--name", "release")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errs)
	}
	dir := filepath.Join(cfg, "halos", "keys")
	for _, f := range []string{"release.key", "release.pub"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not in the user config dir: %v", f, err)
		}
		if _, err := os.Stat(filepath.Join(cwd, f)); err == nil {
			t.Errorf("%s was written into the working directory", f)
		}
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "release.key"): 0o600} {
			if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s mode = %v (%v), want %v", p, fi.Mode().Perm(), err, want)
			}
		}
	}
	if !strings.Contains(out, dir) {
		t.Errorf("output does not name the key location %s:\n%s", dir, out)
	}
}

func TestKeysGenerateRefusesInsideGitWorkTree(t *testing.T) {
	fakeConfigHome(t)
	for _, tc := range []struct {
		name     string
		args     func(repo string) []string
		wantCode int
		wantKey  func(repo string) string // where the key must (not) exist
	}{
		{"explicit --out is the repo root", func(r string) []string { return []string{"--out", r} }, 1, func(r string) string { return filepath.Join(r, "halo.key") }},
		{"explicit --out is a new dir in the repo", func(r string) []string { return []string{"--out", filepath.Join(r, "keys", "new")} }, 1, func(r string) string { return filepath.Join(r, "keys", "new", "halo.key") }},
		{"--force allows it", func(r string) []string { return []string{"--out", r, "--force"} }, 0, func(r string) string { return filepath.Join(r, "halo.key") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gitRepo(t)
			code, out, errs := halo(t, append([]string{"keys", "generate"}, tc.args(r)...)...)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d: %s%s", code, tc.wantCode, out, errs)
			}
			_, statErr := os.Stat(tc.wantKey(r))
			if (tc.wantCode == 0) != (statErr == nil) {
				t.Fatalf("key presence wrong (stat: %v)", statErr)
			}
			if tc.wantCode != 0 && (!strings.Contains(errs, "git work tree") || !strings.Contains(errs, "--force")) {
				t.Fatalf("error does not say why and what to do: %q", errs)
			}
		})
	}

	t.Run("default dir inside a git work tree is refused", func(t *testing.T) {
		// A user config dir that lives inside a repo (a dotfiles repo in $HOME).
		home, _ := fakeConfigHome(t)
		if err := os.Mkdir(filepath.Join(home, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		if code, _, errs := halo(t, "keys", "generate"); code != 1 || !strings.Contains(errs, "git work tree") {
			t.Fatalf("exit %d: %q", code, errs)
		}
	})
}
