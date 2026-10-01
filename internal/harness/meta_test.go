package harness_test

import (
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
)

// Every adapter must publish Meta: halod, halo release build and the gateway
// derive their harness lists from it.
func TestEveryAdapterHasMeta(t *testing.T) {
	bin := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	if len(harness.Names()) == 0 {
		t.Fatal("no adapters registered")
	}
	for _, n := range harness.Names() {
		m, ok := harness.MetaOf(n)
		if !ok {
			t.Errorf("%s: adapter does not implement harness.Describer", n)
			continue
		}
		if !bin.MatchString(m.Binary) {
			t.Errorf("%s: binary %q", n, m.Binary)
		}
		switch m.Installer {
		case harness.InstallerNPM:
			if m.NPMPackage == "" {
				t.Errorf("%s: npm installer without package", n)
			}
		case harness.InstallerClaudeNative, "":
			if m.NPMPackage != "" {
				t.Errorf("%s: npm package set for installer %q", n, m.Installer)
			}
		default:
			t.Errorf("%s: unknown installer %q", n, m.Installer)
		}
		for _, p := range m.UAPrefixes {
			if p == "" || p != strings.ToLower(p) {
				t.Errorf("%s: UA prefix %q must be non-empty lower-case", n, p)
			}
		}
	}
	if _, ok := harness.MetaOf("no-such-harness"); ok {
		t.Fatal("unknown harness has meta")
	}
}

// Every file an adapter renders must sit inside its own Meta.ManagedDirs /
// ManagedFiles, or halod (which enforces that allowlist) would refuse it.
func TestRenderedFilesWithinManagedLocations(t *testing.T) {
	prof, gw := hutiltest.Fixture()
	for _, n := range harness.Names() {
		a, _ := harness.Get(n)
		m, _ := harness.MetaOf(n)
		for _, os := range []harness.OS{harness.Darwin, harness.Linux, harness.Windows} {
			files, _, err := a.Render(prof, harness.Context{Gateway: gw, Ring: "r", Release: "x", OS: os})
			if err != nil {
				t.Fatalf("%s/%s: %v", n, os, err)
			}
			for _, f := range files {
				if !within(m, os, f.Path) {
					t.Errorf("%s/%s renders %s outside its managed locations %v %v", n, os, f.Path, m.ManagedDirs[os], m.ManagedFiles[os])
				}
			}
		}
	}
}

func within(m harness.Meta, os harness.OS, p string) bool {
	sep := "/"
	if os == harness.Windows {
		sep = `\`
	}
	for _, d := range m.ManagedDirs[os] {
		if strings.HasPrefix(p, d+sep) {
			return true
		}
	}
	for _, pat := range m.ManagedFiles[os] {
		if ok, _ := path.Match(pat, p); ok {
			return true
		}
	}
	return false
}

type stub struct{ harness.Adapter }

func (stub) Name() string { return "codex" }

func TestOverride(t *testing.T) {
	orig, _ := harness.Get("codex")
	restore := harness.Override(stub{orig})
	if a, _ := harness.Get("codex"); a == orig {
		t.Fatal("not overridden")
	}
	restore()
	if a, _ := harness.Get("codex"); a != orig {
		t.Fatal("not restored")
	}
	restore = harness.Override(stubNew{})
	restore()
	if _, ok := harness.Get("stub-new"); ok {
		t.Fatal("added adapter not removed on restore")
	}
}

type stubNew struct{ harness.Adapter }

func (stubNew) Name() string { return "stub-new" }
