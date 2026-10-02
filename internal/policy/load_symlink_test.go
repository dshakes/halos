package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadSymlinkedRoot: git-sync serves the repo as <root>/current -> .worktrees/<sha>
// and the Helm chart passes --policy-dir=/policy/current. Load used to walk only
// the symlink itself and returned an org with no rings (found by make uat-k8s).
func TestLoadSymlinkedRoot(t *testing.T) {
	root := t.TempDir()
	wt := filepath.Join(root, ".worktrees", "abc123")
	for p, c := range map[string]string{
		"halos.yaml":      "apiVersion: halos.dev/v1\nkind: Halos\norg: acme\n",
		"rings/ga.yaml":   "apiVersion: halos.dev/v1\nkind: Ring\nname: ga\norder: 1\nprofile: base\nmembership: {default: true}\n",
		"profiles/b.yaml": "apiVersion: halos.dev/v1\nkind: Profile\nname: base\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(wt, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wt, p), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "current")
	if err := os.Symlink(filepath.Join(".worktrees", "abc123"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	org, err := Load(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(org.Rings) != 1 || org.Rings[0].Name != "ga" || org.Profiles["base"] == nil {
		t.Fatalf("symlinked root: rings %v profiles %v", org.Rings, org.Profiles)
	}
}

func TestCheckAPIVersion(t *testing.T) {
	cases := []struct {
		in         string
		deprecated bool
		err        bool
	}{
		{APIVersion, false, false},
		{APIVersionV1Alpha1, true, false},
		{"halos.dev/v2", false, true},
		{"", false, true},
	}
	for _, tc := range cases {
		dep, err := checkAPIVersion(tc.in)
		if dep != tc.deprecated || (err != nil) != tc.err {
			t.Errorf("checkAPIVersion(%q) = %v, %v", tc.in, dep, err)
		}
	}
}

func TestRootAPIVersionRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "halos.yaml"), []byte("apiVersion: halos.dev/v9\nkind: Halos\norg: acme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v", err)
	}
}
