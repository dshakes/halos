package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadSymlinkedRoot: git-sync serves the repo as <root>/current -> .worktrees/<sha>
// and the Helm chart passes --policy-dir=/policy/current. Load used to walk only
// the symlink itself and returned an org with no rings (found by make uat-k8s).
func TestLoadSymlinkedRoot(t *testing.T) {
	root := t.TempDir()
	wt := filepath.Join(root, ".worktrees", "abc123")
	for p, c := range map[string]string{
		"halos.yaml":      "apiVersion: halos.dev/v1alpha1\nkind: Halos\norg: acme\n",
		"rings/ga.yaml":   "apiVersion: halos.dev/v1alpha1\nkind: Ring\nname: ga\norder: 1\nprofile: base\nmembership: {default: true}\n",
		"profiles/b.yaml": "apiVersion: halos.dev/v1alpha1\nkind: Profile\nname: base\n",
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
