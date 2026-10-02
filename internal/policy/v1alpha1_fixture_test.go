package policy

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// test/ci/policy-v1alpha1 exists only because the release pinned by the CI
// jobs that install a released halo predates halos.dev/v1. It must stay a pure
// apiVersion rewrite of the YAML in examples/acme-corp; see its README.
func TestV1Alpha1FixtureMirrorsExample(t *testing.T) {
	example, fixture := filepath.Join("..", "..", "examples", "acme-corp"), filepath.Join("..", "..", "test", "ci", "policy-v1alpha1")
	v1, v1alpha1 := []byte("apiVersion: "+APIVersion+"\n"), []byte("apiVersion: "+APIVersionV1Alpha1+"\n")
	n := 0
	err := filepath.WalkDir(example, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		rel, _ := filepath.Rel(example, path)
		want, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(filepath.Join(fixture, rel))
		if err != nil {
			t.Errorf("%s: missing from test/ci/policy-v1alpha1 (%v)", rel, err)
			return nil
		}
		if !bytes.Equal(bytes.ReplaceAll(want, v1, v1alpha1), got) {
			t.Errorf("%s: test/ci/policy-v1alpha1 differs from examples/acme-corp beyond apiVersion", rel)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("examples/acme-corp is empty")
	}
}
