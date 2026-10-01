package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExamplesValidate loads every policy repo under examples/ and fails on any
// validation error, so a copy-paste example can never rot.
func TestExamplesValidate(t *testing.T) {
	root := filepath.Join("..", "..", "examples")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n++
		t.Run(e.Name(), func(t *testing.T) {
			org, err := Load(filepath.Join(root, e.Name()))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			for _, is := range org.Validate() {
				if is.Severity == SeverityError {
					t.Errorf("%s", is)
				}
			}
		})
	}
	if n == 0 {
		t.Fatal("no example directories found")
	}
}
