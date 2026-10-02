package docgen

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const securityModel = "docs/src/content/docs/concepts/security-model.md"

var testRef = regexp.MustCompile("`([\\w./-]+_test\\.go):((?:Test|Fuzz)\\w+)`")

// TestSecurityModelClaimsBound: every row of the security model's "Tests
// binding each claim" table names at least one test, and every named test
// exists in the named file. A renamed or deleted test fails here instead of
// leaving a claim silently unproven.
func TestSecurityModelClaimsBound(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, securityModel))
	if err != nil {
		t.Fatal(err)
	}
	_, sec, ok := strings.Cut(string(b), "\n## Tests binding each claim\n")
	if !ok {
		t.Fatalf("%s has no \"## Tests binding each claim\" section", securityModel)
	}
	sec, _, _ = strings.Cut(sec, "\n## ")
	rows := 0
	for _, line := range strings.Split(sec, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Claim") {
			continue
		}
		rows++
		refs := testRef.FindAllStringSubmatch(line, -1)
		if len(refs) == 0 {
			t.Errorf("claim row names no test: %s", line)
		}
		for _, r := range refs {
			src, err := os.ReadFile(filepath.Join(repoRoot, r[1]))
			if err != nil {
				t.Errorf("%s: %v", r[0], err)
				continue
			}
			if !regexp.MustCompile(`(?m)^func ` + r[2] + `\(`).Match(src) {
				t.Errorf("%s: no func %s in %s", r[0], r[2], r[1])
			}
		}
	}
	if rows < 20 {
		t.Fatalf("only %d claim rows; the table is incomplete", rows)
	}
}
