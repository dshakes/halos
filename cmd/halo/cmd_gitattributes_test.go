package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/supplychain"
)

func TestInitWritesGitAttributes(t *testing.T) {
	for _, tc := range []struct {
		name, existing, want string
	}{
		{"new", "", "artifacts/** -text\n"},
		{"append", "*.sh text eol=lf", "*.sh text eol=lf\n# Artifact digests"},
		{"present", "artifacts/** -text\n", "artifacts/** -text\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ga := filepath.Join(dir, ".gitattributes")
			if tc.existing != "" {
				if err := os.WriteFile(ga, []byte(tc.existing), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if code, out, errs := halo(t, "init", dir, "--org", "acme"); code != 0 {
				t.Fatalf("init exit %d: %s%s", code, out, errs)
			}
			b, err := os.ReadFile(ga)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), tc.want) || strings.Count(string(b), "artifacts/** -text") != 1 {
				t.Fatalf(".gitattributes = %q, want it to contain %q once", b, tc.want)
			}
		})
	}
}

func TestValidateWarnsOnCRLFArtifact(t *testing.T) {
	dir := copyDir(t, "../../examples/acme-corp")
	f := filepath.Join(dir, "artifacts/agents/security-reviewer.md")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	crlf := strings.ReplaceAll(string(b), "\n", "\r\n")
	if err := os.WriteFile(f, []byte(crlf), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, errs := halo(t, "validate", "--policy-dir", dir)
	if all := out + errs; !strings.Contains(all, "CRLF") || !strings.Contains(all, "security-reviewer.md") {
		t.Fatalf("validate did not warn about the CRLF artifact:\n%s", all)
	}
}

func TestArtifactDigestWarnsOnCRLF(t *testing.T) {
	dir := t.TempDir()
	crlf := []byte("# skill\r\nbody\r\n")
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), crlf, 0o644); err != nil {
		t.Fatal(err)
	}
	want := supplychain.Tree{"SKILL.md": crlf}.Digest()
	code, out, errs := halo(t, "artifact", "digest", dir)
	if code != 0 || strings.TrimSpace(out) != want {
		t.Fatalf("exit %d, stdout %q, want digest %s (unchanged by the warning)", code, out, want)
	}
	if !strings.Contains(errs, "SKILL.md") || !strings.Contains(errs, "-text") {
		t.Fatalf("stderr %q does not name the file and the .gitattributes fix", errs)
	}

	lf := t.TempDir()
	if err := os.WriteFile(filepath.Join(lf, "SKILL.md"), []byte("# skill\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, errs := halo(t, "artifact", "digest", lf); strings.Contains(errs, "CRLF") {
		t.Fatalf("LF-only artifact warned: %q", errs)
	}
}
