package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The digest is sha256 of what `find . -type f | sort | xargs sha256sum`
// prints (paths without the ./ prefix), so it reproduces with stock tools.
func TestDigestIsSortedSha256sumListing(t *testing.T) {
	tr := Tree{"b/x.sh": []byte("echo hi\n"), "SKILL.md": []byte("# s\n"), "a.txt": []byte("")}
	h := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	listing := h("# s\n") + "  SKILL.md\n" + h("") + "  a.txt\n" + h("echo hi\n") + "  b/x.sh\n"
	if got := string(Listing(tr.Sums())); got != listing {
		t.Fatalf("listing:\n%s\nwant:\n%s", got, listing)
	}
	if want := "sha256:" + h(listing); tr.Digest() != want {
		t.Fatalf("digest %s, want %s", tr.Digest(), want)
	}
	tr["a.txt"] = []byte(" ")
	if tr.Digest() == "sha256:"+h(listing) {
		t.Fatal("changing one byte did not change the digest")
	}
}

func TestCheckPath(t *testing.T) {
	for p, ok := range map[string]bool{
		"SKILL.md": true, "hooks/audit.sh": true, "a/b@1+2/c-d_e.txt": true,
		"": false, "/abs": false, "../up": false, "a/../b": false, "a/./b": false,
		"a//b": false, "sp ace": false, "con.": false, `a\b`: false, "a:b": false,
	} {
		if err := CheckPath(p); (err == nil) != ok {
			t.Errorf("CheckPath(%q) = %v, want ok=%v", p, err, ok)
		}
	}
}

func TestTreeCheck(t *testing.T) {
	big := Tree{"a": make([]byte, MaxBytes+1)}
	many := Tree{}
	for i := 0; i <= MaxFiles; i++ {
		many["f"+hex.EncodeToString([]byte{byte(i), byte(i >> 8)})] = nil
	}
	for name, tr := range map[string]Tree{"empty": {}, "too big": big, "too many": many, "bad path": {"../x": nil}} {
		if tr.Check() == nil {
			t.Errorf("%s: Check passed", name)
		}
	}
}

func TestReadPath(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "skill", "SKILL.md"), "# s\n")
	write(t, filepath.Join(d, "skill", "ref", "notes.md"), "n\n")
	write(t, filepath.Join(d, "skill", ".git", "HEAD"), "ref\n")
	tr, err := ReadPath(filepath.Join(d, "skill"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 2 || string(tr["ref/notes.md"]) != "n\n" || tr["SKILL.md"] == nil {
		t.Fatalf("tree = %v (want SKILL.md and ref/notes.md, .git skipped)", tr)
	}
	one, err := ReadPath(filepath.Join(d, "skill", "SKILL.md"))
	if err != nil || len(one) != 1 || one["SKILL.md"] == nil {
		t.Fatalf("single file: %v %v", one, err)
	}
	if _, err := ReadPath(filepath.Join(d, "missing")); err == nil {
		t.Fatal("missing path read")
	}
	if err := os.MkdirAll(filepath.Join(d, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPath(filepath.Join(d, "emptydir")); err == nil {
		t.Fatal("empty directory accepted")
	}
	if err := os.Symlink(filepath.Join(d, "skill", "SKILL.md"), filepath.Join(d, "skill", "link.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ReadPath(filepath.Join(d, "skill")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink in artifact: err = %v", err)
	}
}
