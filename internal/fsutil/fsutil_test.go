package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteAtomic(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("bb"), ExistingPerm(p, 0o644)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	st, _ := os.Stat(p)
	// Windows has no POSIX mode bits (Perm() is always 0666); access is ACL-based.
	if string(b) != "bb" || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("got %q %v", b, st.Mode())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
	if ExistingPerm(filepath.Join(dir, "none"), 0o640) != 0o640 {
		t.Error("default perm")
	}
	if err := WriteAtomic(filepath.Join(dir, "missing", "f"), nil, 0o600); err == nil {
		t.Error("want error for missing dir")
	}
}
