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
	if err := VerifyPrivate(p); err != nil || string(b) != "bb" { // overwrite keeps it private
		t.Fatalf("got %q: %v", b, err)
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

func TestRestrictToOwner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivate(p); err == nil {
		t.Fatal("a default-permission file passed VerifyPrivate")
	}
	if err := os.Chmod(p, 0o600); err != nil { // unix: this alone is private
		t.Fatal(err)
	}
	if err := RestrictToOwner(p); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivate(p); err != nil {
		t.Fatal(err)
	}
	if err := RestrictToOwner(filepath.Join(t.TempDir(), "missing")); runtime.GOOS == "windows" && err == nil {
		t.Error("restricting a missing file must fail")
	}
}
