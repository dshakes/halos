package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDirSigFollowsSymlinkedRoot: an edit inside a symlinked policy dir (git-sync's
// /policy/current layout) must change the reload signature.
func TestDirSigFollowsSymlinkedRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "repo")
	f := filepath.Join(target, "rings", "ga.yaml")
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "current")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	before := dirSig(link)
	if err := os.WriteFile(f, []byte("ab"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(f, later, later); err != nil {
		t.Fatal(err)
	}
	if after := dirSig(link); after == before {
		t.Fatalf("signature unchanged after an edit behind the symlink: %s", after)
	}
}
