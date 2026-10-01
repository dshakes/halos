package promote

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A nil file value deletes it in the commit; everything else is untouched.
func TestCommitOnBranchDeletes(t *testing.T) {
	dir := gitRepo(t)
	branch, _, err := CommitOnBranch(context.Background(), nil, dir, BranchCommit{Branch: "halos/del", Subject: "del",
		Edit: func(read ReadFunc) (map[string][]byte, error) {
			return map[string][]byte{"ring.yaml": nil, "exp.yaml": []byte("kind: Experiment\n")}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", dir, "show", "--name-status", "--format=", branch).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(out)); strings.Join(got, " ") != "A exp.yaml D ring.yaml" {
		t.Fatalf("commit changes = %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "ring.yaml")); err != nil {
		t.Fatalf("checkout touched: %v", err)
	}
	// Deleting a file HEAD does not have fails rather than committing nothing.
	if _, _, err := CommitOnBranch(context.Background(), nil, dir, BranchCommit{Branch: "halos/del2", Subject: "x",
		Edit: func(ReadFunc) (map[string][]byte, error) { return map[string][]byte{"nope.yaml": nil}, nil }}); err == nil {
		t.Fatal("deleting a missing file succeeded")
	}
}
