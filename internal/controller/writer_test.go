package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/promote"
)

type recOpener struct{ reqs []promote.PRRequest }

func (o *recOpener) OpenPR(_ context.Context, r promote.PRRequest) (string, error) {
	o.reqs = append(o.reqs, r)
	return "https://gh/pr/7", nil
}

const expYAML = `# keep this comment
apiVersion: halos.dev/v1alpha1
kind: Experiment
name: exp-a
status: running # inline
`

func TestGitWriterProposeStatus(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "policy", "experiments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "policy", "experiments", "a.yaml"), []byte(expYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	o := &recOpener{}
	w := &GitWriter{RepoDir: repo, Subdir: "policy", Base: "main", Opener: o}
	url, err := w.ProposeStatus(context.Background(), "exp-a", "paused", "Pause exp-a", "evidence")
	if err != nil || url != "https://gh/pr/7" {
		t.Fatalf("url=%q err=%v", url, err)
	}
	r := o.reqs[0]
	got := string(r.Files["experiments/a.yaml"])
	if r.Base != "main" || !strings.HasPrefix(r.Branch, "halos/status-paused-exp-a") || r.Title != "Pause exp-a" ||
		!strings.Contains(got, "status: paused # inline") || !strings.Contains(got, "# keep this comment") {
		t.Fatalf("req = %+v\n%s", r, got)
	}
	if !strings.Contains(r.Body, "evidence") || !strings.Contains(r.Body, "+status: paused") || !strings.Contains(r.Body, "human must review") {
		t.Fatalf("body = %s", r.Body)
	}
	// Edit re-applies to the committed content, not the working tree.
	files, err := r.Edit(func(string) ([]byte, error) {
		return []byte(strings.Replace(expYAML, "# keep this comment", "# committed", 1)), nil
	})
	if err != nil || !strings.Contains(string(files["experiments/a.yaml"]), "# committed") || !strings.Contains(string(files["experiments/a.yaml"]), "status: paused") {
		t.Fatalf("edit: %v %s", err, files["experiments/a.yaml"])
	}

	// Errors: unknown experiment; status already set (empty diff).
	if _, err := w.ProposeStatus(context.Background(), "nope", "paused", "t", "b"); err == nil {
		t.Fatal("unknown experiment accepted")
	}
	if _, err := w.ProposeStatus(context.Background(), "exp-a", "running", "t", "b"); err == nil || !strings.Contains(err.Error(), "already has status") {
		t.Fatalf("no-op status change: %v", err)
	}
	if len(o.reqs) != 1 {
		t.Fatalf("failed proposals opened PRs: %d", len(o.reqs))
	}
}
