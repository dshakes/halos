package server

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// Console status changes and the controller's ProposeStatus share one clone,
// one lock and the controller.GitWriter implementation.
func TestGitPolicyWriterProposeStatus(t *testing.T) {
	repo := portalPolicy(t)
	var gitCalls []string
	op := &recOpener{}
	w := &GitPolicyWriter{RepoDir: repo, ServedDir: t.TempDir(), Base: "trunk", Opener: op, Git: func(_ context.Context, a ...string) (string, error) {
		gitCalls = append(gitCalls, strings.Join(a, " "))
		if a[0] == "rev-parse" {
			return repo, nil
		}
		return "", nil
	}}
	url, err := w.Propose(context.Background(), nil, Request{ID: "r9", Kind: experimentStatusKind, Item: "opus-5-5-canary", Note: "paused"}, "adm")
	if err != nil || url == "" {
		t.Fatal(url, err)
	}
	r := op.req
	if f := string(r.Files["experiments/opus-5-5-canary.yaml"]); !strings.Contains(f, "status: paused") {
		t.Fatalf("files = %v", r.Files)
	}
	if r.Base != "trunk" || !strings.HasPrefix(r.Branch, "halos/status-paused-opus-5-5-canary") || r.Title != "Set experiment opus-5-5-canary to paused" ||
		!strings.Contains(r.Body, "requested by adm") || !strings.Contains(r.Body, "+status: paused") || r.Edit == nil {
		t.Fatalf("req = %+v", r)
	}
	want := []string{"rev-parse --show-toplevel", "fetch origin trunk", "checkout -f -B trunk origin/trunk", "clean -fd", "checkout -f -B trunk origin/trunk", "clean -fd"}
	if !slices.Equal(gitCalls, want) {
		t.Fatalf("git calls: %v", gitCalls)
	}
	// Errors: already in that status (no PR), unknown experiment, overlapping clone.
	op.req.Branch = ""
	for _, tc := range []struct{ exp, status, want string }{
		{"opus-5-5-canary", "running", "already has status"},
		{"nope", "paused", "nope"},
	} {
		if _, err := w.ProposeStatus(context.Background(), tc.exp, tc.status, "t", "b"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s -> %s: %v", tc.exp, tc.status, err)
		}
	}
	if op.req.Branch != "" {
		t.Fatal("failed proposal opened a PR")
	}
	w.ServedDir = repo
	if _, err := w.ProposeStatus(context.Background(), "opus-5-5-canary", "paused", "t", "b"); err == nil || !strings.Contains(err.Error(), "separate clone") {
		t.Fatalf("overlapping clone: %v", err)
	}
}
