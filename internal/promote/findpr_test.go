package promote

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGHOpenerFindPR(t *testing.T) {
	const marker = "<!-- halos-intent: abc123 -->"
	var args []string
	g := GHOpener{Exec: func(_ context.Context, _, name string, a ...string) ([]byte, error) {
		args = append([]string{name}, a...)
		return []byte(`[{"url":"https://gh/pr/1","body":"mentions abc123 in prose"},{"url":"https://gh/pr/2","body":"x\n\n` + marker + `"}]`), nil
	}}
	url, ok, err := g.FindPR(context.Background(), "/repo", marker)
	if err != nil || !ok || url != "https://gh/pr/2" {
		t.Fatalf("FindPR = %q %v %v (the marker must match exactly, not the search hit)", url, ok, err)
	}
	if got := strings.Join(args, " "); !strings.Contains(got, "pr list --state all --search halos-intent: abc123 in:body") {
		t.Fatalf("gh args: %s", got)
	}
	g.Exec = func(context.Context, string, string, ...string) ([]byte, error) { return []byte(`[]`), nil }
	if _, ok, err := g.FindPR(context.Background(), "/repo", marker); ok || err != nil {
		t.Fatalf("no PR: %v %v", ok, err)
	}
	g.Exec = func(context.Context, string, string, ...string) ([]byte, error) {
		return nil, errors.New("gh: rate limited")
	}
	if _, _, err := g.FindPR(context.Background(), "/repo", marker); err == nil {
		t.Fatal("gh error swallowed")
	}
}
