package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/promote"
)

// fakeFinder is an opener that can also search the bodies it has opened, like
// promote.ForgeOpener.
type fakeFinder struct {
	bodies []string
	opens  int
}

func (f *fakeFinder) OpenPR(_ context.Context, r promote.PRRequest) (string, error) {
	f.opens++
	f.bodies = append(f.bodies, r.Body)
	return "https://example.com/pr/" + string(rune('0'+f.opens)), nil
}

func (f *fakeFinder) FindPR(_ context.Context, _, marker string) (string, bool, error) {
	for i, b := range f.bodies {
		if strings.Contains(b, marker) {
			return "https://example.com/pr/" + string(rune('1'+i)), true, nil
		}
	}
	return "", false, nil
}

func TestProposeRolloutIsIdempotent(t *testing.T) {
	dir := copyExample(t)
	f := &fakeFinder{}
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true, PROpener: f})
	args := map[string]any{"name": "opus-5-5-upgrade", "reason": "r", "open_pr": true, "dry_run": false, "base": "main"}
	first, err := call(t, cs, "propose_rollout_rollback", args)
	if err != nil || first["pr"] != "https://example.com/pr/1" || f.opens != 1 {
		t.Fatalf("first: %v %v opens=%d", first, err, f.opens)
	}
	if !strings.Contains(f.bodies[0], "<!-- halos:propose=") {
		t.Fatalf("body lacks the marker: %q", f.bodies[0])
	}
	// A different reason is still the same change: same PR, no second open.
	args["reason"] = "asking again"
	second, err := call(t, cs, "propose_rollout_rollback", args)
	if err != nil || second["pr"] != first["pr"] || f.opens != 1 {
		t.Fatalf("second: %v %v opens=%d", second, err, f.opens)
	}
}

func TestReasonOpenerFindsAndDedupes(t *testing.T) {
	f := &fakeFinder{}
	o := reasonOpener{reason: "why", gh: f}
	req := promote.PRRequest{RepoDir: "d", Branch: "halos/promote-x", Title: "Promote x", Body: "b",
		Files: map[string][]byte{"ring.yaml": []byte("a: 1\n")}}
	u1, err := o.OpenPR(context.Background(), req)
	if err != nil || f.opens != 1 {
		t.Fatalf("open: %q %v", u1, err)
	}
	u2, err := o.OpenPR(context.Background(), req)
	if err != nil || u2 != u1 || f.opens != 1 {
		t.Fatalf("second open: %q %v opens=%d", u2, err, f.opens)
	}
	// FindPR delegates.
	if url, ok, err := o.FindPR(context.Background(), "d", proposeMarker(req)); err != nil || !ok || url != u1 {
		t.Fatalf("FindPR: %q %v %v", url, ok, err)
	}
	// Different file content is a different proposal.
	req.Files = map[string][]byte{"ring.yaml": []byte("a: 2\n")}
	if u3, err := o.OpenPR(context.Background(), req); err != nil || u3 == u1 || f.opens != 2 {
		t.Fatalf("changed content: %q %v opens=%d", u3, err, f.opens)
	}
	// An opener that cannot search still opens, and reports nothing found.
	plain := reasonOpener{reason: "why", gh: &fakeOpener{}}
	if _, ok, err := plain.FindPR(context.Background(), "d", "m"); ok || err != nil {
		t.Fatalf("plain FindPR: %v %v", ok, err)
	}
}
