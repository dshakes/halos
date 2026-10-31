package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/promote"
)

// fakeFinder is an opener that can also search the bodies it has opened, like
// promote.ForgeOpener. states[i] is "open", "merged" or "closed".
type fakeFinder struct {
	bodies []string
	states []string
	opens  int
}

func (f *fakeFinder) OpenPR(_ context.Context, r promote.PRRequest) (string, error) {
	f.opens++
	f.bodies = append(f.bodies, r.Body)
	f.states = append(f.states, "open")
	return "https://example.com/pr/" + string(rune('0'+f.opens)), nil
}

func (f *fakeFinder) find(marker string, openOnly bool) (string, bool) {
	for i, b := range f.bodies {
		if strings.Contains(b, marker) && (!openOnly || f.states[i] == "open") {
			return "https://example.com/pr/" + string(rune('1'+i)), true
		}
	}
	return "", false
}

// FindPR is the controller's lookup: any state.
func (f *fakeFinder) FindPR(_ context.Context, _, marker string) (string, bool, error) {
	u, ok := f.find(marker, false)
	return u, ok, nil
}

func (f *fakeFinder) FindOpenPR(_ context.Context, _, marker string) (string, bool, error) {
	u, ok := f.find(marker, true)
	return u, ok, nil
}

// A merged or closed request with the same marker never blocks a new proposal;
// an open one is returned.
func TestOpenIdempotentOnlyDedupesOpen(t *testing.T) {
	req := promote.PRRequest{RepoDir: "d", Branch: "halos/x", Title: "t", Body: "b", Files: map[string][]byte{"f": []byte("1")}}
	for _, tc := range []struct {
		name, state string
		wantOpens   int
		wantSame    bool
	}{
		{"open one returns the existing URL", "open", 1, true},
		{"merged one leads to a new PR", "merged", 2, false},
		{"closed one leads to a new PR", "closed", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFinder{}
			first, err := openIdempotent(context.Background(), f, req)
			if err != nil {
				t.Fatal(err)
			}
			f.states[0] = tc.state
			second, err := openIdempotent(context.Background(), f, req)
			if err != nil || f.opens != tc.wantOpens || (second == first) != tc.wantSame {
				t.Fatalf("second = %q (first %q) err=%v opens=%d", second, first, err, f.opens)
			}
			// The controller-style lookup still sees the merged/closed one.
			if _, ok, _ := f.FindPR(context.Background(), "d", proposeMarker(req)); !ok {
				t.Fatal("FindPR must match any state")
			}
		})
	}
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
	// FindPR and FindOpenPR delegate.
	if url, ok, err := o.FindPR(context.Background(), "d", proposeMarker(req)); err != nil || !ok || url != u1 {
		t.Fatalf("FindPR: %q %v %v", url, ok, err)
	}
	if url, ok, err := o.FindOpenPR(context.Background(), "d", proposeMarker(req)); err != nil || !ok || url != u1 {
		t.Fatalf("FindOpenPR: %q %v %v", url, ok, err)
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
