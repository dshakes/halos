package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/assign"
	"github.com/dshakes/halos/internal/impact"
)

// TestPlanAllRingsAndImpact: without --ring every ring is planned; --diff
// diffs against the policy at a git ref and previews who is affected.
func TestPlanAllRingsAndImpact(t *testing.T) {
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	dir := buildable(t)
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.name", "t"}, {"config", "user.email", "t@t"}, {"add", "."}, {"commit", "-qm", "base"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	code, out, errs := halo(t, "plan", "--policy-dir", dir)
	if code != 0 || !strings.Contains(out, "ring ring0-harness-team") || !strings.Contains(out, "ring ring3-ga") {
		t.Fatalf("plan every ring: exit %d\n%s%s", code, out, errs)
	}

	// Canary 5% -> 15% (cumulative cuts): [500, 1500) moves ring2 -> ring1 and
	// [3000, 4000) ga -> ring2.
	p := filepath.Join(dir, "rings", "ring1-canary.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "percent: 5", "percent: 15", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs = halo(t, "plan", "--policy-dir", dir, "--ring", "ring1-canary", "--diff", "HEAD", "--output", "json")
	if code != 0 {
		t.Fatalf("plan --diff: exit %d\n%s%s", code, out, errs)
	}
	var res struct {
		Changed bool          `json:"changed"`
		Impact  impact.Report `json:"impact"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := 0
	for _, m := range impact.PolicyMembers(1000) { // no org: the sample alone
		if b := assign.Bucket("halos/rings", m.ID); b >= 500 && b < 1500 || b >= 3000 && b < 4000 {
			want++
		}
	}
	if s := res.Impact.ByKind[impact.KindSample]; res.Impact.Source != "policy" || s.Total != 1000 || s.Ring != want || res.Changed {
		t.Fatalf("impact = %+v (want %d ring moves); release changed=%v", res.Impact, want, res.Changed)
	}
	code, out, _ = halo(t, "plan", "--policy-dir", dir, "--ring", "ring1-canary", "--diff", "HEAD")
	if code != 0 || !strings.Contains(out, "Impact vs HEAD (policy-only estimate") || !strings.Contains(out, "no changes vs the --diff base") {
		t.Fatalf("text:\n%s", out)
	}
	if code, _, errs := halo(t, "plan", "--policy-dir", dir, "--diff", "--upload-pack=x"); code == 0 || !strings.Contains(errs, "want a git ref") {
		t.Fatalf("option-like ref accepted: %s", errs)
	}
}

