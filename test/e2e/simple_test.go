//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/policy"
)

// TestSimpleMode: `halo init` (one halos.yaml) -> validate -> publish the GA
// ring to a real registry -> `halo upgrade start` builds and publishes the
// candidate itself (no ring pointer moves) -> `halo rollout plan` shows the
// preset's steps; then eject and the policy is unchanged.
func TestSimpleMode(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	must(t, nil, "halo", "init", pol, "--org", "acme", "--tools", "claude-code@"+pin)
	if entries, _ := os.ReadDir(pol); len(entries) != 1 {
		t.Fatalf("simple init wrote %d entries, want only halos.yaml", len(entries))
	}
	must(t, nil, "halo", "validate", pol)

	keys := filepath.Join(dir, "keys")
	must(t, nil, "halo", "keys", "generate", "--out", keys)
	repo := repoName(t)
	reg := []string{"--registry", repo, "--plain-http", "--key", filepath.Join(keys, "halo.key")}
	var pub struct{ Digest string }
	r := must(t, nil, "halo", append([]string{"release", "publish", pol, "--ring", "ring3-ga", "--release-version", "1.0.0", "--no-artifacts", "--output", "json"}, reg...)...)
	if err := json.Unmarshal([]byte(r.stdout), &pub); err != nil || !strings.HasPrefix(pub.Digest, "sha256:") {
		t.Fatalf("publish: %s", r)
	}

	dry := must(t, nil, "halo", append([]string{"upgrade", "start", "claude-code", "2.1.300", "--policy-dir", pol, "--no-artifacts", "--dry-run"}, reg...)...)
	if !strings.Contains(dry.stdout, "would create") || !strings.Contains(dry.stdout, "+kind: Rollout") {
		t.Fatalf("dry run: %s", dry)
	}
	if _, err := os.Stat(filepath.Join(pol, "rollouts")); err == nil {
		t.Fatal("--dry-run wrote files")
	}
	up := must(t, nil, "halo", append([]string{"upgrade", "start", "claude-code", "2.1.300", "--policy-dir", pol, "--no-artifacts"}, reg...)...)
	for _, want := range []string{"create " + filepath.Join(pol, "rollouts", "claude-code-2.1.300.yaml"), "no ring pointer moved", "published channel ring1-canary.x-claude-code-2.1.300-canary.next"} {
		if !strings.Contains(up.stdout, want) {
			t.Fatalf("upgrade start lacks %q: %s", want, up)
		}
	}
	must(t, nil, "halo", "validate", pol)
	org, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	ro := org.Rollouts[0]
	if ro.Baseline.Release != pub.Digest || !strings.HasPrefix(ro.Change.Release, "sha256:") || ro.Change.Release == pub.Digest {
		t.Fatalf("rollout digests not filled in: %+v", ro)
	}

	// Nothing reached a ring: GA still serves the baseline, no other ring has a pointer.
	src, err := bundle.Repository(repo, true)
	if err != nil {
		t.Fatal(err)
	}
	v, err := bundle.ParseEd25519Verifier([]byte(readFile(t, filepath.Join(keys, "halo.pub"))))
	if err != nil {
		t.Fatal(err)
	}
	for ring, want := range map[string]string{"ring3-ga": pub.Digest, "ring0-team": "", "ring1-canary": "", "ring2-early": ""} {
		p, found, err := bundle.ReadPointer(ctx, src, ring, v)
		if err != nil || (want == "") == found || found && p.Digest != want {
			t.Fatalf("ring %s pointer: found=%v %+v %v (want %q)", ring, found, p, err, want)
		}
	}
	if _, err := src.Resolve(ctx, "vclaude-code-2.1.300"); err != nil {
		t.Fatalf("candidate release not in the registry: %v", err)
	}

	plan := must(t, nil, "halo", "rollout", "plan", "claude-code-2.1.300", "--policy-dir", pol)
	for _, step := range []string{"ring0-team", "canary-5", "canary-50", "ring2-early", "ring3-ga"} {
		if !strings.Contains(plan.stdout, step) {
			t.Fatalf("plan lacks step %s:\n%s", step, plan.stdout)
		}
	}
	adv := must(t, nil, "halo", "rollout", "advance", "claude-code-2.1.300", "--policy-dir", pol, "--reason", "e2e", "--dry-run")
	if !strings.Contains(adv.stdout, "+release: "+ro.Change.Release) {
		t.Fatalf("first step does not move ring0-team to the candidate:\n%s", adv.stdout)
	}

	before := must(t, nil, "halo", "explain", "--policy-dir", pol, "--output", "json").stdout
	must(t, nil, "halo", "eject", "--policy-dir", pol)
	must(t, nil, "halo", "validate", pol)
	docs := func(s string) string { // sources differ after eject; the document set must not
		var ds []struct{ Kind, Name string }
		if err := json.Unmarshal([]byte(s), &ds); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, d := range ds {
			b.WriteString(d.Kind + "/" + d.Name + "\n")
		}
		return b.String()
	}
	if after := must(t, nil, "halo", "explain", "--policy-dir", pol, "--output", "json").stdout; docs(after) != docs(before) {
		t.Fatalf("eject changed the document set:\n%s\nvs\n%s", docs(before), docs(after))
	}
}
