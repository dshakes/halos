package policytest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

const exampleDir = "../../examples/acme-corp"

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// slim is a copy of the example without its rollouts and policy tests: the
// simulation and the case builds are the slow part, and most fixtures are
// about something else.
func slim(t *testing.T) string {
	t.Helper()
	d := copyDir(t, exampleDir)
	for _, sub := range []string{"rollouts", policy.TestsDir} {
		if err := os.RemoveAll(filepath.Join(d, sub)); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// edit replaces the first occurrence of old in dir/rel; it fails the test if
// old is not there, so a fixture cannot silently stop mutating anything.
func edit(t *testing.T, dir, rel, old, new string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s does not contain %q", rel, old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, new, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, opt Options) *Report {
	t.Helper()
	if opt.MaxImpact == 0 {
		opt.MaxImpact = DefaultMaxImpact
	}
	rep, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// find returns the result of suite named name, failing the test if absent.
func find(t *testing.T, rep *Report, suite, name string) Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.Suite == suite && r.Name == name {
			return r
		}
	}
	t.Fatalf("no %s/%s result in %+v", suite, name, rep.Results)
	return Result{}
}

func wantFail(t *testing.T, rep *Report, suite, name, substr string) Result {
	t.Helper()
	r := find(t, rep, suite, name)
	all := r.Message + "\n" + strings.Join(r.Details, "\n")
	if r.Status != Fail || !strings.Contains(all, substr) {
		t.Fatalf("%s/%s: want a failure containing %q, got %s: %s", suite, name, substr, r.Status, all)
	}
	if rep.OK || rep.Failed == 0 {
		t.Fatalf("report is OK despite failed %s/%s", suite, name)
	}
	return r
}

func TestExamplePasses(t *testing.T) {
	rep := run(t, Options{Dir: exampleDir})
	if !rep.OK {
		for _, r := range rep.Results {
			if r.Status != Pass {
				t.Errorf("%s/%s %s: %s %v", r.Suite, r.Name, r.Status, r.Message, r.Details)
			}
		}
		t.FailNow()
	}
	count := map[string]int{}
	for _, r := range rep.Results {
		count[r.Suite]++
	}
	// 4 rings, 7 example cases, 3 rollouts.
	for suite, min := range map[string]int{SuiteValidate: 1, SuiteRender: 4, SuiteRelease: 4, SuiteInvariants: 4, SuiteCases: 7, SuiteRollout: 3} {
		if count[suite] < min {
			t.Errorf("suite %s ran %d checks, want at least %d", suite, count[suite], min)
		}
	}
	if count[SuiteImpact] != 0 {
		t.Error("impact ran without --against")
	}
	if rep.Warnings == 0 {
		t.Error("adapter warnings are not surfaced")
	}
	if len(rep.NextSteps) == 0 {
		t.Error("no next_steps")
	}
	// The render check names the harness x OS matrix it covered.
	if r := find(t, rep, SuiteRender, "ring3-ga"); !strings.Contains(r.Message, "x 3 OS") || len(r.Warnings) == 0 {
		t.Errorf("render result: %+v", r)
	}
}

func TestRingFlagLimitsRingChecks(t *testing.T) {
	rep := run(t, Options{Dir: slim(t), Ring: "ring1-canary"})
	for _, r := range rep.Results {
		if (r.Suite == SuiteRender || r.Suite == SuiteRelease || r.Suite == SuiteInvariants) && r.Name != "ring1-canary" {
			t.Errorf("--ring ring1-canary also ran %s/%s", r.Suite, r.Name)
		}
	}
	if !rep.OK {
		t.Fatalf("not OK: %+v", rep.Results)
	}
	if _, err := Run(context.Background(), Options{Dir: exampleDir, Ring: "nope", MaxImpact: 25}); err == nil || !strings.Contains(err.Error(), "ring3-ga") {
		t.Fatalf("unknown ring: %v", err)
	}
}

func TestRunErrors(t *testing.T) {
	if _, err := Run(context.Background(), Options{Dir: t.TempDir(), MaxImpact: 25}); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("empty dir: want ErrNoPolicy, got %v", err)
	}
	for _, v := range []float64{-1, 101} {
		if _, err := Run(context.Background(), Options{Dir: exampleDir, MaxImpact: v}); err == nil {
			t.Fatalf("max impact %v accepted", v)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Options{Dir: exampleDir, MaxImpact: 25}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
}

// Check 1: validate.
func TestValidateFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		want   string
	}{
		{"ring names a missing profile", func(t *testing.T, d string) {
			edit(t, d, "rings/ring3-ga.yaml", "profile: engineering", "profile: nope")
		}, "nope"},
		{"bypass token in a profile", func(t *testing.T, d string) {
			edit(t, d, "profiles/engineering.yaml", "extends: base\n", "extends: base\ninstructions: \"launch with --dangerously-skip-permissions\"\n")
		}, "permission-bypass"},
		{"unknown field", func(t *testing.T, d string) {
			edit(t, d, "rings/ring3-ga.yaml", "order: 3\n", "order: 3\nbogus: 1\n")
		}, "bogus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := copyDir(t, exampleDir)
			tt.mutate(t, d)
			rep := run(t, Options{Dir: d})
			wantFail(t, rep, SuiteValidate, "policy", "")
			r := find(t, rep, SuiteValidate, "policy")
			if !strings.Contains(strings.Join(r.Details, "\n"), tt.want) {
				t.Fatalf("details lack %q: %v", tt.want, r.Details)
			}
			// Nothing else runs on a policy that does not validate.
			for _, s := range []string{SuiteRender, SuiteRelease, SuiteInvariants, SuiteRollout} {
				if x := find(t, rep, s, "all"); x.Status != Skip {
					t.Errorf("%s ran on an invalid policy: %+v", s, x)
				}
			}
		})
	}
}

func TestStrictFailsOnWarnings(t *testing.T) {
	d0 := slim(t)
	loose := run(t, Options{Dir: d0, Ring: "ring3-ga"})
	if !loose.OK || loose.Warnings == 0 {
		t.Fatalf("baseline: ok=%v warnings=%d", loose.OK, loose.Warnings)
	}
	rep := run(t, Options{Dir: d0, Ring: "ring3-ga", Strict: true})
	wantFail(t, rep, SuiteRender, "ring3-ga", "--strict")
	// A policy validation warning fails the validate check under --strict only.
	d := slim(t)
	edit(t, d, "toggles/format-hook.yaml", `expires: "2026-11-30"`, `expires: "2020-01-01"`)
	if v := find(t, run(t, Options{Dir: d, Ring: "ring3-ga"}), SuiteValidate, "policy"); v.Status != Pass || len(v.Warnings) == 0 {
		t.Fatalf("stale toggle should warn, not fail: %+v", v)
	}
	wantFail(t, run(t, Options{Dir: d, Ring: "ring3-ga", Strict: true}), SuiteValidate, "policy", "--strict")
}

// bypassAdapter wraps the real claude-code adapter and adds a rendered file.
type wrapAdapter struct {
	harness.Adapter
	extra func() []harness.File
}

func (w wrapAdapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	files, warns, err := w.Adapter.Render(p, c)
	return append(files, w.extra()...), warns, err
}

func override(t *testing.T, extra func() []harness.File) {
	t.Helper()
	real, ok := harness.Get("claude-code")
	if !ok {
		t.Fatal("claude-code adapter not registered")
	}
	t.Cleanup(harness.Override(wrapAdapter{real, extra}))
}

// Check 2: an adapter that renders a bypass setting fails the render, whatever
// the policy says; the release and invariant checks then have nothing to check.
func TestRenderFailsOnBypassToken(t *testing.T) {
	override(t, func() []harness.File {
		return []harness.File{{Path: "/etc/claude-code/extra.json", Mode: 0o644, Data: []byte(`{"permissions":{"defaultMode":"bypassPermissions"}}`)}}
	})
	rep := run(t, Options{Dir: slim(t), Ring: "ring3-ga"})
	wantFail(t, rep, SuiteRender, "ring3-ga", "bypassPermissions")
	wantFail(t, rep, SuiteRender, "ring3-ga", "invariant")
	for _, s := range []string{SuiteRelease, SuiteInvariants} {
		if r := find(t, rep, s, "ring3-ga"); r.Status != Skip {
			t.Errorf("%s after a failed render: %+v", s, r)
		}
	}
}

// Check 3: a build that differs from run to run is not content-addressed.
func TestReleaseFailsWhenBuildIsNotReproducible(t *testing.T) {
	n := 0
	override(t, func() []harness.File {
		n++
		return []harness.File{{Path: "/etc/claude-code/stamp.json", Mode: 0o644, Data: []byte(fmt.Sprintf(`{"build": %d}`, n))}}
	})
	rep := run(t, Options{Dir: slim(t), Ring: "ring3-ga"})
	wantFail(t, rep, SuiteRelease, "ring3-ga", "not reproducible")
	if r := find(t, rep, SuiteRender, "ring3-ga"); r.Status != Pass {
		t.Errorf("render should still pass: %+v", r)
	}
}

func TestReleaseConsistencyDetectsMismatchedManifest(t *testing.T) {
	org, err := policy.Load(exampleDir)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{opt: Options{Version: DefaultVersion}, org: org, tmp: t.TempDir()}
	rel, _, err := release.BuildRing(org, "ring3-ga", release.Options{Version: DefaultVersion, Org: org.Name})
	if err != nil {
		t.Fatal(err)
	}
	if errs := r.releaseConsistency(context.Background(), org.Rings[len(org.Rings)-1], rel); len(errs) != 0 {
		t.Fatalf("consistent release reported %v", errs)
	}
	// The same bundle claimed for another ring, org and version.
	other := &policy.Ring{Meta: policy.Meta{Name: "ring1-canary"}, Profile: "engineering-next"}
	r.opt.Version = "9.9.9"
	r.org = &policy.Org{Name: "someone-else", Profiles: org.Profiles}
	errs := strings.Join(r.releaseConsistency(context.Background(), other, rel), "\n")
	for _, want := range []string{`manifest ring is "ring3-ga"`, `profile is "engineering"`, `org is "acme-corp"`, `version is "0.0.0-dev"`} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing %q in:\n%s", want, errs)
		}
	}
}

// Check 4: ScanBypass reaches what the per-file release check does not.
func TestScanBypass(t *testing.T) {
	org, err := policy.Load(exampleDir)
	if err != nil {
		t.Fatal(err)
	}
	rel, _, err := release.BuildRing(org, "ring3-ga", release.Options{Version: DefaultVersion, Org: org.Name})
	if err != nil {
		t.Fatal(err)
	}
	if hits := ScanBypass(rel); len(hits) != 0 {
		t.Fatalf("clean release has hits: %v", hits)
	}
	// A blob the manifest names (a cloud agent file) and one it does not.
	rel.Blobs["aaaa"] = []byte("run codex with --dangerously-bypass-approvals-and-sandbox")
	rel.Manifest.CloudAgents = append(rel.Manifest.CloudAgents, release.CloudAgentFile{Vendor: "acme", Path: ".github/agent.md", SHA256: "bbbb"})
	rel.Blobs["bbbb"] = []byte(`{"sandbox": "danger-full-access"}`)
	hits := strings.Join(ScanBypass(rel), "\n")
	for _, want := range []string{"blob sha256:aaaa", "dangerously-bypass-approvals-and-sandbox", "cloud agent acme .github/agent.md", "danger-full-access"} {
		if !strings.Contains(hits, want) {
			t.Errorf("missing %q in:\n%s", want, hits)
		}
	}
	// The manifest itself, e.g. an experiment or ring name smuggling a flag.
	rel.Manifest.Ring = "r--yolo"
	if hits := ScanBypass(rel); !strings.Contains(strings.Join(hits, "\n"), "manifest") {
		t.Errorf("manifest not scanned: %v", hits)
	}
}

// Check 5 needs git: base commit, then a change to the default ring.
func gitRepo(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.autocrlf=true'")
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.name", "t"}, {"config", "user.email", "t@t"}, {"config", "commit.gpgsign", "false"}, {"add", "."}, {"commit", "-qm", "base"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestImpactBlastRadius(t *testing.T) {
	d := slim(t)
	gitRepo(t, d)

	// No change: nobody moves.
	rep := run(t, Options{Dir: d, Against: "HEAD", Ring: "ring3-ga"})
	if r := find(t, rep, SuiteImpact, "blast radius vs HEAD"); r.Status != Pass || rep.Impact == nil || rep.Impact.Source != "policy" {
		t.Fatalf("unchanged policy: %+v / %+v", r, rep.Impact)
	}

	// ring3-ga is the default ring: a new deny rule in its profile changes the
	// effective settings of every user in it.
	edit(t, d, "rings/ring3-ga.yaml", "profile: engineering", "profile: engineering-next")
	rep = run(t, Options{Dir: d, Against: "HEAD", Ring: "ring3-ga"})
	r := wantFail(t, rep, SuiteImpact, "blast radius vs HEAD", "high blast radius")
	if !strings.Contains(r.Message, "ring3-ga") || !strings.Contains(strings.Join(r.Details, "\n"), "all users") {
		t.Fatalf("message does not name the ring: %+v", r)
	}
	// The threshold is the knob: a reviewed change passes with a higher one.
	rep = run(t, Options{Dir: d, Against: "HEAD", Ring: "ring3-ga", MaxImpact: 100})
	if r := find(t, rep, SuiteImpact, "blast radius vs HEAD"); r.Status != Pass {
		t.Fatalf("--max-impact 100 still fails: %+v", r)
	}
	if rep.Impact.ByKind["sample"].Settings == 0 {
		t.Fatalf("impact report empty: %+v", rep.Impact)
	}

	// An unreadable ref is an error, not a failed check.
	if _, err := Run(context.Background(), Options{Dir: d, Against: "no-such-ref", MaxImpact: 25}); err == nil {
		t.Fatal("bad --against ref accepted")
	}
	if _, err := Run(context.Background(), Options{Dir: d, Against: "--upload-pack=x", MaxImpact: 25}); err == nil {
		t.Fatal("option-like --against ref accepted")
	}
}

// Check 7: a rollout whose gate cannot pass on healthy evidence is a failure.
func TestRolloutThatCannotComplete(t *testing.T) {
	d := slim(t)
	for _, f := range []string{"claude-code-2.1.300", "opus-5-5-upgrade"} {
		write(t, d, "rollouts/"+f+".yaml", mustRead(t, filepath.Join(exampleDir, "rollouts", f+".yaml")))
	}
	edit(t, d, "rollouts/claude-code-2.1.300.yaml", "minPass1: 0.70", "minPass1: 0.9999")
	rep := run(t, Options{Dir: d, Ring: "ring3-ga"})
	wantFail(t, rep, SuiteRollout, "claude-code-2.1.300", "not complete")
	if r := find(t, rep, SuiteRollout, "opus-5-5-upgrade"); r.Status != Pass {
		t.Errorf("the other rollouts still pass: %+v", r)
	}
}

// Remote artifacts need the network: the rings that use them are skipped, not failed.
func TestRemoteArtifactsSkipOffline(t *testing.T) {
	org, err := policy.Load(exampleDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := remoteArtifacts(org); len(got) != 0 {
		t.Fatalf("example has unresolved remote artifacts: %v", got)
	}
	org.SupplyChain = &policy.SupplyChain{Artifacts: []policy.Artifact{{Name: "ext", Git: &policy.GitSource{URL: "https://example.invalid/x.git", Commit: strings.Repeat("a", 40)}}}}
	if got := remoteArtifacts(org); len(got) != 1 || got[0] != "ext" {
		t.Fatalf("remoteArtifacts = %v", got)
	}
	org.ArtifactContent = map[string]*policy.ArtifactContent{"ext": {Files: map[string][]byte{"a": nil}}}
	if got := remoteArtifacts(org); len(got) != 0 {
		t.Fatalf("resolved artifact still listed: %v", got)
	}
}
