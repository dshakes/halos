package main

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testFixture is a copy of the example without its rollouts (the simulation is
// the slow part), for the failing-policy cases.
func testFixture(t *testing.T) string {
	t.Helper()
	dir := copyDir(t, example)
	if err := os.RemoveAll(filepath.Join(dir, "rollouts")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTestCommandPassesOnExample(t *testing.T) {
	code, out, errs := halo(t, "test", "--policy-dir", example, "--ring", "ring3-ga")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	for _, want := range []string{"PASS  validate", "PASS  render     ring3-ga", "PASS  release", "PASS  invariants", "PASS  cases", "PASS  rollout", "next steps:", "0 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("FAIL in a passing run:\n%s", out)
	}
	// The positional policy dir still works like everywhere else.
	if code, _, errs := halo(t, "test", example, "--ring", "ring3-ga"); code != 0 {
		t.Fatalf("positional dir: exit %d %s", code, errs)
	}
}

func TestTestCommandOutputFormats(t *testing.T) {
	for _, args := range [][]string{
		{"test", "--policy-dir", example, "--ring", "ring3-ga", "-o", "json"},
		{"test", "--policy-dir", example, "--ring", "ring3-ga", "--output", "json"},
		{"--output", "json", "test", "--policy-dir", example, "--ring", "ring3-ga"},
	} {
		code, out, errs := halo(t, args...)
		var rep struct {
			OK        bool
			Passed    int
			NextSteps []string `json:"next_steps"`
			Results   []struct{ Suite, Status string }
		}
		if err := json.Unmarshal([]byte(out), &rep); code != 0 || err != nil || !rep.OK || rep.Passed == 0 || len(rep.NextSteps) == 0 || len(rep.Results) == 0 {
			t.Fatalf("%v: exit %d, %v\n%s%s", args, code, err, out, errs)
		}
	}
	code, out, errs := halo(t, "test", "--policy-dir", example, "--ring", "ring3-ga", "-o", "junit")
	var ju struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Suites   []struct {
			Name string `xml:"name,attr"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal([]byte(out), &ju); code != 0 || err != nil || ju.Tests < 10 || ju.Failures != 0 || len(ju.Suites) < 5 {
		t.Fatalf("junit: exit %d, %v\n%s%s", code, err, out, errs)
	}
}

// Exit code 2: a check failed. Each fixture fails the check it targets and says why.
func TestTestCommandFailingFixtures(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, dir string)
		args   []string
		stdout []string // in the text output
	}{
		{"bypass token in the policy", func(t *testing.T, d string) {
			mustEdit(t, filepath.Join(d, "profiles", "engineering.yaml"), "extends: base\n", "extends: base\ninstructions: \"use bypassPermissions\"\n")
		}, nil, []string{"FAIL  validate", "permission-bypass", "SKIP  render"}},
		{"invalid policy", func(t *testing.T, d string) {
			mustEdit(t, filepath.Join(d, "rings", "ring3-ga.yaml"), "profile: engineering", "profile: nope")
		}, nil, []string{"FAIL  validate", "nope"}},
		{"policy that does not load", func(t *testing.T, d string) {
			mustEdit(t, filepath.Join(d, "rings", "ring3-ga.yaml"), "order: 3\n", "order: 3\nbogus: 1\n")
		}, nil, []string{"FAIL  validate", "policy does not load", "bogus"}},
		{"bad expectation", func(t *testing.T, d string) {
			mustEdit(t, filepath.Join(d, "tests", "ring-placement.yaml"), "ring: ring0-harness-team", "ring: ring3-ga")
		}, nil, []string{"FAIL  cases      ring-placement/ai-platform group is ring0", `ring: want "ring3-ga", got "ring0-harness-team"`, "halo whoami"}},
		{"bad setting expectation", func(t *testing.T, d string) {
			mustEdit(t, filepath.Join(d, "tests", "rendered-settings.yaml"), "sandbox.enabled: true", "sandbox.enabled: false")
		}, nil, []string{"FAIL  cases", "sandbox.enabled (linux): want false, got true"}},
		{"invalid test file", func(t *testing.T, d string) {
			mustWrite(t, filepath.Join(d, "tests", "broken.yaml"), "apiVersion: halos.dev/v1\nkind: PolicyTest\nname: broken\ncases:\n  - name: c\n    identity: {user: u}\n    expct: {}\n")
		}, nil, []string{"FAIL  cases      tests/broken.yaml", "invalid test file", "field expct not found"}},
		{"warnings under --strict", func(*testing.T, string) {}, []string{"--strict"}, []string{"FAIL  render     ring3-ga", "adapter warnings (--strict)"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testFixture(t)
			tt.setup(t, dir)
			args := append([]string{"test", "--policy-dir", dir, "--ring", "ring3-ga"}, tt.args...)
			code, out, errs := halo(t, args...)
			if code != exitValidation {
				t.Fatalf("exit %d, want %d\n%s%s", code, exitValidation, out, errs)
			}
			for _, want := range tt.stdout {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			if !strings.Contains(errs, "checks failed") {
				t.Errorf("stderr lacks the summary: %q", errs)
			}
			if tt.name != "bad expectation" { // the machine formats are checked once
				return
			}
			// They carry the same failure and the same exit code.
			code, out, _ = halo(t, append(args, "-o", "json")...)
			var rep struct{ OK bool }
			if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValidation || rep.OK {
				t.Fatalf("json: exit %d ok=%v %v\n%s", code, rep.OK, err, out)
			}
			code, out, _ = halo(t, append(args, "-o", "junit")...)
			if code != exitValidation || !strings.Contains(out, "<failure") {
				t.Fatalf("junit: exit %d\n%s", code, out)
			}
		})
	}
}

// Exit code 1: the run could not happen.
func TestTestCommandUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no policy repo", []string{"test", "--policy-dir", "@empty"}, "no halos.yaml"},
		{"unknown ring", []string{"test", "--policy-dir", example, "--ring", "nope"}, "unknown ring"},
		{"bad output", []string{"test", "--policy-dir", example, "-o", "xml"}, "text, json or junit"},
		{"bad max-impact", []string{"test", "--policy-dir", example, "--max-impact", "150"}, "between 0 and 100"},
		{"option-like ref", []string{"test", "--policy-dir", "@fixture", "--against", "--upload-pack=x"}, "git ref"},
		{"unknown ref", []string{"test", "--policy-dir", "@fixture", "--against", "no-such-ref"}, "--against no-such-ref"},
	}
	fixture := testFixture(t)
	gitCommit(t, fixture)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string(nil), tt.args...)
			for i, a := range args {
				switch a {
				case "@empty":
					args[i] = t.TempDir()
				case "@fixture":
					args[i] = fixture
				}
			}
			code, out, errs := halo(t, args...)
			if code != exitError || !strings.Contains(errs, tt.want) {
				t.Fatalf("exit %d, want %d with %q\n%s%s", code, exitError, tt.want, out, errs)
			}
		})
	}
}

func gitCommit(t *testing.T, dir string) {
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

func TestTestCommandAgainst(t *testing.T) {
	dir := testFixture(t)
	gitCommit(t, dir)
	args := []string{"test", "--policy-dir", dir, "--ring", "ring3-ga", "--against", "HEAD"}
	if code, out, errs := halo(t, args...); code != 0 || !strings.Contains(out, "PASS  impact     blast radius vs HEAD") {
		t.Fatalf("unchanged: exit %d\n%s%s", code, out, errs)
	}
	// Moving the default ring to another profile changes everyone in it.
	mustEdit(t, filepath.Join(dir, "rings", "ring3-ga.yaml"), "profile: engineering", "profile: engineering-next")
	code, out, errs := halo(t, args...)
	if code != exitValidation || !strings.Contains(out, "FAIL  impact") || !strings.Contains(out, "high blast radius") || !strings.Contains(out, "halo plan") {
		t.Fatalf("high blast radius: exit %d\n%s%s", code, out, errs)
	}
	// A reviewed change passes once the threshold says so (the cases that pin ring3-ga still fail, so drop them).
	if err := os.RemoveAll(filepath.Join(dir, "tests")); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := halo(t, append(args, "--max-impact", "100")...); code != 0 {
		t.Fatalf("--max-impact 100: exit %d\n%s%s", code, out, errs)
	}
}

func mustEdit(t *testing.T, p, old, new string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s lacks %q", p, old)
	}
	mustWrite(t, p, strings.Replace(string(b), old, new, 1))
}
