package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func editFile(t *testing.T, dir, rel, old, nw string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if old == "" {
		b = append(b, nw...)
	} else if s := string(b); !strings.Contains(s, old) {
		t.Fatalf("%s: no %q", rel, old)
	} else {
		b = []byte(strings.Replace(s, old, nw, 1))
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	relA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	relB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	relC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// TestFreezeCheckCI: the base branch's windows apply (a PR cannot delete its
// own freeze), a rollback is recognised from the diff in pull_request and
// merge_group events alike, and a branch name proves nothing.
func TestFreezeCheckCI(t *testing.T) {
	now := time.Now().UTC()
	dir := governed(t, "governance:\n  freezes:\n    - name: incident-review\n      reason: postmortem in progress\n      start: \""+
		now.Add(-time.Hour).Format(time.RFC3339)+"\"\n      end: \""+now.Add(2*time.Hour).Format(time.RFC3339)+"\"\n")
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"config", "user.name", "t"}, {"config", "user.email", "t@t"}, {"add", "."}, {"commit", "-qm", "base"}} {
		gitIn(t, dir, a...)
	}
	ring := "rings/ring1-canary.yaml"
	editFile(t, dir, ring, "", "release: "+relA+"\n")
	gitIn(t, dir, "commit", "-qam", "ring1 at A")
	editFile(t, dir, ring, relA, relB)
	gitIn(t, dir, "commit", "-qam", "ring1 at B")
	gitIn(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
	baseSHA := gitIn(t, dir, "rev-parse", "HEAD")

	events := map[string]string{
		"pull_request": `{"pull_request":{"head":{"ref":"anything"},"base":{"ref":"main","sha":"` + baseSHA + `"}}}`,
		"merge_group":  `{"merge_group":{"head_ref":"refs/heads/gh-readonly-queue/main/pr-7-abc","base_ref":"refs/heads/main","base_sha":"` + baseSHA + `"}}`,
	}
	evDir := t.TempDir()
	for k, v := range events {
		if err := os.WriteFile(filepath.Join(evDir, k+".json"), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name   string
		branch string
		edit   func()
		code   int
		want   string
	}{
		{"rollback: ring back to a published release, rollout aborted, experiment paused", "feature-x", func() {
			editFile(t, dir, ring, relB, relA)
			editFile(t, dir, "rollouts/opus-5-5-upgrade.yaml", "status: active", "status: aborted")
			editFile(t, dir, "experiments/opus-5-5-canary.yaml", "status: running", "status: paused")
		}, 0, "is a rollback"},
		{"pause only", "x", func() { editFile(t, dir, "rollouts/opus-5-5-upgrade.yaml", "status: active", "status: paused") }, 0, "is a rollback"},
		{"ring to a release never published to it", "halos/rollback-x", func() { editFile(t, dir, ring, relB, relC) }, 1, "never published"},
		{"forward experiment edit", "halos/rollback-x", func() {
			editFile(t, dir, "experiments/opus-5-5-canary.yaml", "weight: 5\n", "weight: 50\n")
		}, 1, "changes more than a rollback"},
		{"resume is forward", "x", func() {
			editFile(t, dir, "experiments/opus-5-5-canary.yaml", "status: running", "status: concluded")
		}, 1, "not paused"},
		{"deleting the freeze window does not unfreeze its own PR", "halos/rollback-x", func() {
			editFile(t, dir, "halos.yaml", "name: incident-review", "name: incident-review-x")
			b, _ := os.ReadFile(filepath.Join(dir, "halos.yaml"))
			s := string(b)
			_ = os.WriteFile(filepath.Join(dir, "halos.yaml"), []byte(s[:strings.Index(s, "\ngovernance:")+1]), 0o644)
		}, 1, "incident-review (postmortem in progress)"},
		{"new file", "x", func() { _ = os.WriteFile(filepath.Join(dir, "notes.yaml"), []byte("a: 1\n"), 0o644) }, 1, "is A"},
	}
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	for _, tc := range tests {
		for ev := range events {
			t.Run(tc.name+"/"+ev, func(t *testing.T) {
				gitIn(t, dir, "checkout", "-q", "-B", tc.branch, "main")
				tc.edit()
				gitIn(t, dir, "add", "-A")
				gitIn(t, dir, "commit", "-qm", "pr")
				defer gitIn(t, dir, "checkout", "-q", "main")
				code, out, errs := halo(t, "freeze", "check", "--policy-dir", dir, "--event", filepath.Join(evDir, ev+".json"))
				if code != tc.code || !strings.Contains(out+errs, tc.want) {
					t.Fatalf("exit %d, want %d and %q\n%s%s", code, tc.code, tc.want, out, errs)
				}
			})
		}
	}
	t.Run("forward change with --base", func(t *testing.T) {
		gitIn(t, dir, "checkout", "-q", "-B", "fwd", "main")
		editFile(t, dir, "experiments/opus-5-5-canary.yaml", "weight: 5\n", "weight: 50\n")
		gitIn(t, dir, "commit", "-qam", "fwd")
		defer gitIn(t, dir, "checkout", "-q", "main")
		if code, out, errs := halo(t, "freeze", "check", "--policy-dir", dir, "--base", "origin/main"); code != 1 || !strings.Contains(errs, "incident-review") {
			t.Fatalf("exit %d\n%s%s", code, out, errs)
		}
	})
	t.Run("--branch is refused", func(t *testing.T) {
		if code, out, errs := halo(t, "freeze", "check", "--policy-dir", dir, "--branch", "halos/rollback-x"); code != 1 || !strings.Contains(errs, "no longer trusted") {
			t.Fatalf("exit %d\n%s%s", code, out, errs)
		}
	})
	t.Run("bad event", func(t *testing.T) {
		p := filepath.Join(evDir, "push.json")
		_ = os.WriteFile(p, []byte(`{"ref":"refs/heads/main"}`), 0o644)
		if code, out, errs := halo(t, "freeze", "check", "--policy-dir", dir, "--event", p); code != 1 || !strings.Contains(errs, "no pull_request or merge_group") {
			t.Fatalf("exit %d\n%s%s", code, out, errs)
		}
	})
}
