package main

import (
	"strings"
	"testing"
)

func TestMissingPolicyIsActionable(t *testing.T) {
	_, _, stderr := halo(t, "validate", "--policy-dir", t.TempDir())
	for _, want := range []string{"no halos.yaml in", "halo init", "--policy-dir"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q missing %q", stderr, want)
		}
	}
}

func TestMissingRingListsPolicyRings(t *testing.T) {
	const ex = "../../examples/acme-corp"
	tests := []struct {
		name string
		args []string
	}{
		{"plan", []string{"plan", "--policy-dir", ex}},
		{"release build", []string{"release", "build", "--policy-dir", ex}},
		{"render", []string{"render", "--policy-dir", ex}},
		{"rollback", []string{"rollback", "--to", "1.0.0", "--policy-dir", ex}},
		{"refresh", []string{"release", "refresh", "--policy-dir", ex}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := halo(t, tt.args...)
			if code == 0 {
				t.Fatal("expected failure")
			}
			if !strings.Contains(stderr, "--ring is required") || !strings.Contains(stderr, "ring3-ga") {
				t.Errorf("stderr %q should say --ring is required and list policy rings", stderr)
			}
		})
	}
}

func TestRollbackMissingRingWithoutPolicyStillErrors(t *testing.T) {
	code, _, stderr := halo(t, "rollback", "--to", "1.0.0", "--policy-dir", t.TempDir())
	if code == 0 || !strings.Contains(stderr, "--ring is required") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

// Every visible top-level command appears under a help group (help and
// completion are cobra's own and stay under Additional Commands).
func TestEveryCommandIsGrouped(t *testing.T) {
	for _, c := range newRoot(&strings.Builder{}, &strings.Builder{}).Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		if c.GroupID == "" {
			t.Errorf("command %q has no help group; add it to helpGroups", c.Name())
		}
	}
}
