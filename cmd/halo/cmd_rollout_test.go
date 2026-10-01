package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/rollout"
)

func TestRolloutCLI(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		want []string // substrings of stdout (or stderr when code != 0)
	}{
		{"list", []string{"rollout", "list"}, 0, []string{"opus-5-5-upgrade", "traffic", "canary-5", "engineering-settings-2026-10"}},
		{"plan", []string{"rollout", "plan", "claude-code-2.1.300"}, 0, []string{"canary-1", "[#.........]", "ring3-ga", "Earliest completion: T+7d14h"}},
		{"plan manual on completion", []string{"rollout", "plan", "opus-5-5-upgrade"}, 0, []string{"held on control", "On completion: gateway.models.opus has failover targets"}},
		{"status without evidence", []string{"rollout", "status", "opus-5-5-upgrade"}, 0, []string{"3/6 canary-5", "Entered:    unknown", "bake", "pending", "(metric gates need --clickhouse)", "Next:       hold"}},
		{"simulate healthy", []string{"rollout", "simulate", "opus-5-5-upgrade"}, 0, []string{"advance (approved)", "Outcome: complete after 19d20h"}},
		{"simulate regression", []string{"rollout", "simulate", "claude-code-2.1.300", "--scenario", "regression"}, 0, []string{"rollback", "guardrail:halo.tool.error_rate failed", "Outcome: rollback"}},
		{"simulate bad scenario", []string{"rollout", "simulate", "opus-5-5-upgrade", "--scenario", "chaos"}, 1, []string{"--scenario must be"}},
		{"advance dry-run", []string{"rollout", "advance", "opus-5-5-upgrade", "--reason", "metrics look fine", "--dry-run"}, 0, []string{"-step: canary-5", "+step: canary-25", "-    weight: 95", "+    weight: 75"}},
		{"advance needs reason", []string{"rollout", "advance", "opus-5-5-upgrade", "--dry-run"}, 1, []string{"--reason is required"}},
		{"rollback dry-run", []string{"rollout", "rollback", "claude-code-2.1.300", "--reason", "x", "--dry-run"}, 0, []string{"+status: aborted", "-status: running", "+status: paused"}},
		{"abort alias", []string{"rollout", "abort", "opus-5-5-upgrade", "--reason", "x", "--dry-run"}, 0, []string{"+status: aborted"}},
		{"pause dry-run", []string{"rollout", "pause", "opus-5-5-upgrade", "--reason", "x", "--dry-run"}, 0, []string{"-status: active", "+status: paused"}},
		{"unknown rollout", []string{"rollout", "plan", "nope"}, 1, []string{`unknown rollout "nope"`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := halo(t, append(tc.args, "--policy-dir", example)...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, out, errs)
			}
			got := out
			if code != 0 {
				got = errs
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("missing %q in:\n%s", w, got)
				}
			}
		})
	}
}

func TestRolloutCLIJSON(t *testing.T) {
	code, out, errs := halo(t, "rollout", "simulate", "opus-5-5-upgrade", "--policy-dir", example, "--output", "json")
	var res rollout.SimResult
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.Outcome != rollout.Complete || len(res.Events) == 0 {
		t.Fatalf("exit %d %s %s", code, out, errs)
	}
	code, out, _ = halo(t, "rollout", "plan", "claude-code-2.1.300", "--policy-dir", example, "--output", "json")
	var plan struct{ Timeline rollout.Timeline }
	if code != 0 || json.Unmarshal([]byte(out), &plan) != nil || len(plan.Timeline.Steps) != 7 {
		t.Fatalf("plan json: %s", out)
	}
}

// status reads the controller's state file for bake progress.
func TestRolloutStatusWithState(t *testing.T) {
	data := t.TempDir()
	st := rollout.NewState("opus-5-5-upgrade")
	st.Record(rollout.EventEnter, 2, "canary-5", "", time.Now().Add(-13*time.Hour))
	if err := st.Save(filepath.Join(data, "rollouts")); err != nil {
		t.Fatal(err)
	}
	code, out, errs := halo(t, "rollout", "status", "opus-5-5-upgrade", "--policy-dir", example, "--data-dir", data, "--output", "json")
	var got struct {
		Decision rollout.Decision
		State    rollout.State
	}
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("exit %d %s %s", code, out, errs)
	}
	if g := got.Decision.Gates[0]; g.Gate != "bake" || g.Status != rollout.GatePass || got.State.StepName != "canary-5" {
		t.Fatalf("gates %+v state %+v", got.Decision.Gates, got.State)
	}
	// A tampered state file is refused.
	p := rollout.StatePath(filepath.Join(data, "rollouts"), "opus-5-5-upgrade")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), `"index": 2`, `"index": 4`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := halo(t, "rollout", "status", "opus-5-5-upgrade", "--policy-dir", example, "--data-dir", data); code == 0 || !strings.Contains(errs, "hash chain") {
		t.Fatalf("tampered state accepted: %d %s", code, errs)
	}
}

// advance refuses when a gate failed unless --force; the scorecard gate is
// the one evaluable without ClickHouse.
func TestRolloutAdvanceRefusesBreach(t *testing.T) {
	dir := copyDir(t, example)
	sc := filepath.Join(dir, "evals", "claude-code-2.1.300.scorecard.json")
	b, err := os.ReadFile(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sc, []byte(strings.Replace(string(b), `"pass1": 0.767`, `"pass1": 0.5`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "rollouts", "claude-code-2.1.300.yaml")
	y, _ := os.ReadFile(f)
	if err := os.WriteFile(f, []byte(strings.Replace(string(y), "status: draft\n", "status: active\nstep: canary-25\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := halo(t, "rollout", "advance", "claude-code-2.1.300", "--policy-dir", dir, "--reason", "x", "--dry-run")
	if code == 0 || !strings.Contains(errs, "scorecard failed") {
		t.Fatalf("advance on breach: %d %s", code, errs)
	}
	if code, out, errs := halo(t, "rollout", "advance", "claude-code-2.1.300", "--policy-dir", dir, "--reason", "x", "--dry-run", "--force"); code != 0 || !strings.Contains(out, "+step: canary-50") {
		t.Fatalf("--force: %d %s %s", code, out, errs)
	}
	org, err := policy.Load(dir)
	if err != nil || org.Rollouts[0].Step == "canary-50" {
		t.Fatal("--dry-run wrote to the policy dir")
	}
}
