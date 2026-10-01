package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
)

type rolloutPR struct{ branch, title, body string }

// fakeRolloutWriter is a fakeWriter that also opens rollout PRs.
type fakeRolloutWriter struct {
	fakeWriter
	rmu sync.Mutex
	prs []rolloutPR
}

func (w *fakeRolloutWriter) ProposeRollout(_ context.Context, _ func(string) (*promote.Change, error), branch, title string, body func(string) string) (string, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	w.prs = append(w.prs, rolloutPR{branch, title, body("--- a/x\n+++ b/x\n")})
	return "https://github.test/pr/" + branch, nil
}

func testRollout(step string) *policy.Rollout {
	guard := []policy.MetricGoal{{Metric: "halo.cost.usd_per_session", Direction: "decrease", MaxRegression: 0.10}}
	return &policy.Rollout{
		Meta: policy.Meta{Name: "ro"}, Axis: policy.AxisTraffic, Status: policy.RolloutActive, Step: step, Experiment: "exp-a",
		Change: policy.RolloutChange{Alias: "opus"},
		Steps: []policy.RolloutStep{
			{Name: "c5", Strategy: policy.StrategyCanary, Percent: 5, Bake: "1h", MinSamples: 100, Gates: policy.RolloutGates{Guardrails: guard}},
			{Name: "c25", Strategy: policy.StrategyCanary, Percent: 25, MinSamples: 100, Gates: policy.RolloutGates{Guardrails: guard}},
		},
	}
}

func rolloutRig(t *testing.T, v promote.Verdict, step string) (*rig, *fakeRolloutWriter, *time.Time) {
	t.Helper()
	r := newRig(t, v)
	w := &fakeRolloutWriter{}
	now := start.Add(48 * time.Hour)
	r.c.Writer, r.c.Clock = w, func() time.Time { return now }
	r.c.RolloutStateDir = r.dir + "/rollouts"
	r.org.Rollouts = []*policy.Rollout{testRollout(step)}
	return r, w, &now
}

func ticks(t *testing.T, c *Controller, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := c.Tick(context.Background()); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
}

func TestRolloutStartOpensOnePR(t *testing.T) {
	r, w, _ := rolloutRig(t, promote.Continue, "")
	ticks(t, r.c, 3)
	if len(w.prs) != 1 || w.prs[0].branch != "halos/rollout-ro-c5" || !strings.Contains(w.prs[0].body, "must review and merge") {
		t.Fatalf("PRs = %+v", w.prs)
	}
	if len(r.n.events) != 1 || r.n.events[0].Rollout != "ro" || r.n.events[0].Verdict != "advance" || r.n.events[0].PRURL == "" {
		t.Fatalf("events = %+v", r.n.events)
	}
	if !strings.HasPrefix(r.n.events[0].Text(), "Halos rollout ro: ADVANCE") {
		t.Fatalf("text = %q", r.n.events[0].Text())
	}
	if len(w.calls) != 0 {
		t.Fatalf("backing experiment was driven by the experiment loop: %+v", w.calls)
	}
}

func TestRolloutBakesThenAdvances(t *testing.T) {
	r, w, now := rolloutRig(t, promote.Promote, "c5") // guardrail passes
	ticks(t, r.c, 1)                                  // enters c5 now: baking
	if len(w.prs) != 0 {
		t.Fatalf("advanced while baking: %+v", w.prs)
	}
	*now = now.Add(2 * time.Hour)
	ticks(t, r.c, 2)
	if len(w.prs) != 1 || w.prs[0].branch != "halos/rollout-ro-c25" {
		t.Fatalf("PRs = %+v", w.prs)
	}
	st, err := rollout.LoadState(r.c.RolloutStateDir, "ro")
	if err != nil || st.Last == nil || st.Last.Action != rollout.Advance || st.StepName != "c5" {
		t.Fatalf("state %+v %v", st, err)
	}
	// The human merges: the step is entered and a fresh PR can follow later.
	r.org.Rollouts[0].Step = "c25"
	ticks(t, r.c, 1)
	if st, _ := rollout.LoadState(r.c.RolloutStateDir, "ro"); st.StepName != "c25" || !st.EnteredAt.Equal(*now) {
		t.Fatalf("not entered: %+v", st)
	}
}

func TestRolloutBreachKillsOnce(t *testing.T) {
	r, w, _ := rolloutRig(t, promote.Rollback, "c5") // cost guardrail regresses on gateway evidence
	ticks(t, r.c, 3)
	if got := r.killed(t); len(got) != 1 || got[0] != "exp-a" {
		t.Fatalf("killed = %v", got)
	}
	if len(w.prs) != 1 || w.prs[0].branch != "halos/rollout-ro-rollback" || !strings.Contains(w.prs[0].body, "kill switch") {
		t.Fatalf("PRs = %+v", w.prs)
	}
	if len(r.n.events) != 1 || !r.n.events[0].Killed || r.n.events[0].KillOutcome != KillEnforced || r.n.events[0].Verdict != promote.Rollback {
		t.Fatalf("events = %+v", r.n.events)
	}
	st, err := rollout.LoadState(r.c.RolloutStateDir, "ro")
	if err != nil || st.Halted != "rollback" {
		t.Fatalf("state %+v %v", st, err)
	}
	// A human merges the rollback: the halt is acknowledged, nothing re-fires.
	r.org.Rollouts[0].Status, r.org.Experiments[0].Status = policy.RolloutAborted, "paused" // what the PR edits
	ticks(t, r.c, 2)
	if st, _ := rollout.LoadState(r.c.RolloutStateDir, "ro"); st.Halted != "" || len(w.prs) != 1 || len(r.n.events) != 1 {
		t.Fatalf("after merge: halted=%q prs=%d events=%d", st.Halted, len(w.prs), len(r.n.events))
	}
}

func TestRolloutBreachOnCLIEvidenceDoesNotKill(t *testing.T) {
	r, w, _ := rolloutRig(t, promote.Rollback, "c5")
	r.c.Metrics.(*promote.MemorySource).Source = promote.SourceCLI
	ticks(t, r.c, 2)
	if got := r.killed(t); len(got) != 0 {
		t.Fatalf("killed on CLI evidence: %v", got)
	}
	if len(w.prs) != 1 || len(r.n.events) != 1 || r.n.events[0].KillOutcome != KillNotGateway {
		t.Fatalf("prs=%d events=%+v", len(w.prs), r.n.events)
	}
}

func TestRolloutTamperedStateIsNotActedOn(t *testing.T) {
	r, w, _ := rolloutRig(t, promote.Continue, "")
	ticks(t, r.c, 1)
	p := rollout.StatePath(r.c.RolloutStateDir, "ro")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), `"event": "action"`, `"event": "enter"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "hash chain") {
		t.Fatalf("tick err = %v", err)
	}
	if len(w.prs) != 1 {
		t.Fatalf("acted on tampered state: %+v", w.prs)
	}
}

type fakeOpener struct{ req promote.PRRequest }

func (o *fakeOpener) OpenPR(_ context.Context, req promote.PRRequest) (string, error) {
	o.req = req
	return "https://github.test/pr/1", nil
}

func TestGitWriterProposeRollout(t *testing.T) {
	o := &fakeOpener{}
	w := &GitWriter{RepoDir: "/repo", Subdir: "policy", Base: "main", Opener: o}
	var gotDir string
	url, err := w.ProposeRollout(context.Background(), func(dir string) (*promote.Change, error) {
		gotDir = dir
		return &promote.Change{Files: map[string][]byte{"r.yaml": []byte("x")}, Patch: "PATCH"}, nil
	}, "halos/rollout-x", "T", func(p string) string { return "body " + p })
	if err != nil || url == "" || gotDir != filepath.Join("/repo", "policy") || o.req.Body != "body PATCH" || o.req.Base != "main" || o.req.Branch != "halos/rollout-x" {
		t.Fatalf("url=%q err=%v dir=%q req=%+v", url, err, gotDir, o.req)
	}
	_, err = w.ProposeRollout(context.Background(), func(string) (*promote.Change, error) { return &promote.Change{}, nil }, "b", "T", func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "already has this change") {
		t.Fatalf("empty change err = %v", err)
	}
}
