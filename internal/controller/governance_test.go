package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
)

// TestRolloutFreezeMatrix: a change freeze (policy window, incident freeze,
// or unreadable governance state) holds starts and advances, never a
// rollback or its kill (ADR-0030).
func TestRolloutFreezeMatrix(t *testing.T) {
	incident := func(context.Context, *policy.Org, *policy.Rollout) (rollout.Governance, error) {
		return rollout.Governance{Incident: &policy.ActiveFreeze{By: "oncall@x", Reason: "SEV1"}}, nil
	}
	broken := func(context.Context, *policy.Org, *policy.Rollout) (rollout.Governance, error) {
		return rollout.Governance{}, errors.New("store down")
	}
	window := func(r *rig, now time.Time) {
		r.org.Governance = &policy.Governance{Freezes: []policy.FreezeWindow{{Name: "q4", Reason: "year end",
			Start: now.Add(-time.Hour).Format(time.RFC3339), End: now.Add(time.Hour).Format(time.RFC3339)}}}
	}
	for _, c := range []struct {
		name  string
		setup func(*rig, time.Time)
		gov   func(context.Context, *policy.Org, *policy.Rollout) (rollout.Governance, error)
	}{
		{"policy window", window, nil},
		{"incident freeze", nil, incident},
		{"governance unreadable", nil, broken},
	} {
		t.Run(c.name+": start held", func(t *testing.T) {
			r, w, now := rolloutRig(t, promote.Continue, "")
			if c.setup != nil {
				c.setup(r, *now)
			}
			r.c.Governance = c.gov
			for range 3 {
				_ = r.c.Tick(context.Background()) // the unreadable case also reports its error
			}
			if len(w.prs) != 0 {
				t.Fatalf("PR opened during a freeze: %+v", w.prs)
			}
			if len(r.n.events) != 1 || r.n.events[0].Verdict != "frozen" {
				t.Fatalf("want one frozen notification: %+v", r.n.events)
			}
		})
		t.Run(c.name+": rollback still kills", func(t *testing.T) {
			r, w, now := rolloutRig(t, promote.Rollback, "c5")
			if c.setup != nil {
				c.setup(r, *now)
			}
			r.c.Governance = c.gov
			for range 2 {
				_ = r.c.Tick(context.Background())
			}
			if got := r.killed(t); len(got) != 1 || got[0] != "exp-a" {
				t.Fatalf("killed = %v", got)
			}
			if len(w.prs) != 1 || w.prs[0].branch != "halos/rollout-ro-rollback" {
				t.Fatalf("PRs = %+v", w.prs)
			}
		})
	}
}

// TestRolloutQuorumGatesTheController: a step an approval rule covers waits
// for its quorum; recorded approvals then let the controller propose it.
func TestRolloutQuorumGatesTheController(t *testing.T) {
	r, w, _ := rolloutRig(t, promote.Continue, "")
	r.org.Rings = []*policy.Ring{{Meta: policy.Meta{Name: "ring1"}}}
	r.org.Experiments[0].Rings = []string{"ring1"}
	r.org.Governance = &policy.Governance{Approvals: []policy.ApprovalRule{{Name: "two", Quorum: 2, Groups: []string{"sre"}, Ticket: `CHG[0-9]+`}}}
	var approvals []policy.Approval
	r.c.Governance = func(context.Context, *policy.Org, *policy.Rollout) (rollout.Governance, error) {
		return rollout.Governance{Approvals: approvals}, nil
	}
	ticks(t, r.c, 2)
	if len(w.prs) != 0 || len(r.n.events) != 1 || r.n.events[0].Verdict != "awaiting_approval" {
		t.Fatalf("prs=%+v events=%+v", w.prs, r.n.events)
	}
	approvals = []policy.Approval{{By: "bo@x", Groups: []string{"sre"}, Ticket: "CHG42"}, {By: "cy@x", Groups: []string{"sre"}}}
	ticks(t, r.c, 1)
	if len(w.prs) != 1 || !strings.Contains(w.prs[0].body, "Ticket: `CHG42`") || !strings.Contains(w.prs[0].body, "bo@x, cy@x") {
		t.Fatalf("PRs = %+v", w.prs)
	}
}

func TestKillStoreIncidentFreeze(t *testing.T) {
	s, err := OpenKillStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if _, err := s.Kill(ctx, "exp", "a", "r"); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Freeze(ctx, "oncall@x", "SEV1"); err != nil || !changed {
		t.Fatalf("freeze: %v %v", changed, err)
	}
	if changed, _ := s.Freeze(ctx, "oncall@x", "again"); changed {
		t.Fatal("second freeze changed state")
	}
	recs, _, err := s.Killed()
	if err != nil || len(recs) != 1 || recs[0].Experiment != "exp" {
		t.Fatalf("the freeze must never reach a kill list: %+v %v", recs, err)
	}
	if inc, err := s.Incident(); err != nil || inc == nil || inc.By != "oncall@x" || inc.Reason != "SEV1" {
		t.Fatalf("incident = %+v %v", inc, err)
	}
	if changed, err := s.Unfreeze(ctx, "oncall@x", "resolved"); err != nil || !changed {
		t.Fatalf("unfreeze: %v %v", changed, err)
	}
	if inc, _ := s.Incident(); inc != nil {
		t.Fatalf("still frozen: %+v", inc)
	}
}
