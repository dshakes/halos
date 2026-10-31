package rollout

import (
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/stats"
)

func govTestOrg(g *policy.Governance) *policy.Org {
	return &policy.Org{
		Rings:       []*policy.Ring{{Meta: policy.Meta{Name: "ring1"}}, {Meta: policy.Meta{Name: "ga"}}, {Meta: policy.Meta{Name: "canary"}}},
		Experiments: []*policy.Experiment{{Meta: policy.Meta{Name: "e"}, Rings: []string{"canary"}}},
		Governance:  g,
	}
}

// TestFreezeMatrix: a freeze holds every forward move (start, advance,
// complete) but never a rollback or pause, whatever the gate state.
func TestFreezeMatrix(t *testing.T) {
	frozen := &policy.FreezeStatus{Frozen: true, Active: []policy.ActiveFreeze{{Name: "q4", Reason: "year end", Until: t0.Add(48 * time.Hour)}}, NextOpen: t0.Add(48 * time.Hour)}
	good := card(0.8, 0.01, "no_difference")
	cases := []struct {
		name string
		st   State
		ev   Evidence
		now  time.Time
		want Action
	}{
		{"start is held", NewState("r"), Evidence{}, t0, Hold},
		{"advance is held", at(1, t0), Evidence{Report: rep(500, stats.Pass, "gateway"), Scorecard: good}, t0.Add(3 * time.Hour), Hold},
		{"complete is held", at(4, t0), Evidence{Report: rep(5000, stats.Pass, "gateway")}, t0.Add(15 * 24 * time.Hour), Hold},
		{"rollback is never held", at(1, t0), Evidence{Report: rep(500, stats.Fail, "gateway"), Scorecard: good}, t0.Add(time.Minute), Rollback},
		{"pause is never held", at(0, t0), Evidence{Report: rep(50, stats.Fail, "gateway")}, t0.Add(time.Minute), Pause},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.ev.Freeze = frozen
			d := Evaluate(testRollout(), c.st, c.ev, c.now)
			if d.Action != c.want {
				t.Fatalf("action = %s, want %s (%v)", d.Action, c.want, d.Reasons)
			}
			if c.want == Hold && (!strings.Contains(d.Frozen, "q4 (year end)") || !strings.Contains(d.Frozen, "next open")) {
				t.Fatalf("frozen = %q", d.Frozen)
			}
			if c.want != Hold && d.Frozen != "" {
				t.Fatalf("a %s must not report a freeze: %q", d.Action, d.Frozen)
			}
			// Without the freeze the same evidence moves forward.
			c.ev.Freeze = nil
			if d := Evaluate(testRollout(), c.st, c.ev, c.now); c.want == Hold && d.Action == Hold {
				t.Fatalf("unfrozen still holds: %v", d.Reasons)
			}
		})
	}
}

func TestGovernanceApply(t *testing.T) {
	org := govTestOrg(&policy.Governance{
		Freezes: []policy.FreezeWindow{{Name: "ga-weekend", Reason: "weekend", Scope: policy.ChangeScope{Rings: []string{"ga"}},
			Weekly: &policy.WeeklyWindow{From: "Sat 00:00", To: "Mon 00:00"}}},
		Approvals: []policy.ApprovalRule{{Name: "prod", Scope: policy.ChangeScope{Rings: []string{"ga"}}, Quorum: 2, Groups: []string{"sre", "mgr"}, DistinctGroups: true, Ticket: `CHG[0-9]+`}},
	})
	r := testRollout()
	sat := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) // a Saturday
	mon := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

	// From ring1 (step 2) the next step enters ga: covered by both.
	st := at(2, t0)
	var ev Evidence
	Governance{}.Apply(org, r, st, &ev, sat)
	if ev.Freeze == nil || ev.Quorum == nil || ev.Quorum.Met {
		t.Fatalf("ga advance on Saturday: freeze %v quorum %+v", ev.Freeze, ev.Quorum)
	}
	d := Evaluate(r, st, ev, sat)
	if d.Action != Hold || !d.AwaitingApproval || d.Gates[len(d.Gates)-1].Gate != "approval" {
		t.Fatalf("want an approval hold: %+v", d)
	}
	// A human advance (ev.Approved) does not satisfy a quorum.
	ev.Approved = true
	if d := Evaluate(r, st, ev, mon); d.Action != Hold {
		t.Fatalf("quorum bypassed by a human advance: %s", d.Action)
	}

	g := Governance{Requester: "al@x", Approvals: []policy.Approval{
		{By: "al@x", Groups: []string{"sre"}, Ticket: "CHG1"}, // requester: does not count
		{By: "bo@x", Groups: []string{"sre"}, Ticket: "CHG1"},
		{By: "cy@x", Groups: []string{"mgr"}},
	}}
	ev = Evidence{}
	g.Apply(org, r, st, &ev, mon)
	if ev.Freeze != nil || !ev.Quorum.Met || ev.Quorum.Ticket != "CHG1" {
		t.Fatalf("Monday with quorum: freeze %v quorum %+v", ev.Freeze, ev.Quorum)
	}
	d = Evaluate(r, st, ev, mon)
	if d.Action != Advance || d.Next != 3 {
		t.Fatalf("want advance to ga: %+v", d)
	}
	if b := Body("intro", d, nil, "diff\n"); !strings.Contains(b, "Ticket: `CHG1`") || !strings.Contains(b, "bo@x, cy@x") {
		t.Fatalf("PR body lacks governance:\n%s", b)
	}

	// The same quorum on Saturday is still frozen.
	ev = Evidence{}
	g.Apply(org, r, st, &ev, sat)
	if d := Evaluate(r, st, ev, sat); d.Action != Hold || d.Frozen == "" {
		t.Fatalf("frozen Saturday: %+v", d)
	}
	// An incident freeze holds everything, rings in no window included.
	ev = Evidence{}
	Governance{Incident: &policy.ActiveFreeze{By: "oncall@x", Reason: "SEV1"}}.Apply(org, r, at(0, t0), &ev, mon)
	if ev.Freeze == nil || !strings.Contains(ev.Freeze.String(), "incident (SEV1) until lifted") {
		t.Fatalf("incident: %+v", ev.Freeze)
	}

	// From the dark launch (step 0) the next step exposes the experiment's
	// canary ring: no rule covers it, and a recorded approval is a plain one.
	ev = Evidence{}
	Governance{Approvals: []policy.Approval{{By: "bo@x"}}}.Apply(org, r, at(0, t0), &ev, sat)
	if ev.Quorum != nil || ev.Freeze != nil || !ev.Approved {
		t.Fatalf("canary step: %+v", ev)
	}
	// A scoped approval (ADR-0037) is a plain approval only when its scope
	// covers the step's rings.
	for _, c := range []struct {
		scope policy.RoleScope
		want  bool
	}{{policy.RoleScope{Rings: []string{"canary"}}, true}, {policy.RoleScope{Rings: []string{"ga"}}, false}, {policy.RoleScope{Units: []string{"bu"}}, false}} {
		ev = Evidence{}
		a := policy.ScopedApproval("sc@x", nil, t0, "", []policy.RoleScope{c.scope})
		Governance{Approvals: []policy.Approval{a}}.Apply(org, r, at(0, t0), &ev, sat)
		if ev.Approved != c.want {
			t.Errorf("scoped approval over %s: approved=%v, want %v", c.scope, ev.Approved, c.want)
		}
	}
	// (c) The requester's own approval satisfies no plain gate either.
	for _, c := range []struct {
		by   string
		want bool
	}{{"Bo@X", false}, {"al@x", true}} {
		ev = Evidence{}
		Governance{Requester: "bo@x", Approvals: []policy.Approval{{By: c.by}}}.Apply(org, r, at(0, t0), &ev, sat)
		if ev.Approved != c.want {
			t.Errorf("approval by %s, requested by bo@x: approved=%v, want %v", c.by, ev.Approved, c.want)
		}
	}
}

// TestApprovalKeyChangesWithStepAndChange: approvals never carry over to
// another step, or to the same step after the approved change is edited.
func TestApprovalKeyChangesWithStepAndChange(t *testing.T) {
	setup := func() (*policy.Org, *policy.Rollout) {
		org := govTestOrg(nil)
		org.Experiments[0].Variants = []policy.Variant{
			{Name: "control", Control: true},
			{Name: "new", Routes: map[string]policy.ModelRoute{"opus": {Upstream: "bedrock", Model: "opus-5-5"}}},
		}
		r := testRollout()
		r.Change.Alias = "opus"
		return org, r
	}
	org, r := setup()
	k0 := ApprovalKey(org, r)
	if k0 != ApprovalKey(org, r) {
		t.Fatal("key is not deterministic")
	}
	edits := []struct {
		name string
		edit func(*policy.Org, *policy.Rollout)
	}{
		{"step", func(_ *policy.Org, r *policy.Rollout) { r.Step = "ring1" }},
		{"release", func(_ *policy.Org, r *policy.Rollout) { r.Change.Release = "sha256:" + strings.Repeat("f", 64) }},
		{"alias", func(_ *policy.Org, r *policy.Rollout) { r.Change.Alias = "sonnet" }},
		{"experiment", func(_ *policy.Org, r *policy.Rollout) { r.Experiment = "other" }},
		{"treatment model", func(o *policy.Org, _ *policy.Rollout) {
			o.Experiments[0].Variants[1].Routes["opus"] = policy.ModelRoute{Upstream: "bedrock", Model: "evil"}
		}},
		{"treatment upstream", func(o *policy.Org, _ *policy.Rollout) {
			o.Experiments[0].Variants[1].Routes["opus"] = policy.ModelRoute{Upstream: "elsewhere", Model: "opus-5-5"}
		}},
		// ADR-0037 review (L3): retargeting is a new change, for every reader of the key.
		{"next step's rings", func(_ *policy.Org, r *policy.Rollout) { r.Steps[0].Ring = "ga" }},
		{"experiment's rings", func(o *policy.Org, _ *policy.Rollout) { o.Experiments[0].Rings = []string{"canary", "ga"} }},
	}
	for _, e := range edits {
		t.Run(e.name, func(t *testing.T) {
			org, r := setup()
			e.edit(org, r)
			if ApprovalKey(org, r) == k0 {
				t.Fatalf("approvals carry over after editing the %s", e.name)
			}
		})
	}
}
