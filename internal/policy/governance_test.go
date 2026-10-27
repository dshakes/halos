package policy

import (
	"strings"
	"testing"
	"time"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func govOrg(g *Governance) *Org {
	return &Org{
		Rings:      []*Ring{{Meta: Meta{Name: "ring1"}}, {Meta: Meta{Name: "ring2"}}},
		Units:      []*Unit{{Meta: Meta{Name: "payments"}, Members: UnitMembers{Groups: []string{"payments-eng"}}}},
		Governance: g,
	}
}

// TestFreezeWindowsDST pins weekly and one-off windows to wall-clock times
// across DST changes: the instant moves with the offset, the time does not.
func TestFreezeWindowsDST(t *testing.T) {
	ny := mustZone(t, "America/New_York")
	lon := mustZone(t, "Europe/London")
	weekend := FreezeWindow{Name: "weekend", Reason: "weekend", Timezone: "America/New_York", Weekly: &WeeklyWindow{From: "Fri 18:00", To: "Mon 06:00"}}
	// 2026-03-08 02:00 EST -> 03:00 EDT; 2026-11-01 02:00 EDT -> 01:00 EST.
	gap := FreezeWindow{Name: "gap", Reason: "r", Timezone: "America/New_York", Weekly: &WeeklyWindow{From: "Sun 02:30", To: "Sun 04:00"}}
	overlap := FreezeWindow{Name: "overlap", Reason: "r", Timezone: "America/New_York", Weekly: &WeeklyWindow{From: "Sun 00:30", To: "Sun 01:30"}}
	yearEnd := FreezeWindow{Name: "q4", Reason: "r", Timezone: "Europe/London", Start: "2026-10-24T18:00", End: "2026-10-26T06:00"}
	overnight := FreezeWindow{Name: "nightly", Reason: "r", Timezone: "UTC", Weekly: &WeeklyWindow{From: "Wed 22:00", To: "Wed 02:00"}}

	cases := []struct {
		name   string
		w      FreezeWindow
		at     time.Time
		active bool
		until  time.Time
	}{
		{"weekend spans spring forward", weekend, time.Date(2026, 3, 7, 12, 0, 0, 0, ny), true, time.Date(2026, 3, 9, 6, 0, 0, 0, ny)},
		{"weekend opens Monday 06:00 EDT", weekend, time.Date(2026, 3, 9, 6, 0, 0, 0, ny), false, time.Time{}},
		{"one minute before the weekend", weekend, time.Date(2026, 3, 6, 17, 59, 0, 0, ny), false, time.Time{}},
		{"weekend starts Friday 18:00", weekend, time.Date(2026, 3, 6, 18, 0, 0, 0, ny), true, time.Date(2026, 3, 9, 6, 0, 0, 0, ny)},
		{"weekend spans fall back", weekend, time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("EST", -5*3600)), true, time.Date(2026, 11, 2, 6, 0, 0, 0, ny)},
		{"Monday 05:59 still frozen", weekend, time.Date(2026, 11, 2, 5, 59, 0, 0, ny), true, time.Date(2026, 11, 2, 6, 0, 0, 0, ny)},
		// 02:30 does not exist on 2026-03-08: Go places it at 03:30 EDT.
		{"start in the spring gap: 03:15 EDT is before it", gap, time.Date(2026, 3, 8, 3, 15, 0, 0, ny), false, time.Time{}},
		{"start in the spring gap: 03:45 EDT is in it", gap, time.Date(2026, 3, 8, 3, 45, 0, 0, ny), true, time.Date(2026, 3, 8, 4, 0, 0, 0, ny)},
		{"gap window a normal week later", gap, time.Date(2026, 3, 15, 2, 45, 0, 0, ny), true, time.Date(2026, 3, 15, 4, 0, 0, 0, ny)},
		// 01:30 happens twice on 2026-11-01: the window ends at the first.
		{"ends at the first 01:30", overlap, time.Date(2026, 11, 1, 5, 29, 0, 0, time.UTC), true, time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)},
		{"repeated hour stays open", overlap, time.Date(2026, 11, 1, 6, 15, 0, 0, time.UTC), false, time.Time{}},
		{"one-off across BST end", yearEnd, time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC), true, time.Date(2026, 10, 26, 6, 0, 0, 0, lon)},
		{"one-off before start", yearEnd, time.Date(2026, 10, 24, 16, 59, 0, 0, time.UTC), false, time.Time{}},
		{"one-off start is BST", yearEnd, time.Date(2026, 10, 24, 17, 0, 0, 0, time.UTC), true, time.Date(2026, 10, 26, 6, 0, 0, 0, lon)},
		{"one-off end is exclusive", yearEnd, time.Date(2026, 10, 26, 6, 0, 0, 0, time.UTC), false, time.Time{}},
		{"to before from wraps a week", overnight, time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC), true, time.Date(2026, 3, 11, 2, 0, 0, 0, time.UTC)},
		{"wrapped window opens Wed 02:00", overnight, time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC), false, time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			end, on := c.w.activeAt(c.at)
			if on != c.active {
				t.Fatalf("active = %v, want %v (end %v)", on, c.active, end)
			}
			if c.active && !end.Equal(c.until) {
				t.Fatalf("until = %v, want %v", end, c.until)
			}
		})
	}
	if end, _ := yearEnd.activeAt(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)); end.Sub(time.Date(2026, 10, 24, 17, 0, 0, 0, time.UTC)) != 37*time.Hour {
		t.Fatalf("one-off across BST end lasts %v, want 37h (36h of wall clock plus the repeated hour)", end.Sub(time.Date(2026, 10, 24, 17, 0, 0, 0, time.UTC)))
	}
	if end, _ := weekend.activeAt(time.Date(2026, 3, 7, 0, 0, 0, 0, ny)); end.Sub(time.Date(2026, 3, 6, 18, 0, 0, 0, ny)) != 59*time.Hour {
		t.Fatalf("weekend across spring forward lasts %v, want 59h", end.Sub(time.Date(2026, 3, 6, 18, 0, 0, 0, ny)))
	}
}

func TestFreezeAtScopeAndNextOpen(t *testing.T) {
	ny := mustZone(t, "America/New_York")
	o := govOrg(&Governance{Freezes: []FreezeWindow{
		{Name: "weekend", Reason: "no weekend deploys", Timezone: "America/New_York", Weekly: &WeeklyWindow{From: "Fri 18:00", To: "Mon 06:00"}},
		{Name: "launch", Reason: "launch day", Timezone: "America/New_York", Start: "2026-03-09T05:00", End: "2026-03-09T09:00", Scope: ChangeScope{Rings: []string{"ring2"}}},
		{Name: "close", Reason: "quarter close", Start: "2026-03-31", End: "2026-04-02", Scope: ChangeScope{Units: []string{"payments"}}},
	}})
	sat := time.Date(2026, 3, 7, 12, 0, 0, 0, ny)

	st := o.FreezeAt(sat, o.RingTarget("ring1"))
	if !st.Frozen || len(st.Active) != 1 || !st.NextOpen.Equal(time.Date(2026, 3, 9, 6, 0, 0, 0, ny)) {
		t.Fatalf("ring1 on Saturday: %+v", st)
	}
	// ring2's launch window abuts and overlaps the weekend: open at 09:00.
	st = o.FreezeAt(sat, o.RingTarget("ring2"))
	if !st.Frozen || !st.NextOpen.Equal(time.Date(2026, 3, 9, 9, 0, 0, 0, ny)) {
		t.Fatalf("ring2 on Saturday: next open %v, want 09:00 EDT Monday", st.NextOpen)
	}
	if st := o.FreezeAt(time.Date(2026, 3, 9, 7, 0, 0, 0, ny), o.RingTarget("ring1")); st.Frozen {
		t.Fatalf("ring1 Monday 07:00 frozen: %+v", st)
	}
	// A unit-scoped window covers ring changes (any ring may hold its members)
	// and requests from its members, not requests from others.
	tue := time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC)
	if !o.FreezeAt(tue, o.RingTarget("ring1")).Frozen {
		t.Fatal("unit window must cover ring changes")
	}
	if !o.FreezeAt(tue, o.SubjectTarget(Subject{ID: "a@x", Groups: []string{"payments-eng"}})).Frozen {
		t.Fatal("unit window must cover its members' requests")
	}
	if o.FreezeAt(tue, o.SubjectTarget(Subject{ID: "b@x"})).Frozen {
		t.Fatal("unit window must not cover non-members' requests")
	}
	if msg := o.FreezeAt(sat, o.RingTarget("ring1")).String(); !strings.Contains(msg, "weekend (no weekend deploys) until 2026-03-09T06:00:00-04:00") ||
		!strings.Contains(msg, "next open 2026-03-09T06:00:00-04:00") || !strings.Contains(msg, "Rollbacks") {
		t.Fatalf("message: %s", msg)
	}

	st = o.FreezeAt(time.Date(2026, 3, 10, 12, 0, 0, 0, ny), o.RingTarget("ring1"))
	st.AddIncident("oncall@acme", "SEV1 checkout outage")
	if !st.Frozen || !st.NextOpen.IsZero() || !strings.Contains(st.String(), "until lifted") {
		t.Fatalf("incident: %+v %s", st, st.String())
	}
}

func TestFreezeInvalidWindowFailsClosed(t *testing.T) {
	o := govOrg(&Governance{Freezes: []FreezeWindow{{Name: "bad", Reason: "r", Timezone: "Mars/Olympus", Start: "2026-01-01", End: "2026-01-02"}}})
	st := o.FreezeAt(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), o.RingTarget("ring1"))
	if !st.Frozen || !st.NextOpen.IsZero() {
		t.Fatalf("unparseable window must hold every change: %+v", st)
	}
}

func TestQuorum(t *testing.T) {
	rule := func(q int, distinct bool, ticket string) *Org {
		return govOrg(&Governance{Approvals: []ApprovalRule{{Name: "prod", Scope: ChangeScope{Rings: []string{"ring2"}}, Quorum: q,
			Groups: []string{"sre", "eng-managers"}, DistinctGroups: distinct, Ticket: ticket}}})
	}
	a := func(by string, groups ...string) Approval { return Approval{By: by, Groups: groups} }
	cases := []struct {
		name      string
		org       *Org
		ticket    string
		approvals []Approval
		have      int
		met       bool
		ignored   int
	}{
		{"two approvers", rule(2, false, ""), "", []Approval{a("bo@x", "sre"), a("cy@x", "sre")}, 2, true, 0},
		{"requester cannot approve", rule(2, false, ""), "", []Approval{a("Al@X", "sre"), a("bo@x", "sre")}, 1, false, 1},
		{"repeat approval counts once", rule(2, false, ""), "", []Approval{a("bo@x", "sre"), a("BO@x", "sre")}, 1, false, 1},
		{"group not held", rule(1, false, ""), "", []Approval{a("bo@x", "devs")}, 0, false, 0},
		{"distinct groups: same group twice", rule(2, true, ""), "", []Approval{a("bo@x", "sre"), a("cy@x", "sre")}, 1, false, 0},
		{"distinct groups: matching reassigns", rule(2, true, ""), "", []Approval{a("bo@x", "sre", "eng-managers"), a("cy@x", "sre")}, 2, true, 0},
		{"ticket required and missing", rule(1, false, `CHG[0-9]{7}`), "", []Approval{a("bo@x", "sre")}, 1, false, 0},
		{"ticket must match whole", rule(1, false, `CHG[0-9]{7}`), "xCHG1234567", []Approval{a("bo@x", "sre")}, 1, false, 0},
		{"ticket matches", rule(1, false, `CHG[0-9]{7}`), "CHG1234567", []Approval{a("bo@x", "sre")}, 1, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := c.org.Quorum(c.org.RingTarget("ring2"), "al@x", c.ticket, c.approvals)
			if q == nil || q.Met != c.met || q.Rules[0].Have != c.have || len(q.Ignored) != c.ignored {
				t.Fatalf("got %+v", q)
			}
			if !c.met && q.String() == "approval quorum met" {
				t.Fatal("String must say what is missing")
			}
		})
	}
	if q := rule(2, false, "").Quorum(ChangeTarget{Rings: []string{"ring1"}}, "al@x", "", nil); q != nil {
		t.Fatalf("ring1 is not covered: %+v", q)
	}
	o := rule(1, false, `OPS-[0-9]+`)
	if err := o.CheckTicket(o.RingTarget("ring2"), ""); err == nil {
		t.Fatal("missing ticket accepted")
	}
	if err := o.CheckTicket(o.RingTarget("ring2"), "OPS-12"); err != nil {
		t.Fatal(err)
	}
	if err := o.CheckTicket(o.RingTarget("ring1"), ""); err != nil {
		t.Fatalf("uncovered ring needs no ticket: %v", err)
	}
}

func TestValidateGovernance(t *testing.T) {
	cases := []struct {
		name string
		g    Governance
		path string
	}{
		{"unknown zone", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r", Timezone: "Nowhere/City", Start: "2026-01-01", End: "2026-01-02"}}}, "governance.freezes[0].timezone"},
		{"end before start", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r", Start: "2026-01-02", End: "2026-01-01"}}}, "governance.freezes[0].end"},
		{"both kinds", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r", Start: "2026-01-01", End: "2026-01-02", Weekly: &WeeklyWindow{From: "Fri 18:00", To: "Mon 06:00"}}}}, "governance.freezes[0]"},
		{"neither kind", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r"}}}, "governance.freezes[0]"},
		{"bad day", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r", Weekly: &WeeklyWindow{From: "Funday 18:00", To: "Mon 06:00"}}}}, "governance.freezes[0].weekly.from"},
		{"bad time", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r", Weekly: &WeeklyWindow{From: "Fri 18:00", To: "Mon 24:00"}}}}, "governance.freezes[0].weekly.to"},
		{"whole week", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r", Weekly: &WeeklyWindow{From: "Fri 18:00", To: "fri 18:00"}}}}, "governance.freezes[0].weekly"},
		{"no reason", Governance{Freezes: []FreezeWindow{{Name: "a", Start: "2026-01-01", End: "2026-01-02"}}}, "governance.freezes[0].reason"},
		{"reserved name", Governance{Freezes: []FreezeWindow{{Name: "incident", Reason: "r", Start: "2026-01-01", End: "2026-01-02"}}}, "governance.freezes[0].name"},
		{"unknown ring", Governance{Freezes: []FreezeWindow{{Name: "a", Reason: "r", Start: "2026-01-01", End: "2026-01-02", Scope: ChangeScope{Rings: []string{"ring9"}}}}}, "governance.freezes[0].scope.rings[0]"},
		{"unknown unit", Governance{Approvals: []ApprovalRule{{Name: "a", Quorum: 1, Groups: []string{"g"}, Scope: ChangeScope{Units: []string{"hr"}}}}}, "governance.approvals[0].scope.units[0]"},
		{"zero quorum", Governance{Approvals: []ApprovalRule{{Name: "a", Groups: []string{"g"}}}}, "governance.approvals[0].quorum"},
		{"no groups", Governance{Approvals: []ApprovalRule{{Name: "a", Quorum: 1}}}, "governance.approvals[0].groups"},
		{"distinct needs groups", Governance{Approvals: []ApprovalRule{{Name: "a", Quorum: 2, Groups: []string{"g"}, DistinctGroups: true}}}, "governance.approvals[0].quorum"},
		{"bad ticket regexp", Governance{Approvals: []ApprovalRule{{Name: "a", Quorum: 1, Groups: []string{"g"}, Ticket: "CHG[0-9"}}}, "governance.approvals[0].ticket"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &validator{org: govOrg(&c.g)}
			v.governance()
			for _, i := range v.issues {
				if i.Path == c.path && i.Severity == SeverityError {
					return
				}
			}
			t.Fatalf("no error at %s: %+v", c.path, v.issues)
		})
	}
	v := &validator{org: govOrg(&Governance{
		Freezes:   []FreezeWindow{{Name: "weekend", Reason: "r", Timezone: "Europe/Berlin", Weekly: &WeeklyWindow{From: "Fri 18:00", To: "Mon 06:00"}, Scope: ChangeScope{Rings: []string{"ring2"}, Units: []string{"payments"}}}},
		Approvals: []ApprovalRule{{Name: "prod", Quorum: 2, Groups: []string{"sre", "mgr"}, DistinctGroups: true, Ticket: `CHG[0-9]+`}},
	})}
	v.governance()
	if len(v.issues) != 0 {
		t.Fatalf("valid governance: %+v", v.issues)
	}
}
