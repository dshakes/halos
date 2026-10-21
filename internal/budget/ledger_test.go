package budget

import (
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func rec(sub string, usd float64, tokens int64, at time.Time) Record {
	return Record{Principal: Principal{Subject: sub, Ring: "ga"}, Spend: Spend{USD: usd, Tokens: tokens}, At: at}
}

func TestLedgerCalendar(t *testing.T) {
	budgets := []policy.Budget{{Name: "daily", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitUSD: 10, Action: policy.BudgetEnforce}}
	l := NewLedger()
	if dup := l.Apply(budgets, "b1", []Record{rec("a", 4, 100, t0), rec("a", 7, 50, t0.Add(time.Hour)), rec("b", 1, 1, t0)}, t0.Add(time.Hour)); dup {
		t.Fatal("first batch reported duplicate")
	}
	if !l.Apply(budgets, "b1", []Record{rec("a", 100, 0, t0)}, t0.Add(time.Hour)) {
		t.Fatal("replayed batch counted again")
	}
	st := l.Status(budgets, Principal{Subject: "a", Ring: "ga"}, t0.Add(2*time.Hour))
	if len(st) != 1 || st[0].SpentUSD != 11 || st[0].SpentTokens != 150 || !st[0].Exceeded() || st[0].Action != policy.BudgetEnforce ||
		st[0].ResetAt != time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC) || st[0].Key != "user:a" || st[0].AlertAt[0] != 0.8 {
		t.Fatalf("status %+v", st)
	}
	// Late usage lands in the window it happened in; a future timestamp is clamped to now.
	l.Apply(budgets, "b2", []Record{rec("c", 5, 0, t0.Add(-24*time.Hour)), rec("c", 2, 0, t0.Add(48*time.Hour))}, t0)
	if st := l.Status(budgets, Principal{Subject: "c"}, t0); st[0].SpentUSD != 2 {
		t.Fatalf("yesterday's usage or a future stamp leaked into today: %+v", st)
	}
	// Next day: a fresh window.
	if st := l.Status(budgets, Principal{Subject: "a"}, t0.Add(13*time.Hour)); st[0].SpentUSD != 0 {
		t.Fatalf("new day: %+v", st)
	}
}

func TestLedgerRolling(t *testing.T) {
	b := policy.Budget{Name: "r", Scope: policy.ScopeOrg, Window: policy.WindowRolling, Period: "24h", LimitTokens: 100, Action: policy.BudgetEnforce}
	budgets := []policy.Budget{b}
	l := NewLedger()
	l.Apply(budgets, "1", []Record{rec("a", 0, 60, t0)}, t0)
	l.Apply(budgets, "2", []Record{rec("b", 0, 30, t0.Add(6*time.Hour))}, t0.Add(6*time.Hour))
	l.Apply(budgets, "3", []Record{rec("a", 0, 20, t0.Add(12*time.Hour))}, t0.Add(12*time.Hour))
	now := t0.Add(13 * time.Hour)
	st := l.Status(budgets, Principal{}, now)[0]
	// 110 >= 100: back under once the 12:00 bucket (60) expires at 12:00+30m+24h.
	if st.SpentTokens != 110 || !st.Exceeded() || st.ResetAt != t0.Add(24*time.Hour+30*time.Minute) {
		t.Fatalf("rolling exceeded: %+v", st)
	}
	after := l.Status(budgets, Principal{}, st.ResetAt)[0]
	if after.SpentTokens != 50 || after.Exceeded() {
		t.Fatalf("at reset: %+v", after)
	}
	// Not exceeded: ResetAt is when the oldest usage leaves the window.
	if after.ResetAt != t0.Add(30*time.Hour+30*time.Minute) {
		t.Fatalf("under-limit reset %v", after.ResetAt)
	}
	if empty := l.Status([]policy.Budget{{Name: "other", Scope: policy.ScopeOrg, Window: policy.WindowRolling, Period: "2h", LimitUSD: 1}}, Principal{}, now)[0]; empty.SpentUSD != 0 || empty.ResetAt != now.Add(2*time.Hour) {
		t.Fatalf("empty rolling counter: %+v", empty)
	}
}

func TestLedgerPruneAllAndPersist(t *testing.T) {
	budgets := []policy.Budget{
		{Name: "users", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitUSD: 5},
		{Name: "teams", Scope: policy.ScopeGroup, Groups: []string{"ml", "platform"}, Window: policy.WindowMonth, LimitUSD: 500},
		{Name: "canary", Scope: policy.ScopeRing, Rings: []string{"ring1"}, Window: policy.WindowWeek, LimitTokens: 9},
		{Name: "gone", Scope: policy.ScopeOrg, Window: policy.WindowDay, LimitUSD: 1},
	}
	l := NewLedger()
	r := rec("a", 1, 10, t0)
	r.Groups = []string{"ml"}
	l.Apply(budgets, "1", []Record{r}, t0)

	all := l.All(budgets, t0)
	var got []string
	for _, s := range all {
		got = append(got, s.Budget+"="+s.Key)
	}
	want := "users=user:a teams=group:ml teams=group:platform canary=ring:ring1 gone=org"
	if g := strings.Join(got, " "); g != want {
		t.Fatalf("All: %s\nwant %s", g, want)
	}

	b, changed, err := l.Snapshot()
	if err != nil || !changed {
		t.Fatalf("snapshot: %v %v", changed, err)
	}
	if _, changed, _ := l.Snapshot(); changed {
		t.Fatal("unchanged ledger reported changed")
	}
	l2, err := LoadLedger(b)
	if err != nil {
		t.Fatal(err)
	}
	if st := l2.Status(budgets, Principal{Subject: "a", Groups: []string{"ml"}}, t0); st[0].SpentUSD != 1 || st[1].SpentUSD != 1 {
		t.Fatalf("restored: %+v", st)
	}
	if !l2.Apply(budgets, "1", nil, t0) {
		t.Fatal("restored ledger forgot batch ids")
	}

	// A budget removed from policy and an expired window are pruned; batch ids expire after an hour.
	later := t0.Add(48 * time.Hour)
	l2.Apply(budgets[:3], "2", nil, later)
	if len(l2.c["gone"]) != 0 || len(l2.c["users"]) != 0 || len(l2.c["teams"]) != 1 {
		t.Fatalf("prune left %v", l2.c)
	}
	if l2.Apply(budgets, "1", nil, later.Add(2*time.Minute)) {
		t.Fatal("an hour-old batch id must be forgotten")
	}

	for name, raw := range map[string]string{"garbage": "{", "version": `{"version":9}`} {
		if _, err := LoadLedger([]byte(raw)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}
