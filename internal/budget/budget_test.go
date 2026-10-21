package budget

import (
	"math"
	"slices"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

func keys(cs []Charge) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Budget.Name+"="+c.Key)
	}
	return out
}

func TestCharges(t *testing.T) {
	budgets := []policy.Budget{
		{Name: "per-user", Scope: policy.ScopeUser},
		{Name: "contractors", Scope: policy.ScopeUser, Groups: []string{"contractors"}},
		{Name: "teams", Scope: policy.ScopeGroup, Groups: []string{"platform", "ml"}},
		{Name: "rings", Scope: policy.ScopeRing},
		{Name: "canary", Scope: policy.ScopeRing, Rings: []string{"ring1"}},
		{Name: "org", Scope: policy.ScopeOrg},
		{Name: "org-ring1", Scope: policy.ScopeOrg, Rings: []string{"ring1"}},
	}
	tests := []struct {
		name string
		p    Principal
		want []string
	}{
		{"plain user in ga", Principal{Subject: "a", Ring: "ga"}, []string{"per-user=user:a", "rings=ring:ga", "org=org"}},
		{"contractor in two teams on ring1", Principal{Subject: "c", Groups: []string{"ml", "contractors", "platform"}, Ring: "ring1"},
			[]string{"per-user=user:c", "contractors=user:c", "teams=group:platform", "teams=group:ml", "rings=ring:ring1", "canary=ring:ring1", "org=org", "org-ring1=org"}},
		{"anonymous: no user or group counters", Principal{Ring: "ga", Groups: []string{"platform"}}, []string{"rings=ring:ga", "org=org"}},
		{"no ring", Principal{Subject: "a"}, []string{"per-user=user:a", "org=org"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keys(Charges(budgets, tt.p)); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestWindow(t *testing.T) {
	at := time.Date(2026, 10, 21, 15, 4, 5, 0, time.FixedZone("PDT", -7*3600)) // Wednesday, 22:04 UTC
	tests := []struct {
		window       string
		start, reset string
	}{
		{policy.WindowDay, "2026-10-21T00:00:00Z", "2026-10-22T00:00:00Z"},
		{policy.WindowWeek, "2026-10-19T00:00:00Z", "2026-10-26T00:00:00Z"},
		{policy.WindowMonth, "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z"},
	}
	for _, tt := range tests {
		s, r := Window(&policy.Budget{Window: tt.window}, at)
		if s.Format(time.RFC3339) != tt.start || r.Format(time.RFC3339) != tt.reset {
			t.Errorf("%s: %s..%s", tt.window, s.Format(time.RFC3339), r.Format(time.RFC3339))
		}
	}
	// Sunday belongs to the week that started the Monday before; Monday starts a new one.
	sun, _ := Window(&policy.Budget{Window: policy.WindowWeek}, time.Date(2026, 10, 25, 23, 0, 0, 0, time.UTC))
	mon, _ := Window(&policy.Budget{Window: policy.WindowWeek}, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
	if sun.Day() != 19 || mon.Day() != 26 {
		t.Fatalf("week edges: %v %v", sun, mon)
	}
	// December rolls into January.
	if _, r := Window(&policy.Budget{Window: policy.WindowMonth}, time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)); r != time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("december reset %v", r)
	}
	if got := bucketSize(24 * time.Hour); got != 30*time.Minute {
		t.Fatalf("24h bucket %v", got)
	}
	if got := bucketSize(time.Hour); got != time.Minute {
		t.Fatalf("1h bucket %v", got)
	}
}

func TestCost(t *testing.T) {
	prices := map[string]policy.ModelPrice{
		"sonnet": {InputPerMTok: 3, OutputPerMTok: 15, CacheReadPerMTok: 0.3, CacheWritePerMTok: 3.75},
		"plain":  {InputPerMTok: 2, OutputPerMTok: 8},
	}
	u := Usage{Input: 1_000_000, Output: 100_000, CacheRead: 2_000_000, CacheWrite: 400_000}
	if usd, ok := Cost(prices, "sonnet", u); !ok || math.Abs(usd-(3+1.5+0.6+1.5)) > 1e-9 {
		t.Fatalf("sonnet: %v %v", usd, ok)
	}
	if usd, ok := Cost(prices, "plain", u); !ok || math.Abs(usd-(2+0.8+4+0.8)) > 1e-9 { // cache priced as input
		t.Fatalf("plain: %v %v", usd, ok)
	}
	if usd, ok := Cost(prices, "unknown", u); ok || usd != 0 {
		t.Fatalf("unpriced: %v %v", usd, ok)
	}
	if u.Tokens() != 3_500_000 {
		t.Fatalf("tokens %d", u.Tokens())
	}
}

func TestStatusThresholds(t *testing.T) {
	s := Status{LimitUSD: 10, LimitTokens: 1000, SpentUSD: 5, SpentTokens: 850, AlertAt: []float64{0.5, 0.8, 0.95}}
	if s.Utilization() != 0.85 || s.Exceeded() || s.Alert() != 0.8 {
		t.Fatalf("util %v exceeded %v alert %v", s.Utilization(), s.Exceeded(), s.Alert())
	}
	s.SpentUSD = 10
	if !s.Exceeded() {
		t.Fatal("USD limit reached must exceed")
	}
	if (Status{SpentUSD: 99}).Utilization() != 0 {
		t.Fatal("no limits: utilization 0")
	}
}
