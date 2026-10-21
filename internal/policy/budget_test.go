package policy

import (
	"math"
	"strings"
	"testing"
	"time"
)

func budgetOrg(b ...Budget) *Org {
	o := validOrg()
	o.Gateway.Pricing = map[string]ModelPrice{"m1": {InputPerMTok: 3, OutputPerMTok: 15}, "m2": {InputPerMTok: 1, OutputPerMTok: 5}}
	o.Gateway.Budgets = b
	return o
}

func TestValidateBudgets(t *testing.T) {
	ok := Budget{Name: "daily", Scope: ScopeUser, Window: WindowDay, LimitUSD: 25, Action: BudgetEnforce}
	if issues := budgetOrg(ok,
		Budget{Name: "team", Scope: ScopeGroup, Groups: []string{"ml"}, Rings: []string{"r0"}, Window: WindowRolling, Period: "24h", LimitTokens: 1e9, AlertAt: []float64{0.5, 0.9}},
	).Validate(); len(issues) != 0 {
		t.Fatalf("valid budgets: %v", issues)
	}
	with := func(f func(*Budget)) *Org { b := ok; f(&b); return budgetOrg(b) }
	tests := []struct {
		name      string
		org       *Org
		path, msg string
		wantSev   Severity
	}{
		{"bad name", with(func(b *Budget) { b.Name = "Daily Cap" }), "budgets[0].name", "must match", SeverityError},
		{"duplicate name", budgetOrg(ok, ok), "budgets[1].name", "duplicate budget", SeverityError},
		{"bad scope", with(func(b *Budget) { b.Scope = "team" }), "budgets[0].scope", "invalid", SeverityError},
		{"bad window", with(func(b *Budget) { b.Window = "year" }), "budgets[0].window", "invalid", SeverityError},
		{"bad action", with(func(b *Budget) { b.Action = "block" }), "budgets[0].action", "invalid", SeverityError},
		{"group scope without groups", with(func(b *Budget) { b.Scope = ScopeGroup }), "budgets[0].groups", "needs the groups", SeverityError},
		{"unknown ring", with(func(b *Budget) { b.Rings = []string{"ghost"} }), "budgets[0].rings", "not defined", SeverityError},
		{"rolling without period", with(func(b *Budget) { b.Window = WindowRolling }), "budgets[0].period", "needs a period", SeverityError},
		{"rolling period too short", with(func(b *Budget) { b.Window, b.Period = WindowRolling, "5m" }), "budgets[0].period", "between", SeverityError},
		{"rolling period unparsable", with(func(b *Budget) { b.Window, b.Period = WindowRolling, "1d" }), "budgets[0].period", "between", SeverityError},
		{"period on calendar window", with(func(b *Budget) { b.Period = "24h" }), "budgets[0].period", "only valid on window rolling", SeverityError},
		{"no limit", with(func(b *Budget) { b.LimitUSD = 0 }), "budgets[0]", "set limitUSD", SeverityError},
		{"negative limit", with(func(b *Budget) { b.LimitTokens = -1 }), "budgets[0]", ">= 0", SeverityError},
		{"NaN limit", with(func(b *Budget) { b.LimitUSD = math.NaN() }), "budgets[0]", "finite", SeverityError},
		{"alert at 1", with(func(b *Budget) { b.AlertAt = []float64{1} }), "budgets[0].alertAt[0]", "(0,1)", SeverityError},
		{"negative price", func() *Org { o := budgetOrg(ok); o.Gateway.Pricing["m1"] = ModelPrice{InputPerMTok: -1}; return o }(), "gateway.pricing.m1", ">= 0", SeverityError},
		{"routed model without price", func() *Org { o := budgetOrg(ok); delete(o.Gateway.Pricing, "m2"); return o }(), "gateway.pricing", `"m2"`, SeverityWarning},
		{"kong does not enforce", func() *Org { o := budgetOrg(ok); o.Gateway.Engine = "kong"; return o }(), "gateway.budgets", "only by halo-proxy", SeverityWarning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := tt.org.Validate()
			for _, i := range issues {
				if strings.Contains(i.Path, tt.path) && strings.Contains(i.Message, tt.msg) && i.Severity == tt.wantSev {
					return
				}
			}
			t.Fatalf("want %s %s ~%q, got %v", tt.wantSev, tt.path, tt.msg, issues)
		})
	}
	// Token-only budgets need no prices.
	o := budgetOrg(Budget{Name: "t", Scope: ScopeOrg, Window: WindowMonth, LimitTokens: 5})
	o.Gateway.Pricing = nil
	if issues := o.Validate(); len(issues) != 0 {
		t.Fatalf("token-only budget: %v", issues)
	}
}

func TestBudgetDefaults(t *testing.T) {
	b := Budget{Window: WindowRolling, Period: "36h"}
	if b.Mode() != BudgetWarn || len(b.Alerts()) != 1 || b.Alerts()[0] != 0.8 || b.RollingPeriod() != 36*time.Hour {
		t.Fatalf("defaults: %s %v %v", b.Mode(), b.Alerts(), b.RollingPeriod())
	}
	if (&Budget{Window: WindowDay, Period: "36h"}).RollingPeriod() != 0 || (&Budget{Window: WindowRolling, Period: "x"}).RollingPeriod() != 0 {
		t.Fatal("RollingPeriod must be 0 off rolling windows and on bad periods")
	}
}

// The snapshot of a policy without budgets is byte-identical to before they existed.
func TestBudgetsOmittedFromSnapshot(t *testing.T) {
	b, err := Compile(validOrg())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "budgets") || strings.Contains(string(b), "pricing") {
		t.Fatalf("empty budgets serialised: %s", b)
	}
}
