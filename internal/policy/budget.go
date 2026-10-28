package policy

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// ModelPrice is what one provider model costs, in USD per million tokens.
// Cache prices of 0 fall back to InputPerMTok: over-counting a cache hit is
// the safe direction for a budget.
type ModelPrice struct {
	InputPerMTok      float64 `yaml:"inputPerMTok" json:"inputPerMTok"`
	OutputPerMTok     float64 `yaml:"outputPerMTok" json:"outputPerMTok"`
	CacheReadPerMTok  float64 `yaml:"cacheReadPerMTok,omitempty" json:"cacheReadPerMTok,omitempty"`
	CacheWritePerMTok float64 `yaml:"cacheWritePerMTok,omitempty" json:"cacheWritePerMTok,omitempty"`
}

// Budget caps model spend over a window for one scope (ADR-0017).
type Budget struct {
	Name string `yaml:"name" json:"name"`
	// Scope picks the counter: user (one per verified subject), group (one per
	// listed group), ring (one per ring) or org (one shared counter).
	Scope string `yaml:"scope" json:"scope"`
	// Groups: for scope group, the groups that each get a counter (required);
	// for other scopes, only callers in one of them are counted. Empty = everyone.
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	// Rings limits the budget to callers routed to these rings. Empty = every ring.
	Rings []string `yaml:"rings,omitempty" json:"rings,omitempty"`
	// Window: day | week (Monday) | month, calendar windows in UTC, or rolling
	// over Period.
	Window string `yaml:"window" json:"window"`
	// Period is the rolling window length as a Go duration (e.g. 24h); rolling only.
	Period string `yaml:"period,omitempty" json:"period,omitempty"`
	// LimitUSD and LimitTokens (input + output + cache) cap the window; set at
	// least one. Either one reached exhausts the budget.
	LimitUSD    float64 `yaml:"limitUSD,omitempty" json:"limitUSD,omitempty"`
	LimitTokens int64   `yaml:"limitTokens,omitempty" json:"limitTokens,omitempty"`
	// Action when exhausted: warn (header + metric, the request passes) or
	// enforce (HTTP 429 until the window resets). Empty means warn.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
	// AlertAt are soft thresholds as fractions of the limit (default [0.8]).
	AlertAt []float64 `yaml:"alertAt,omitempty" json:"alertAt,omitempty"`
}

// Budget scopes, windows and actions.
const (
	ScopeUser  = "user"
	ScopeGroup = "group"
	ScopeRing  = "ring"
	ScopeOrg   = "org"

	WindowDay     = "day"
	WindowWeek    = "week"
	WindowMonth   = "month"
	WindowRolling = "rolling"

	BudgetWarn    = "warn"
	BudgetEnforce = "enforce"
)

var (
	budgetScopes  = []string{ScopeUser, ScopeGroup, ScopeRing, ScopeOrg}
	budgetWindows = []string{WindowDay, WindowWeek, WindowMonth, WindowRolling}
)

// DefaultAlertAt is the soft threshold when a budget sets none.
var DefaultAlertAt = []float64{0.8}

// Mode is the action with the default (warn) applied.
func (b *Budget) Mode() string {
	if b.Action == "" {
		return BudgetWarn
	}
	return b.Action
}

// Alerts are the soft thresholds with the default applied.
func (b *Budget) Alerts() []float64 {
	if len(b.AlertAt) == 0 {
		return DefaultAlertAt
	}
	return b.AlertAt
}

// RollingPeriod is the parsed Period (0 unless the window is rolling and valid).
func (b *Budget) RollingPeriod() time.Duration {
	if b.Window != WindowRolling {
		return 0
	}
	d, err := time.ParseDuration(b.Period)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// Rolling periods are bounded so per-key buckets stay small (see internal/budget).
const (
	minRollingPeriod = time.Hour
	maxRollingPeriod = 90 * 24 * time.Hour
)

func (v *validator) budgets(g *Gateway) {
	rings := map[string]bool{}
	for _, r := range v.org.Rings {
		rings[r.Name] = true
	}
	for _, m := range sortedKeys(g.Pricing) {
		p := g.Pricing[m]
		for _, f := range []float64{p.InputPerMTok, p.OutputPerMTok, p.CacheReadPerMTok, p.CacheWritePerMTok} {
			if f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
				v.errf("gateway.pricing."+m, "prices must be finite and >= 0")
				break
			}
		}
	}
	if len(g.Budgets) == 0 {
		return
	}
	if g.Engine == "kong" || g.Engine == EngineExternal {
		v.warnf("gateway.budgets", "budgets are metered and enforced only by halo-proxy; engine %s does not apply them", g.Engine)
	}
	names := map[string]bool{}
	needPrice := false
	for i, b := range g.Budgets {
		path := fmt.Sprintf("gateway.budgets[%d]", i)
		if !nameRe.MatchString(b.Name) {
			v.errf(path+".name", "%q must match %s", b.Name, nameRe)
		} else if names[b.Name] {
			v.errf(path+".name", "duplicate budget name %q", b.Name)
		}
		names[b.Name] = true
		v.budgetEntry(path, b, rings)
		needPrice = needPrice || b.LimitUSD > 0
	}
	if needPrice {
		for _, m := range v.routedModels() {
			if _, ok := g.Pricing[m]; !ok {
				v.warnf("gateway.pricing", "no price for routed model %q: its tokens count toward limitTokens but cost $0 toward limitUSD", m)
			}
		}
	}
}

// budgetEntry checks one budget's fields (gateway.budgets and cloudAgents
// budgets share them).
func (v *validator) budgetEntry(path string, b Budget, rings map[string]bool) {
	v.oneOf(path+".scope", "scope", b.Scope, budgetScopes)
	v.oneOf(path+".window", "window", b.Window, budgetWindows)
	if b.Action != "" {
		v.oneOf(path+".action", "action", b.Action, []string{BudgetWarn, BudgetEnforce})
	}
	if b.Scope == ScopeGroup && len(b.Groups) == 0 {
		v.errf(path+".groups", "scope group needs the groups that get a counter")
	}
	for _, r := range b.Rings {
		if !rings[r] {
			v.errf(path+".rings", "ring %q not defined", r)
		}
	}
	switch {
	case b.Window == WindowRolling && b.Period == "":
		v.errf(path+".period", "rolling window needs a period, e.g. 24h")
	case b.Window == WindowRolling:
		if d, err := time.ParseDuration(b.Period); err != nil || d < minRollingPeriod || d > maxRollingPeriod {
			v.errf(path+".period", "%q must be a duration between %s and %s", b.Period, minRollingPeriod, maxRollingPeriod)
		}
	case b.Period != "":
		v.errf(path+".period", "period is only valid on window rolling")
	}
	if b.LimitUSD < 0 || math.IsNaN(b.LimitUSD) || math.IsInf(b.LimitUSD, 0) || b.LimitTokens < 0 {
		v.errf(path, "limitUSD and limitTokens must be finite and >= 0")
	} else if b.LimitUSD == 0 && b.LimitTokens == 0 {
		v.errf(path, "set limitUSD, limitTokens or both")
	}
	for j, a := range b.AlertAt {
		if !(a > 0 && a < 1) {
			v.errf(fmt.Sprintf("%s.alertAt[%d]", path, j), "%v must be in (0,1)", a)
		}
	}
}

// routedModels is every provider model id a gateway or variant route can reach, sorted.
func (v *validator) routedModels() []string {
	var out []string
	add := func(r ModelRoute) {
		for _, t := range r.Candidates() {
			if t.Model != "" && !slices.Contains(out, t.Model) {
				out = append(out, t.Model)
			}
		}
	}
	for _, r := range v.org.Gateway.Models {
		add(r)
	}
	for _, e := range v.org.Experiments {
		for _, va := range e.Variants {
			for _, r := range va.Routes {
				add(r)
			}
		}
	}
	slices.Sort(out)
	return out
}
