// Package budget meters model spend against the policy's gateway budgets
// (ADR-0017). It is shared by both sides of the design: halo-server keeps
// the authoritative counters (Ledger), and every halo-proxy replica reports
// usage to it and caches its verdicts (Client). Scope keys and windows are
// computed here once so both sides agree.
package budget

import (
	"math"
	"slices"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Principal is who a request is charged to: the verified subject (empty when
// anonymous) with its IdP groups, and the ring the gateway routed it to.
// It never comes from client-supplied headers (invariant 4).
type Principal struct {
	Subject string   `json:"subject,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Ring    string   `json:"ring,omitempty"`
}

// Charge is one counter a request is charged to.
type Charge struct {
	Budget *policy.Budget
	Key    string // "user:<id>", "group:<name>", "ring:<name>" or "org"
}

// Charges returns every counter p's requests are charged to. A budget with a
// rings or groups filter skips callers outside it; user and group scopes skip
// anonymous callers (there is no verified identity to key on).
func Charges(budgets []policy.Budget, p Principal) []Charge {
	var out []Charge
	for i := range budgets {
		b := &budgets[i]
		if len(b.Rings) > 0 && !slices.Contains(b.Rings, p.Ring) {
			continue
		}
		if b.Scope != policy.ScopeGroup && len(b.Groups) > 0 && !slices.ContainsFunc(b.Groups, func(g string) bool { return slices.Contains(p.Groups, g) }) {
			continue
		}
		switch b.Scope {
		case policy.ScopeUser:
			if p.Subject != "" {
				out = append(out, Charge{b, "user:" + p.Subject})
			}
		case policy.ScopeGroup:
			if p.Subject == "" {
				continue
			}
			for _, g := range b.Groups {
				if slices.Contains(p.Groups, g) {
					out = append(out, Charge{b, "group:" + g})
				}
			}
		case policy.ScopeRing:
			if p.Ring != "" {
				out = append(out, Charge{b, "ring:" + p.Ring})
			}
		case policy.ScopeOrg:
			out = append(out, Charge{b, "org"})
		}
	}
	return out
}

// Window returns the calendar window (UTC) containing t: its start and the
// next reset. Rolling budgets have no fixed window; see bucketSize.
func Window(b *policy.Budget, t time.Time) (start, reset time.Time) {
	t = t.UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	switch b.Window {
	case policy.WindowWeek:
		start = day.AddDate(0, 0, -((int(t.Weekday()) + 6) % 7)) // Monday
		return start, start.AddDate(0, 0, 7)
	case policy.WindowMonth:
		start = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0)
	default: // day
		return day, day.AddDate(0, 0, 1)
	}
}

// rollingBuckets is how many buckets a rolling period is split into: usage
// leaves the window one bucket at a time, so the window edge is accurate to
// period/rollingBuckets (30m for 24h) and a counter holds at most this many.
const rollingBuckets = 48

func bucketSize(period time.Duration) time.Duration {
	return max(period/rollingBuckets, time.Minute).Truncate(time.Minute)
}

// bucket is the start of the counter bucket that usage at t lands in.
func bucket(b *policy.Budget, t time.Time) time.Time {
	if p := b.RollingPeriod(); p > 0 {
		return t.UTC().Truncate(bucketSize(p))
	}
	s, _ := Window(b, t)
	return s
}

// Usage is the token usage of one model response, normalised across wire
// protocols so the four counts never overlap: Input excludes cached tokens,
// Output includes reasoning/thinking tokens.
type Usage struct {
	Input, Output, CacheRead, CacheWrite int64
}

// Tokens is every token billed for the response.
func (u Usage) Tokens() int64 { return u.Input + u.Output + u.CacheRead + u.CacheWrite }

// Cost prices u for a provider model. priced is false when the model has no
// price: its tokens still count toward token limits, but it costs $0.
func Cost(prices map[string]policy.ModelPrice, model string, u Usage) (usd float64, priced bool) {
	p, ok := prices[model]
	if !ok {
		return 0, false
	}
	cr, cw := p.CacheReadPerMTok, p.CacheWritePerMTok
	if cr == 0 {
		cr = p.InputPerMTok
	}
	if cw == 0 {
		cw = p.InputPerMTok
	}
	return (float64(u.Input)*p.InputPerMTok + float64(u.Output)*p.OutputPerMTok +
		float64(u.CacheRead)*cr + float64(u.CacheWrite)*cw) / 1e6, true
}

// Spend is accumulated usage.
type Spend struct {
	USD    float64 `json:"usd"`
	Tokens int64   `json:"tokens"`
}

func (s *Spend) add(o Spend) { s.USD += o.USD; s.Tokens += o.Tokens }

// Status is one counter's state in its current window.
type Status struct {
	Budget      string    `json:"budget"`
	Scope       string    `json:"scope"`
	Key         string    `json:"key"`
	Window      string    `json:"window"`
	Period      string    `json:"period,omitempty"`
	Action      string    `json:"action"`
	LimitUSD    float64   `json:"limitUSD,omitempty"`
	LimitTokens int64     `json:"limitTokens,omitempty"`
	SpentUSD    float64   `json:"spentUSD"`
	SpentTokens int64     `json:"spentTokens"`
	AlertAt     []float64 `json:"alertAt,omitempty"`
	// ResetAt is when the counter drops below its limit again: the next
	// calendar window, or for rolling windows when enough old usage expires.
	ResetAt time.Time `json:"resetAt"`
}

// Utilization is the larger of spent/limit over USD and tokens (0 when unlimited).
func (s Status) Utilization() float64 {
	var u float64
	if s.LimitUSD > 0 {
		u = s.SpentUSD / s.LimitUSD
	}
	if s.LimitTokens > 0 {
		u = math.Max(u, float64(s.SpentTokens)/float64(s.LimitTokens))
	}
	return u
}

// Exceeded reports whether the counter has reached a limit.
func (s Status) Exceeded() bool { return s.Utilization() >= 1 }

// Alert is the highest soft threshold the counter has crossed (0 = none).
func (s Status) Alert() float64 {
	var a float64
	u := s.Utilization()
	for _, t := range s.AlertAt {
		if u >= t && t > a {
			a = t
		}
	}
	return a
}

func statusFor(c Charge) Status {
	b := c.Budget
	return Status{Budget: b.Name, Scope: b.Scope, Key: c.Key, Window: b.Window, Period: b.Period, Action: b.Mode(),
		LimitUSD: b.LimitUSD, LimitTokens: b.LimitTokens, AlertAt: b.Alerts()}
}

func under(b *policy.Budget, s Spend) bool {
	return (b.LimitUSD <= 0 || s.USD < b.LimitUSD) && (b.LimitTokens <= 0 || s.Tokens < b.LimitTokens)
}
