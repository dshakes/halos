package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// BudgetConfig points at halo-server's budget counters (ADR-0017).
type BudgetConfig struct {
	URL       string `yaml:"url"`       // https://halo-server/api/v1/gateway/budget; empty disables metering and enforcement
	TokenFile string `yaml:"tokenFile"` // halo-server --gateway-token-file value
	// CacheTTL is how long a principal's verdict is reused (default 30s).
	CacheTTL time.Duration `yaml:"cacheTTL"`
	// Grace is how long the last verdict keeps serving while halo-server is
	// unreachable (default 15m); after it the verdict is unknown.
	Grace time.Duration `yaml:"grace"`
	// FlushInterval is how often usage is reported (default 5s).
	FlushInterval time.Duration `yaml:"flushInterval"`
	// FailMode decides an unknown verdict for callers under an enforce budget:
	// open (default) lets the request through and counts it; closed answers 503.
	FailMode string `yaml:"failMode"`
	// AllowInsecureInCluster permits plain http to a non-loopback host.
	AllowInsecureInCluster bool `yaml:"allowInsecureInCluster"`
}

// Budget fail modes.
const (
	failOpen   = "open"
	failClosed = "closed"
)

// unknownRetry is the Retry-After of a fail-closed 503.
const unknownRetry = 30 * time.Second

// build returns nil when budgets are not configured.
func (c BudgetConfig) build(log *slog.Logger) (*gateway.BudgetClient, error) {
	if c.FailMode != "" && c.FailMode != failOpen && c.FailMode != failClosed {
		return nil, fmt.Errorf("halo-proxy: budgets.failMode %q must be open or closed", c.FailMode)
	}
	if c.URL == "" {
		if c.TokenFile != "" {
			return nil, fmt.Errorf("halo-proxy: budgets.url is required when budgets.tokenFile is set")
		}
		return nil, nil
	}
	if c.TokenFile == "" {
		return nil, fmt.Errorf("halo-proxy: budgets needs tokenFile")
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: budgets.tokenFile: %w", err)
	}
	bc, err := gateway.NewBudgetClient(c.URL, strings.TrimSpace(string(tok)), c.CacheTTL, c.Grace, c.FlushInterval, log, c.AllowInsecureInCluster)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: %w", err)
	}
	return bc, nil
}

// budgetMeter carries what a metered request needs once its response ends.
type budgetMeter struct {
	principal budget.Principal
	proto     string
	model     string // planned provider model; the served attempt's wins
	prices    map[string]policy.ModelPrice
}

// budgetGate checks the caller's budgets before a model call. It returns the
// meter that charges the response (nil = not metered), notes for the request
// log, and the refusal to answer instead of forwarding, if any. h is the
// client response header: warn and alert states are reported there.
func (p *Proxy) budgetGate(ctx context.Context, org *policy.Org, sub *policy.Subject, ring, proto, model string, h http.Header) (*budgetMeter, []string, *gateway.Rejection) {
	if org == nil || org.Gateway == nil || len(org.Gateway.Budgets) == 0 {
		return nil, nil, nil
	}
	if p.bc == nil {
		p.budgetOff.Do(func() {
			p.log.Warn("policy defines gateway budgets but budgets.url is not set: budgets are neither metered nor enforced")
		})
		return nil, nil, nil
	}
	pr := budget.Principal{Ring: ring} // identity only from the verified subject (invariant 4)
	if sub != nil {
		pr.Subject, pr.Groups = sub.ID, sub.Groups
	}
	charges := budget.Charges(org.Gateway.Budgets, pr)
	if len(charges) == 0 {
		return nil, nil, nil
	}
	meter := &budgetMeter{principal: pr, proto: proto, model: model, prices: org.Gateway.Pricing}
	st, known := p.bc.Check(ctx, pr)
	if !known {
		for _, c := range charges {
			p.m.budget(c.Budget.Name, "unknown")
		}
		if p.cfg.Budgets.FailMode == failClosed && slices.ContainsFunc(charges, func(c budget.Charge) bool { return c.Budget.Mode() == policy.BudgetEnforce }) {
			return nil, []string{"budget unknown: fail closed"}, &gateway.Rejection{Status: http.StatusServiceUnavailable, Protocol: proto, RetryAfter: unknownRetry,
				Message: "halos: your model budget cannot be checked right now (the Halos control plane is unreachable). Retry shortly."}
		}
		return meter, []string{"budget unknown"}, nil
	}
	now := p.bc.Time()
	var notes []string
	var rej *gateway.Rejection
	for _, s := range st {
		outcome := "ok"
		switch {
		case s.Exceeded() && s.Action == policy.BudgetEnforce:
			outcome = "refused"
			if wait := s.ResetAt.Sub(now); rej == nil || wait > rej.RetryAfter {
				rej = &gateway.Rejection{Status: http.StatusTooManyRequests, Protocol: proto, RetryAfter: max(wait, time.Second), Message: exhausted(s)}
			}
		case s.Exceeded():
			outcome = "exceeded"
		case s.Alert() > 0:
			outcome = "alert"
		}
		p.m.budget(s.Budget, outcome)
		if outcome != "ok" {
			h.Add("X-Halo-Budget", fmt.Sprintf("%s; scope=%s; used=%.0f%%; state=%s; reset=%s", s.Budget, s.Scope, 100*s.Utilization(), outcome, s.ResetAt.UTC().Format(time.RFC3339)))
			notes = append(notes, fmt.Sprintf("budget %s %s %.0f%%", s.Budget, outcome, 100*s.Utilization()))
		}
	}
	if rej != nil {
		return nil, notes, rej
	}
	return meter, notes, nil
}

// exhausted is what the developer's CLI shows on a 429.
func exhausted(s budget.Status) string {
	var used []string
	if s.LimitUSD > 0 {
		used = append(used, fmt.Sprintf("$%.2f of $%.2f", s.SpentUSD, s.LimitUSD))
	}
	if s.LimitTokens > 0 {
		used = append(used, fmt.Sprintf("%d of %d tokens", s.SpentTokens, s.LimitTokens))
	}
	window := s.Window
	if s.Period != "" {
		window = "rolling " + s.Period
	}
	return fmt.Sprintf("halos: model budget %q (%s, %s) is used up: %s. It resets at %s. Ask your Halos admin if you need more.",
		s.Budget, s.Scope, window, strings.Join(used, ", "), s.ResetAt.UTC().Format(time.RFC3339))
}

// meterResponse wraps a successful model response so its usage is charged when the body ends.
func (p *Proxy) meterResponse(resp *http.Response, rc *routeCtx) {
	m := rc.budget
	if m == nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
		return
	}
	model := m.model
	if rc.served != nil {
		model = rc.served.model
	}
	resp.Body = gateway.UsageTap(m.proto, resp.Header.Get("Content-Type"), resp.Body, func(u budget.Usage, ok bool) {
		if !ok {
			p.m.budgetResponse("no_usage", 0, u)
			return
		}
		usd, priced := budget.Cost(m.prices, model, u)
		outcome := "metered"
		if !priced {
			outcome = "unpriced"
		}
		p.m.budgetResponse(outcome, usd, u)
		p.bc.Record(m.principal, budget.Spend{USD: usd, Tokens: u.Tokens()}, p.bc.Time())
	})
}
