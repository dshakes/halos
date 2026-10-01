package rollout

import (
	"fmt"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// TimelineStep is one row of a rollout plan.
type TimelineStep struct {
	Index      int      `json:"index"`
	Name       string   `json:"name"`
	Strategy   string   `json:"strategy"`
	Ring       string   `json:"ring"`
	Percent    float64  `json:"percent"`
	Exposure   string   `json:"exposure"`
	Bake       string   `json:"bake,omitempty"`
	MinSamples int      `json:"minSamples,omitempty"`
	Gates      []string `json:"gates"`
	OnFailure  string   `json:"onFailure"`
	// EarliestStart is the sum of earlier bakes: the soonest the step can be
	// live if every gate passes on time and every PR merges at once.
	EarliestStart string `json:"earliestStart"`
	Live          bool   `json:"live,omitempty"`
}

// Timeline is a rollout's plan for humans.
type Timeline struct {
	Rollout    string         `json:"rollout"`
	Axis       string         `json:"axis"`
	Status     string         `json:"status"`
	Experiment string         `json:"experiment"`
	Change     string         `json:"change"`
	Steps      []TimelineStep `json:"steps"`
	// MinDuration is the sum of all bakes: the soonest completion.
	MinDuration string `json:"minDuration"`
}

// Days renders d as "3d4h" style (time.Duration stops at hours).
func Days(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	s := ""
	for _, u := range []struct {
		d time.Duration
		n string
	}{{24 * time.Hour, "d"}, {time.Hour, "h"}, {time.Minute, "m"}} {
		if n := d / u.d; n > 0 {
			s += fmt.Sprintf("%d%s", n, u.n)
			d -= n * u.d
		}
	}
	if s == "" {
		return d.String()
	}
	return s
}

// ChangeSummary describes what r rolls out.
func ChangeSummary(r *policy.Rollout) string {
	if r.Axis == policy.AxisTraffic {
		return "gateway alias " + r.Change.Alias + " -> treatment route of experiment " + r.Experiment
	}
	s := "release " + short(r.Change.Release)
	if r.Change.Version != "" {
		s = r.Change.Version + " (" + short(r.Change.Release) + ")"
	}
	if r.Baseline.Release != "" {
		s += ", baseline " + short(r.Baseline.Release)
	}
	return s
}

func short(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

// StepRings is the population step s exposes: its ring, or for percent
// steps without one, the backing experiment's rings.
func StepRings(org *policy.Org, r *policy.Rollout, s policy.RolloutStep) string {
	if s.Ring != "" || s.RingWide() {
		return s.Ring
	}
	if e := findExp(org, r.Experiment); e != nil {
		return strings.Join(e.Rings, ",")
	}
	return "?"
}

// Exposure describes what step s does to users.
func Exposure(org *policy.Org, r *policy.Rollout, s policy.RolloutStep) string {
	p, rings := s.EffectivePercent(), StepRings(org, r, s)
	switch s.Strategy {
	case policy.StrategyCanary:
		return fmt.Sprintf("%g%% of %s on treatment", p, rings)
	case policy.StrategyHoldout:
		return fmt.Sprintf("%g%% of %s held on control", p, rings)
	case policy.StrategyDarkLaunch:
		return fmt.Sprintf("%g%% of %s requests mirrored, none served", p, rings)
	case policy.StrategyBlueGreen:
		return fmt.Sprintf("%s switches to standby %s", s.Ring, short(r.Change.Release))
	default:
		return fmt.Sprintf("%s -> %s", s.Ring, short(r.Change.Release))
	}
}

// GateSummary lists step s's gates compactly.
func GateSummary(s policy.RolloutStep) []string {
	g := []string{}
	for _, m := range s.Gates.Guardrails {
		g = append(g, fmt.Sprintf("%s<=%g%%", strings.TrimPrefix(m.Metric, "halo."), 100*m.MaxRegression))
	}
	if sc := s.Gates.Scorecard; sc != nil {
		g = append(g, "eval:"+sc.Variant)
	}
	if s.Gates.Approval {
		g = append(g, "approval")
	}
	return g
}

// BuildTimeline lays out r's steps with their earliest start.
func BuildTimeline(org *policy.Org, r *policy.Rollout) Timeline {
	t := Timeline{Rollout: r.Name, Axis: string(r.Axis), Status: r.EffectiveStatus(), Experiment: r.Experiment,
		Change: ChangeSummary(r), Steps: []TimelineStep{}}
	var at time.Duration
	for i, s := range r.Steps {
		bake, _ := s.BakeDuration()
		t.Steps = append(t.Steps, TimelineStep{
			Index: i, Name: s.Name, Strategy: string(s.Strategy), Ring: StepRings(org, r, s), Percent: s.EffectivePercent(),
			Exposure: Exposure(org, r, s), Bake: s.Bake, MinSamples: s.MinSamples, Gates: GateSummary(s),
			OnFailure: s.FailureAction(), EarliestStart: "T+" + Days(at), Live: r.Step == s.Name,
		})
		at += bake
	}
	t.MinDuration = Days(at)
	return t
}
