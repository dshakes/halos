package policy

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// KindRollout is a phased rollout of one change (see Rollout).
const KindRollout Kind = "Rollout"

// LabelGeneratedBy marks a document a tool generated for one owner, with the
// value GeneratedFor(rollout): `halo model switch --canary` labels the
// gateway.yaml override it writes, and the rollout's completion deletes it.
const LabelGeneratedBy = "halos.dev/generated-by"

// GeneratedFor is the LabelGeneratedBy value of documents generated for rollout.
func GeneratedFor(rollout string) string { return "rollout/" + rollout }

// RolloutStrategy is how one step exposes the change.
type RolloutStrategy string

const (
	// StrategyProgressive moves Step.Ring's release pointer to Change.Release (client axis).
	StrategyProgressive RolloutStrategy = "progressive"
	// StrategyCanary gives Percent of the backing experiment's users the treatment.
	StrategyCanary RolloutStrategy = "canary"
	// StrategyBlueGreen switches Step.Ring from the pre-staged standby
	// Change.Release atomically; rollback switches back to Baseline.Release.
	StrategyBlueGreen RolloutStrategy = "blue-green"
	// StrategyDarkLaunch mirrors Percent of requests to the treatment via
	// halo-shadow; no user sees it (traffic axis).
	StrategyDarkLaunch RolloutStrategy = "dark-launch"
	// StrategyHoldout keeps Percent of users on control for Bake to measure
	// the long-term effect; everyone else gets the treatment.
	StrategyHoldout RolloutStrategy = "holdout"
)

// Rollout statuses. Only active rollouts are driven by the controller.
const (
	RolloutDraft     = "draft"
	RolloutActive    = "active"
	RolloutPaused    = "paused"
	RolloutAborted   = "aborted"
	RolloutCompleted = "completed"
)

// Rollout describes how ONE change rolls out: ordered steps, each with a
// target ring and percent, a minimum bake, gates, and a failure action.
//
// Exposure inside a ring is carried by the backing Experiment (its control and
// treatment weights, or its shadow sample rate), so assignment stays in
// internal/assign and the existing kill switch is the traffic-axis rollback.
// Ring-wide steps move Ring.release. Every edit is proposed as a PR.
type Rollout struct {
	Meta `yaml:",inline"`
	Axis Axis `yaml:"axis" json:"axis"`
	// Status: draft | active | paused | aborted | completed ("" = draft).
	Status string `yaml:"status,omitempty" json:"status,omitempty"`
	// Step is the live step's name, set by merged advance PRs ("" = not started).
	Step string `yaml:"step,omitempty" json:"step,omitempty"`
	// Experiment is the backing two-arm experiment: exposure, evidence, kill
	// switch. Optional when every step is progressive or blue-green.
	Experiment string          `yaml:"experiment,omitempty" json:"experiment,omitempty"`
	Change     RolloutChange   `yaml:"change" json:"change"`
	Baseline   RolloutBaseline `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	Steps      []RolloutStep   `yaml:"steps" json:"steps"`
}

// RolloutChange is what rolls out.
type RolloutChange struct {
	// Client axis: the release digest ring pointers move to, and its label.
	Release string `yaml:"release,omitempty" json:"release,omitempty"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	// Traffic axis: the gateway model alias whose route becomes the treatment
	// variant's route for it when the rollout completes.
	Alias string `yaml:"alias,omitempty" json:"alias,omitempty"`
}

// RolloutBaseline is the known-good state a rollback returns to.
type RolloutBaseline struct {
	// Release is the client-axis switch-back target (required with ring-wide steps).
	Release string `yaml:"release,omitempty" json:"release,omitempty"`
}

// RolloutStep is one phase of a rollout.
type RolloutStep struct {
	Name     string          `yaml:"name" json:"name"`
	Strategy RolloutStrategy `yaml:"strategy" json:"strategy"`
	// Ring is required for progressive/blue-green. Percent steps expose the
	// backing experiment's rings; Ring, if set, must be one of them.
	Ring string `yaml:"ring,omitempty" json:"ring,omitempty"`
	// Percent: canary = treatment share; holdout = share kept on control;
	// dark-launch = share of requests mirrored; progressive/blue-green = 100.
	Percent float64 `yaml:"percent,omitempty" json:"percent,omitempty"`
	// Bake is the minimum time at this step: Go duration or N"d" (e.g. "14d").
	Bake       string       `yaml:"bake,omitempty" json:"bake,omitempty"`
	MinSamples int          `yaml:"minSamples,omitempty" json:"minSamples,omitempty"`
	Gates      RolloutGates `yaml:"gates,omitempty" json:"gates,omitempty"`
	// OnFailure: rollback | pause (default rollback).
	OnFailure string `yaml:"onFailure,omitempty" json:"onFailure,omitempty"`
}

// RolloutGates must all pass before a step advances.
type RolloutGates struct {
	// Guardrails compare the backing experiment's arms (internal/stats
	// sequential test). A breach triggers OnFailure at any time.
	Guardrails []MetricGoal `yaml:"guardrails,omitempty" json:"guardrails,omitempty"`
	// Scorecard reads a `halo eval run --output json` scorecard.
	Scorecard *ScorecardGate `yaml:"scorecard,omitempty" json:"scorecard,omitempty"`
	// Approval holds the step until a human advances it (`halo rollout advance`).
	Approval bool `yaml:"approval,omitempty" json:"approval,omitempty"`
}

// ScorecardGate passes when Variant's eval scorecard clears the bars.
type ScorecardGate struct {
	// File is the scorecard JSON, relative to the policy dir.
	File    string `yaml:"file" json:"file"`
	Variant string `yaml:"variant" json:"variant"`
	// MinPass1 is the absolute pass@1 floor (0 = none).
	MinPass1 float64 `yaml:"minPass1,omitempty" json:"minPass1,omitempty"`
	// MaxRegression is the largest allowed pass-rate drop vs the scorecard's
	// control (0.02 = 2pp); a significantly worse comparison always fails.
	MaxRegression float64 `yaml:"maxRegression,omitempty" json:"maxRegression,omitempty"`
}

// EffectivePercent is Percent with the ring-wide default (100) applied.
func (s RolloutStep) EffectivePercent() float64 {
	if s.Percent == 0 && (s.Strategy == StrategyProgressive || s.Strategy == StrategyBlueGreen) {
		return 100
	}
	return s.Percent
}

// RingWide reports whether the step moves a ring pointer instead of experiment weights.
func (s RolloutStep) RingWide() bool {
	return s.Strategy == StrategyProgressive || s.Strategy == StrategyBlueGreen
}

// EffectiveGuardrails is what step s is judged on: the backing experiment's
// guardrails, each overridden by the step's guardrail on the same metric, then
// the step's other guardrails. An active rollout owns its experiment (the
// experiment loop skips it), so dropping the experiment's guardrails here
// would silently disable their auto-rollback. Ring-wide steps have no control
// arm and keep only their own (none: validated).
func (s RolloutStep) EffectiveGuardrails(exp *Experiment) []MetricGoal {
	if exp == nil || s.RingWide() {
		return s.Gates.Guardrails
	}
	out := make([]MetricGoal, 0, len(exp.Metrics.Guardrails)+len(s.Gates.Guardrails))
	for _, g := range exp.Metrics.Guardrails {
		if m, ok := LookupMetric(g.Metric); ok && m.ShadowOnly() && s.Strategy != StrategyDarkLaunch {
			continue // graded on halo-shadow pairs, which only a dark-launch step produces
		}
		if i := slices.IndexFunc(s.Gates.Guardrails, func(o MetricGoal) bool { return o.Metric == g.Metric }); i >= 0 {
			g = s.Gates.Guardrails[i]
		}
		out = append(out, g)
	}
	for _, g := range s.Gates.Guardrails {
		if !slices.ContainsFunc(exp.Metrics.Guardrails, func(o MetricGoal) bool { return o.Metric == g.Metric }) {
			out = append(out, g)
		}
	}
	return out
}

// FailureAction is OnFailure with its default.
func (s RolloutStep) FailureAction() string {
	if s.OnFailure == "" {
		return "rollback"
	}
	return s.OnFailure
}

// BakeDuration parses Bake ("" = 0).
func (s RolloutStep) BakeDuration() (time.Duration, error) { return ParseBake(s.Bake) }

// ParseBake parses a Go duration or a whole number of days ("14d").
func ParseBake(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bake %q: want a duration like 30m, 24h or 14d", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bake %q: want a duration like 30m, 24h or 14d", s)
	}
	return d, nil
}

// StepIndex returns the index of the named step, or -1.
func (r *Rollout) StepIndex(name string) int {
	return slices.IndexFunc(r.Steps, func(s RolloutStep) bool { return s.Name == name })
}

// EffectiveStatus is Status with the draft default.
func (r *Rollout) EffectiveStatus() string {
	if r.Status == "" {
		return RolloutDraft
	}
	return r.Status
}

// Arms returns the backing experiment's control and treatment variants.
func (e *Experiment) Arms() (control, treatment *Variant, ok bool) {
	if len(e.Variants) != 2 {
		return nil, nil, false
	}
	for i := range e.Variants {
		if e.Variants[i].Control {
			control = &e.Variants[i]
		} else {
			treatment = &e.Variants[i]
		}
	}
	return control, treatment, control != nil && treatment != nil
}

var (
	rolloutStatus     = []string{RolloutDraft, RolloutActive, RolloutPaused, RolloutAborted, RolloutCompleted}
	rolloutStrategies = []string{string(StrategyProgressive), string(StrategyCanary), string(StrategyBlueGreen), string(StrategyDarkLaunch), string(StrategyHoldout)}
	failureActions    = []string{"rollback", "pause"}
)

func (v *validator) rollouts() {
	names := map[string]bool{}
	byExp := map[string]string{}
	for _, r := range v.org.Rollouts {
		p := "rollouts[" + r.Name + "]"
		if names[r.Name] {
			v.errf(p, "duplicate rollout name")
		}
		names[r.Name] = true
		if !ValidName(r.Name) {
			v.errf(p+".name", "%q must match %s", r.Name, nameRe)
		}
		v.oneOf(p+".axis", "axis", string(r.Axis), []string{string(AxisClient), string(AxisTraffic)})
		v.oneOf(p+".status", "status", r.EffectiveStatus(), rolloutStatus)
		if r.Step != "" && r.StepIndex(r.Step) < 0 {
			v.errf(p+".step", "step %q is not one of steps", r.Step)
		}
		if prev, dup := byExp[r.Experiment]; dup && r.Experiment != "" {
			v.errf(p+".experiment", "experiment %q already backs rollout %q", r.Experiment, prev)
		}
		byExp[r.Experiment] = r.Name
		exp := v.rolloutExperiment(p, r)
		v.rolloutChange(p, r, exp)
		if len(r.Steps) == 0 {
			v.errf(p+".steps", "at least one step required")
		}
		v.rolloutSteps(p, r, exp)
	}
}

func (v *validator) rolloutExperiment(p string, r *Rollout) *Experiment {
	if r.Experiment == "" {
		if r.Axis == AxisTraffic || slices.ContainsFunc(r.Steps, func(s RolloutStep) bool { return !s.RingWide() }) {
			v.errf(p+".experiment", "a backing experiment is required unless every step is progressive or blue-green")
		}
		return nil
	}
	i := slices.IndexFunc(v.org.Experiments, func(e *Experiment) bool { return e.Name == r.Experiment })
	if i < 0 {
		v.errf(p+".experiment", "experiment %q not defined", r.Experiment)
		return nil
	}
	e := v.org.Experiments[i]
	if e.Axis != r.Axis {
		v.errf(p+".experiment", "experiment %q has axis %q, rollout has %q", e.Name, e.Axis, r.Axis)
	}
	if _, _, ok := e.Arms(); !ok {
		v.errf(p+".experiment", "experiment %q needs exactly two variants, one of them control", e.Name)
		return nil
	}
	return e
}

func (v *validator) rolloutChange(p string, r *Rollout, exp *Experiment) {
	switch r.Axis {
	case AxisClient:
		if r.Change.Release == "" {
			v.errf(p+".change.release", "client-axis rollouts need the release digest to roll out")
		}
		if r.Change.Alias != "" {
			v.errf(p+".change.alias", "alias is for traffic-axis rollouts")
		}
		if !slices.ContainsFunc(r.Steps, RolloutStep.RingWide) {
			v.errf(p+".steps", "client-axis rollouts need a progressive or blue-green step (nothing else moves a ring to the release)")
		}
	case AxisTraffic:
		if r.Change.Alias == "" {
			v.errf(p+".change.alias", "traffic-axis rollouts need the model alias to re-route")
		} else if g := v.org.Gateway; g != nil {
			if _, ok := g.Models[r.Change.Alias]; !ok {
				v.errf(p+".change.alias", "alias %q not defined in gateway.models", r.Change.Alias)
			}
		}
		if exp != nil {
			if _, t, _ := exp.Arms(); len(t.Routes[r.Change.Alias].Candidates()) == 0 {
				v.errf(p+".change.alias", "treatment variant %q of experiment %q has no route for alias %q", t.Name, exp.Name, r.Change.Alias)
			}
		}
		if r.Change.Release != "" || r.Baseline.Release != "" {
			v.errf(p+".change.release", "release pointers are for client-axis rollouts")
		}
	}
}

func (v *validator) rolloutSteps(p string, r *Rollout, exp *Experiment) {
	rings := map[string]bool{}
	for _, rg := range v.org.Rings {
		rings[rg.Name] = true
	}
	seen := map[string]bool{}
	lastCanary := 0.0
	for i, s := range r.Steps {
		sp := fmt.Sprintf("%s.steps[%d]", p, i)
		if !ValidName(s.Name) || seen[s.Name] {
			v.errf(sp+".name", "step name %q invalid or duplicate", s.Name)
		}
		seen[s.Name] = true
		v.oneOf(sp+".strategy", "strategy", string(s.Strategy), rolloutStrategies)
		v.oneOf(sp+".onFailure", "onFailure", s.FailureAction(), failureActions)
		if !rings[s.Ring] && (s.Ring != "" || s.RingWide()) {
			v.errf(sp+".ring", "ring %q not defined", s.Ring)
		}
		if _, err := s.BakeDuration(); err != nil {
			v.errf(sp+".bake", "%v", err)
		}
		if s.MinSamples < 0 {
			v.errf(sp+".minSamples", "must be >= 0")
		}
		pct := s.EffectivePercent()
		switch {
		case s.RingWide():
			if r.Axis != AxisClient {
				v.errf(sp+".strategy", "%s moves a ring's release pointer: client axis only (traffic-axis rollouts re-route on completion)", s.Strategy)
			}
			if pct != 100 {
				v.errf(sp+".percent", "%s steps cover the whole ring; percent must be unset or 100", s.Strategy)
			}
			if r.Baseline.Release == "" {
				v.errf(p+".baseline.release", "%s steps need baseline.release to switch back to", s.Strategy)
			}
			if len(s.Gates.Guardrails) > 0 || s.MinSamples > 0 {
				v.errf(sp+".gates", "%s steps have no control arm: metric guardrails and minSamples need a canary or holdout step", s.Strategy)
			}
		default:
			if s.Strategy == StrategyDarkLaunch && r.Axis != AxisTraffic {
				v.errf(sp+".strategy", "dark-launch mirrors gateway traffic: traffic axis only")
			}
			// Both arms need users; only a mirror may take every request.
			if pct <= 0 || pct > 100 || pct == 100 && s.Strategy != StrategyDarkLaunch {
				v.errf(sp+".percent", "%v out of range for %s", pct, s.Strategy)
			}
			if exp != nil && s.Ring != "" && !slices.Contains(exp.Rings, s.Ring) {
				v.errf(sp+".ring", "ring %q is not one of experiment %q's rings %v", s.Ring, exp.Name, exp.Rings)
			} else if exp != nil && s.Ring != "" && len(exp.Rings) > 1 {
				v.issues = append(v.issues, Issue{SeverityWarning, sp + ".ring", fmt.Sprintf("percent applies to every ring of experiment %q %v, not only %q; omit ring or narrow the experiment", exp.Name, exp.Rings, s.Ring)})
			}
			if (s.Strategy == StrategyCanary || s.Strategy == StrategyHoldout) && exp != nil && len(s.EffectiveGuardrails(exp)) == 0 {
				v.errf(sp+".gates.guardrails", "%s step exposes users with no guardrails (neither the step nor experiment %q has any): nothing could auto-roll it back", s.Strategy, exp.Name)
			}
			if s.Strategy == StrategyCanary {
				if pct < lastCanary {
					v.errf(sp+".percent", "canary percent %v below the earlier %v: users would flip back to control", pct, lastCanary)
				}
				lastCanary = pct
			}
		}
		for j, g := range s.Gates.Guardrails {
			gp := fmt.Sprintf("%s.gates.guardrails[%d]", sp, j)
			v.metric(gp, g)
			if m, ok := LookupMetric(g.Metric); ok && m.ShadowOnly() && s.Strategy != StrategyDarkLaunch {
				v.errf(gp+".metric", "%s is graded on halo-shadow pairs: only a dark-launch step (which runs the experiment as shadow) produces them", g.Metric)
			}
			if g.MaxRegression < 0 {
				v.errf(gp+".maxRegression", "must be >= 0")
			}
		}
		if sc := s.Gates.Scorecard; sc != nil {
			gp := sp + ".gates.scorecard"
			if c := path.Clean(sc.File); sc.File == "" || path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") || path.Ext(c) != ".json" {
				v.errf(gp+".file", "%q must be a .json path inside the policy repo", sc.File)
			}
			if sc.Variant == "" {
				v.errf(gp+".variant", "variant is required")
			}
			if sc.MinPass1 < 0 || sc.MinPass1 > 1 {
				v.errf(gp+".minPass1", "%v must be in [0,1]", sc.MinPass1)
			}
			if sc.MaxRegression < 0 || sc.MaxRegression > 1 {
				v.errf(gp+".maxRegression", "%v must be in [0,1]", sc.MaxRegression)
			}
		}
	}
}
