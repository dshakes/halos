// Package promote turns experiment evidence into a rollout decision.
//
// Evaluate combines internal/stats with the experiment's stopping rules and
// returns promote | rollback | continue | expired. Acting on a verdict is
// deliberately asymmetric: rollback may be applied directly to the policy
// repo working tree (ApplyRollback), while promote only ever opens a PR
// (OpenPR); nothing in this package merges.
package promote

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/stats"
)

// Verdict is the decision for an experiment at this point in time.
type Verdict string

const (
	Promote  Verdict = "promote"
	Rollback Verdict = "rollback"
	Continue Verdict = "continue"
	Expired  Verdict = "expired" // budget (days/spend) exhausted without a decision
)

// Window is the experiment's observed span and spend.
type Window struct {
	Start    time.Time // zero = no data yet
	SpendUSD float64
}

// MetricSource supplies experiment evidence.
type MetricSource interface {
	// Window reports when data first appeared and total spend so far.
	Window(ctx context.Context, experiment string) (Window, error)
	// Samples returns per-unit (user) observations of a halo.* metric, by
	// variant name, and their evidence source (SourceGateway | SourceCLI |
	// SourceEval; ""
	// = unknown, treated as untrusted).
	Samples(ctx context.Context, experiment, metric string) (map[string][]float64, string, error)
}

// GuardrailReport is one guardrail's outcome.
type GuardrailReport struct {
	Metric string                `json:"metric"`
	Source string                `json:"source,omitempty"`
	Result stats.GuardrailResult `json:"result"`
}

// Report explains a verdict. JSON keys are camelCase (the halo-server verdicts format).
type Report struct {
	Verdict    Verdict `json:"verdict"`
	Reason     string  `json:"reason"`
	Control    string  `json:"control"`
	Treatment  string  `json:"treatment"`
	NControl   int     `json:"nControl"`
	NTreatment int     `json:"nTreatment"`
	// PValue and Effect (treatment - control) are for the primary metric.
	PValue     float64           `json:"pValue"`
	Effect     float64           `json:"effect"`
	Guardrails []GuardrailReport `json:"guardrails"`
	// Source is the evidence source of the metric that decided a promote or
	// rollback verdict (the failing guardrail, else the primary); "" otherwise.
	Source string `json:"source,omitempty"`
}

// tauFraction sets the mSPRT mixture sd as a fraction of the pooled metric
// sd: we expect effects around 0.2 sd. It affects power, not validity.
const tauFraction = 0.2

// Evaluate decides using the current time.
func Evaluate(ctx context.Context, exp *policy.Experiment, data MetricSource) (Report, error) {
	return EvaluateAt(ctx, exp, data, time.Now())
}

// EvaluateAt is Evaluate with an explicit clock.
//
// Order: (1) guardrails can trigger rollback once every arm has MinSamples;
// (2) exhausted MaxDays/MaxSpendUSD -> expired; (3) below MinSamples ->
// continue; (4) primary metric: significant improvement AND all guardrails
// passing -> promote, significant regression -> rollback, else continue.
// Only two-variant experiments (one control, one treatment) are supported.
//
// Guardrails use an always-valid mSPRT confidence sequence (stats.SeqGuardrail)
// with a Bonferroni-split alpha, so polling on every evaluation does not
// inflate the false-rollback rate above alpha.
func EvaluateAt(ctx context.Context, exp *policy.Experiment, data MetricSource, now time.Time) (Report, error) {
	ctl, trt, err := pickVariants(exp)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Verdict: Continue, Control: ctl, Treatment: trt}
	alpha := exp.Stopping.Alpha
	if alpha <= 0 || alpha >= 1 {
		alpha = 0.05
	}

	win, err := data.Window(ctx, exp.Name)
	if err != nil {
		return rep, fmt.Errorf("promote: window for %s: %w", exp.Name, err)
	}

	// Primary metric samples.
	pc, pt, psrc, err := arms(ctx, data, exp.Name, exp.Metrics.Primary.Metric, ctl, trt)
	if err != nil {
		return rep, err
	}
	rep.NControl, rep.NTreatment = len(pc), len(pt)
	enough := rep.NControl >= exp.Stopping.MinSamples && rep.NTreatment >= exp.Stopping.MinSamples &&
		rep.NControl >= 2 && rep.NTreatment >= 2

	// (1) guardrails.
	allPass := true
	for _, g := range exp.Metrics.Guardrails {
		gc, gt, gsrc, err := arms(ctx, data, exp.Name, g.Metric, ctl, trt)
		if err != nil {
			return rep, err
		}
		res, gerr := stats.SeqGuardrail(gc, gt, g.Direction, g.MaxRegression, alpha/float64(len(exp.Metrics.Guardrails)))
		if gerr != nil && !errors.Is(gerr, stats.ErrTooFewSamples) {
			return rep, fmt.Errorf("promote: guardrail %s: %w", g.Metric, gerr)
		}
		if len(gc) < exp.Stopping.MinSamples || len(gt) < exp.Stopping.MinSamples {
			res.Status = stats.Inconclusive
		}
		rep.Guardrails = append(rep.Guardrails, GuardrailReport{g.Metric, gsrc, res})
		if res.Status == stats.Fail {
			rep.Verdict, rep.Source, rep.Reason = Rollback, gsrc, fmt.Sprintf("guardrail %s regressed %.1f%% (limit %.1f%%)", g.Metric, 100*res.Regression, 100*g.MaxRegression)
			return rep, nil
		}
		allPass = allPass && res.Status == stats.Pass
	}

	// (2) budgets.
	if s := exp.Stopping; !win.Start.IsZero() && s.MaxDays > 0 && now.Sub(win.Start) > time.Duration(s.MaxDays)*24*time.Hour {
		rep.Verdict, rep.Reason = Expired, fmt.Sprintf("ran longer than maxDays=%d without a decision", s.MaxDays)
		return rep, nil
	} else if s.MaxSpendUSD > 0 && win.SpendUSD >= s.MaxSpendUSD {
		rep.Verdict, rep.Reason = Expired, fmt.Sprintf("spend $%.2f reached maxSpendUSD=$%.2f without a decision", win.SpendUSD, s.MaxSpendUSD)
		return rep, nil
	}

	// (3) sample floor.
	if !enough {
		rep.Reason = fmt.Sprintf("need %d samples per arm, have %d/%d", exp.Stopping.MinSamples, rep.NControl, rep.NTreatment)
		return rep, nil
	}

	// (4) primary metric.
	effect, p, err := primary(exp.Stopping.Method, pc, pt, alpha)
	if err != nil {
		return rep, fmt.Errorf("promote: primary %s: %w", exp.Metrics.Primary.Metric, err)
	}
	rep.Effect, rep.PValue = effect, p
	improved := (exp.Metrics.Primary.Direction == "increase") == (effect > 0)
	switch {
	case p > alpha:
		rep.Reason = fmt.Sprintf("primary not significant (p=%.4f, alpha=%.3f)", p, alpha)
	case !improved:
		rep.Verdict, rep.Source, rep.Reason = Rollback, psrc, fmt.Sprintf("primary %s significantly worse (effect %+.4g, p=%.4f)", exp.Metrics.Primary.Metric, effect, p)
	case !allPass:
		rep.Reason = "primary improved but guardrails not yet all passing"
	case psrc == SourceEval:
		// ADR-0004: judge scores come from single-turn shadow pairs, which say
		// nothing about multi-step agent quality. They can roll back, never promote.
		rep.Reason = fmt.Sprintf("primary %s improved, but it is shadow judge evidence; promote needs gateway canary evidence (ADR-0004)", exp.Metrics.Primary.Metric)
	default:
		rep.Verdict, rep.Source, rep.Reason = Promote, psrc, fmt.Sprintf("primary %s improved (effect %+.4g, p=%.4f) and guardrails pass", exp.Metrics.Primary.Metric, effect, p)
	}
	return rep, nil
}

func primary(method string, c, t []float64, alpha float64) (effect, p float64, err error) {
	switch method {
	case "fixed":
		r, err := stats.Welch(c, t, alpha)
		return r.Effect, r.PValue, err
	case "msprt", "":
		// Stateless evaluation of the mixture LR at the current look is still
		// valid (P(any look crosses) >= P(this look crosses)); just conservative
		// compared to keeping a running minimum across polls.
		v := pooledVar(c, t)
		if v == 0 {
			return 0, 1, nil
		}
		r := stats.NewMSPRT(alpha, tauFraction*tauFraction*v).ObserveMeans(c, t)
		return r.Effect, r.PValue, nil
	}
	return 0, 0, fmt.Errorf("unknown stopping method %q", method)
}

func pooledVar(a, b []float64) float64 {
	all := append(append([]float64{}, a...), b...)
	m := 0.0
	for _, x := range all {
		m += x
	}
	m /= float64(len(all))
	s := 0.0
	for _, x := range all {
		s += (x - m) * (x - m)
	}
	v := s / float64(len(all)-1)
	if math.IsNaN(v) {
		return 0
	}
	return v
}

func pickVariants(exp *policy.Experiment) (ctl, trt string, err error) {
	if exp == nil || len(exp.Variants) != 2 {
		return "", "", errors.New("promote: only experiments with exactly two variants are supported")
	}
	for _, v := range exp.Variants {
		if v.Control {
			ctl = v.Name
		} else {
			trt = v.Name
		}
	}
	if ctl == "" || trt == "" {
		return "", "", fmt.Errorf("promote: experiment %s needs exactly one control variant", exp.Name)
	}
	return ctl, trt, nil
}

func arms(ctx context.Context, data MetricSource, exp, metric, ctl, trt string) (c, t []float64, source string, err error) {
	m, source, err := data.Samples(ctx, exp, metric)
	if err != nil {
		return nil, nil, "", fmt.Errorf("promote: samples %s/%s: %w", exp, metric, err)
	}
	return m[ctl], m[trt], source, nil
}
