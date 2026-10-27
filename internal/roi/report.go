package roi

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/stats"
)

// Designs: what a report may claim.
const (
	// DesignRandomized: arms are an experiment's variants, assigned by hash.
	// Differences estimate causal (intent-to-treat) effects.
	DesignRandomized = "randomized"
	// DesignObservational: arms are rings. Membership is chosen (users,
	// groups, opt-in, rollout order), so differences are associations.
	DesignObservational = "observational"
)

// Effect states.
const (
	StateSignificant        = "significant"          // CI excludes 0
	StateNoDetectableEffect = "no_detectable_effect" // CI includes 0 and the study could have seen an effect of MDE
	StateInsufficientPower  = "insufficient_power"   // CI includes 0 and the minimum detectable effect is above MDE
	StateInsufficientData   = "insufficient_data"    // fewer than MinDevelopers per arm
)

// Report statuses.
const (
	StatusOK               = "ok"
	StatusSRM              = "srm" // sample ratio mismatch: do not trust the effects
	StatusInsufficientData = "insufficient_data"
)

// Metric names.
const (
	MetricCycleTime     = "pr_cycle_time_hours"
	MetricThroughput    = "merged_prs_per_dev_week"
	MetricReviewRounds  = "review_rounds_per_pr"
	MetricChangeFailure = "change_failure_rate"
	MetricSize          = "lines_changed_per_pr"
)

// metric is one outcome as a per-developer ratio cluster.
type metric struct {
	name, better string // better: decrease | increase | "" (descriptive)
	// cluster returns the developer's Num/Den over prs (opened in the window
	// and merged before end); ok false leaves the developer out.
	cluster func(prs []PR, end time.Time, weeks float64) (stats.Cluster, bool)
}

func perMerged(f func(PR) float64) func([]PR, time.Time, float64) (stats.Cluster, bool) {
	return func(prs []PR, end time.Time, _ float64) (stats.Cluster, bool) {
		var c stats.Cluster
		for _, p := range prs {
			if p.merged(end) {
				c.Num += f(p)
				c.Den++
			}
		}
		return c, c.Den > 0
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

var metrics = []metric{
	{MetricCycleTime, "decrease", perMerged(func(p PR) float64 { return p.MergedAt.Sub(p.OpenedAt).Hours() })},
	{MetricThroughput, "increase", func(prs []PR, end time.Time, weeks float64) (stats.Cluster, bool) {
		c := stats.Cluster{Den: weeks}
		for _, p := range prs {
			c.Num += b2f(p.merged(end))
		}
		return c, true // every rostered developer in the arm, active or not
	}},
	{MetricReviewRounds, "decrease", perMerged(func(p PR) float64 { return float64(p.ReviewRounds) })},
	{MetricChangeFailure, "decrease", perMerged(func(p PR) float64 { return b2f(p.ChangeFailure) })},
	{MetricSize, "", perMerged(func(p PR) float64 { return float64(p.Additions + p.Deletions) })},
}

// Options selects the arms and the window.
type Options struct {
	Org *policy.Org
	// Experiment (randomized) or Rings (observational; the first is the
	// baseline); exactly one.
	Experiment *policy.Experiment
	Rings      []string
	From, To   time.Time
	// Slices splits the window for the novelty check (default 3; < 2 off).
	Slices int
	// MDE is the relative effect the study must be able to detect for a null
	// result to count as "no detectable effect" (default 0.10).
	MDE float64
	// Alpha for CIs (default 0.05); SRMAlpha for the SRM test (default 0.001).
	Alpha, SRMAlpha float64
	// MinDevelopers per arm before an effect is estimated (default 10).
	MinDevelopers int
	Iters         int    // bootstrap resamples (default 2000)
	Seed          uint64 // bootstrap seed (default 1)
}

func (o *Options) defaults() {
	if o.Slices == 0 {
		o.Slices = 3
	}
	if o.MDE <= 0 {
		o.MDE = 0.10
	}
	if o.Alpha <= 0 || o.Alpha >= 1 {
		o.Alpha = 0.05
	}
	if o.SRMAlpha <= 0 || o.SRMAlpha >= 1 {
		o.SRMAlpha = 0.001
	}
	if o.MinDevelopers <= 0 {
		o.MinDevelopers = 10
	}
	if o.Iters <= 1 {
		o.Iters = 2000
	}
	if o.Seed == 0 {
		o.Seed = 1
	}
}

// Arm is one arm's population and volume.
type Arm struct {
	Name string `json:"name"`
	// Weight is the configured share (randomized only).
	Weight float64 `json:"weight,omitempty"`
	// Developers on the roster assigned to the arm; Active opened >= 1 PR.
	Developers int `json:"developers"`
	Active     int `json:"active"`
	PRs        int `json:"prs"`
	Merged     int `json:"merged"`
	// AI spend over the window and the arm-level cost per merged PR, when a
	// cost source has rows for the arm. Spend and PRs are joined per arm,
	// not per developer, so there is no CI on CostPerMergedPR.
	SpendUSD        float64 `json:"spendUSD,omitempty"`
	CostUnits       int     `json:"costUnits,omitempty"`
	CostPerMergedPR float64 `json:"costPerMergedPR,omitempty"`
}

// Effect is one metric's treatment-vs-control comparison.
type Effect struct {
	Metric string `json:"metric"`
	Arm    string `json:"arm"` // the treatment arm compared with the control
	// Kind is "causal" (randomized) or "association" (observational).
	Kind   string `json:"kind"`
	Better string `json:"better,omitempty"` // decrease | increase; "" = descriptive
	State  string `json:"state"`
	// Outcome is improved | worsened for a significant effect with a direction.
	Outcome string `json:"outcome,omitempty"`
	stats.DiffResult
	// MDERel is the relative effect detectable with 80% power at Alpha.
	MDERel  float64  `json:"mdeRel,omitempty"`
	Slices  []Effect `json:"slices,omitempty"`
	Novelty bool     `json:"novelty,omitempty"`
	From    string   `json:"from,omitempty"` // set on slices
}

// Report is a delivery-ROI analysis.
type Report struct {
	Design     string           `json:"design"`
	Claim      string           `json:"claim"`
	Status     string           `json:"status"`
	Experiment string           `json:"experiment,omitempty"`
	Rings      []string         `json:"rings,omitempty"`
	From       time.Time        `json:"from"`
	To         time.Time        `json:"to"`
	Control    string           `json:"control"`
	Arms       []Arm            `json:"arms"`
	SRM        *stats.SRMResult `json:"srm,omitempty"`
	Effects    []Effect         `json:"effects"`
	CostSource string           `json:"costSource,omitempty"`
	// Excluded counts PRs left out, by reason.
	Excluded       map[string]int `json:"excluded"`
	UnmappedLogins []string       `json:"unmappedLogins,omitempty"` // first 20
	Warnings       []string       `json:"warnings"`
}

// Analyze builds the report from the store's PRs, the identity roster and,
// when cost is non-nil, AI spend per arm.
func Analyze(ctx context.Context, store Store, cost CostSource, ids *Identities, o Options) (*Report, error) {
	o.defaults()
	if (o.Experiment == nil) == (len(o.Rings) == 0) {
		return nil, errors.New("roi: choose an experiment or rings, not both")
	}
	if o.Org == nil || ids == nil {
		return nil, errors.New("roi: policy and identities are required")
	}
	if !o.From.Before(o.To) {
		return nil, fmt.Errorf("roi: empty window %s .. %s", o.From.Format(time.RFC3339), o.To.Format(time.RFC3339))
	}
	rep := &Report{From: o.From.UTC(), To: o.To.UTC(), Excluded: map[string]int{}, Warnings: []string{}, Effects: []Effect{}}
	arms, err := rep.setArms(o)
	if err != nil {
		return nil, err
	}
	// Roster -> arm, recovered with the fleet's own assignment.
	devArm := map[string]int{}
	for _, s := range ids.Subjects() {
		if s.Kind == policy.SubjectWorkload {
			continue
		}
		if i := armOf(o, arms, s); i >= 0 {
			devArm[s.ID] = i
			rep.Arms[i].Developers++
		}
	}
	prs, err := store.PRs(ctx, o.From, o.To)
	if err != nil {
		return nil, err
	}
	devPRs := map[string][]PR{}
	unmapped := map[string]bool{}
	for _, p := range prs {
		s, ok := ids.Resolve(p)
		switch {
		case p.Bot || ok && s.Kind == policy.SubjectWorkload:
			rep.Excluded["bot_or_workload"]++
		case !ok:
			rep.Excluded["unmapped_author"]++
			unmapped[cmpOr(p.Author, p.Subject)] = true
		default:
			if _, in := devArm[s.ID]; !in {
				rep.Excluded["outside_arms"]++
				continue
			}
			devPRs[s.ID] = append(devPRs[s.ID], p)
		}
	}
	for l := range unmapped {
		rep.UnmappedLogins = append(rep.UnmappedLogins, l)
	}
	sort.Strings(rep.UnmappedLogins)
	if len(rep.UnmappedLogins) > 20 {
		rep.UnmappedLogins = rep.UnmappedLogins[:20]
	}
	if n := rep.Excluded["unmapped_author"]; n > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("%d PRs by authors missing from the identity roster were left out; add them (login,subject,groups) and re-run", n))
	}
	for id, ps := range devPRs {
		a := &rep.Arms[devArm[id]]
		a.Active++
		a.PRs += len(ps)
		for _, p := range ps {
			a.Merged += int(b2f(p.merged(o.To)))
		}
	}
	if o.Experiment != nil {
		rep.checkSRM(o)
	}
	if cost != nil {
		if err := rep.addCost(ctx, cost, o); err != nil {
			return nil, err
		}
	}
	rep.estimate(o, devArm, devPRs)
	return rep, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// setArms fills Design, Claim, Control and Arms.
func (rep *Report) setArms(o Options) ([]string, error) {
	var names []string
	if e := o.Experiment; e != nil {
		rep.Design, rep.Experiment = DesignRandomized, e.Name
		rep.Rings = append([]string{}, e.Rings...)
		for _, v := range e.Variants {
			if v.Control {
				if rep.Control != "" {
					return nil, fmt.Errorf("roi: experiment %s has more than one control variant", e.Name)
				}
				rep.Control = v.Name
			}
			names = append(names, v.Name)
			rep.Arms = append(rep.Arms, Arm{Name: v.Name, Weight: v.Weight})
		}
		if rep.Control == "" || len(names) < 2 {
			return nil, fmt.Errorf("roi: experiment %s needs one control and at least one other variant", e.Name)
		}
		rep.Claim = fmt.Sprintf("Randomized: internal/assign hashed each developer in rings %s into a variant of %s, so arm differences estimate the causal effect of being assigned the variant (intent-to-treat) for developers in those rings, and nowhere else.",
			strings.Join(e.Rings, ", "), e.Name)
		return names, nil
	}
	rep.Design, rep.Rings = DesignObservational, append([]string{}, o.Rings...)
	for _, r := range o.Rings {
		if !slices.ContainsFunc(o.Org.Rings, func(x *policy.Ring) bool { return x.Name == r }) {
			return nil, fmt.Errorf("roi: unknown ring %q", r)
		}
		if slices.Contains(names, r) {
			return nil, fmt.Errorf("roi: ring %q listed twice", r)
		}
		names = append(names, r)
		rep.Arms = append(rep.Arms, Arm{Name: r})
	}
	if len(names) < 2 {
		return nil, errors.New("roi: compare at least two rings")
	}
	rep.Control = names[0]
	rep.Claim = "Observational: ring membership is chosen (explicit users, groups, opt-in, rollout order), not randomized against delivery, so differences between rings are associations and not effects of a ring's release. Run an experiment for a causal estimate."
	return names, nil
}

// armOf is the subject's arm index, or -1.
func armOf(o Options, arms []string, s policy.Subject) int {
	ring := o.Org.ResolveRing(s)
	if ring == nil {
		return -1
	}
	if o.Experiment == nil {
		return slices.Index(arms, ring.Name)
	}
	v := o.Experiment.AssignVariant(s, ring.Name)
	if v == nil {
		return -1
	}
	return slices.Index(arms, v.Name)
}

func (rep *Report) checkSRM(o Options) {
	obs := make([]int, len(rep.Arms))
	w := make([]float64, len(rep.Arms))
	for i, a := range rep.Arms {
		obs[i], w[i] = a.Active, a.Weight
	}
	r, err := stats.SRM(obs, w, o.SRMAlpha)
	if err != nil {
		return // no active developers yet, or a zero-weight arm: nothing to test
	}
	rep.SRM = &r
	if r.Mismatch {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("sample ratio mismatch: active developers per arm %v do not match the weights (chi2 %.1f, p %.2g); developers were lost or gained unevenly, so do not trust these effects until the cause is found", obs, r.Chi2, r.PValue))
	}
}

func (rep *Report) addCost(ctx context.Context, cost CostSource, o Options) error {
	exp := ""
	if o.Experiment != nil {
		exp = o.Experiment.Name
	}
	m, src, err := cost.ArmCosts(ctx, exp, o.Rings, o.From, o.To)
	if err != nil {
		return err
	}
	rep.CostSource = src
	for i := range rep.Arms {
		a := &rep.Arms[i]
		c, ok := m[a.Name]
		if !ok {
			continue
		}
		a.SpendUSD, a.CostUnits = c.USD, c.Units
		if a.Merged > 0 {
			a.CostPerMergedPR = c.USD / float64(a.Merged)
		}
	}
	return nil
}

// z is the standard normal quantile.
func z(p float64) float64 { return math.Sqrt2 * math.Erfinv(2*p-1) }

// estimate fills Effects (treatment arms x metrics, each with time slices)
// and the overall Status.
func (rep *Report) estimate(o Options, devArm map[string]int, devPRs map[string][]PR) {
	ctl := slices.IndexFunc(rep.Arms, func(a Arm) bool { return a.Name == rep.Control })
	kind := "causal"
	if rep.Design == DesignObservational {
		kind = "association"
	}
	powerZ := z(1-o.Alpha/2) + z(0.8)
	slice := func(m metric, trt int, from, to time.Time, seed uint64) Effect {
		weeks := to.Sub(from).Hours() / (24 * 7)
		var cs [2][]stats.Cluster
		for id, i := range devArm {
			if i != ctl && i != trt {
				continue
			}
			var in []PR
			for _, p := range devPRs[id] {
				if !p.OpenedAt.Before(from) && p.OpenedAt.Before(to) {
					in = append(in, p)
				}
			}
			if c, ok := m.cluster(in, o.To, weeks); ok {
				side := 0
				if i == trt {
					side = 1
				}
				cs[side] = append(cs[side], c)
			}
		}
		e := Effect{Metric: m.name, Arm: rep.Arms[trt].Name, Kind: kind, Better: m.better}
		e.NC, e.NT = len(cs[0]), len(cs[1])
		if e.NC < o.MinDevelopers || e.NT < o.MinDevelopers {
			e.State = StateInsufficientData
			return e
		}
		// Map iteration order must not change the resample: sort clusters.
		for _, c := range cs {
			slices.SortFunc(c, func(a, b stats.Cluster) int { return cmp.Or(cmp.Compare(a.Num, b.Num), cmp.Compare(a.Den, b.Den)) })
		}
		d, err := stats.ClusterBootstrapDiff(cs[0], cs[1], o.Iters, seed, o.Alpha)
		if err != nil {
			e.State = StateInsufficientData
			return e
		}
		e.DiffResult = d
		if d.Control != 0 {
			e.MDERel = powerZ * d.SE / math.Abs(d.Control)
		}
		// Float noise (identical arms differ by ~1e-16) is not an effect.
		tol := 1e-9 * max(math.Abs(d.Control), math.Abs(d.Treatment), 1)
		switch {
		case d.CILo > tol || d.CIHi < -tol:
			e.State = StateSignificant
			if m.better != "" {
				e.Outcome = "worsened"
				if (m.better == "increase") == (d.Effect > 0) {
					e.Outcome = "improved"
				}
			}
		case d.Control != 0 && e.MDERel <= o.MDE:
			e.State = StateNoDetectableEffect
		default:
			e.State = StateInsufficientPower
		}
		return e
	}
	estimated := 0
	for trt := range rep.Arms {
		if trt == ctl {
			continue
		}
		for mi, m := range metrics {
			seed := o.Seed + uint64(100*trt+mi) //nolint:gosec // small non-negative ints
			e := slice(m, trt, o.From, o.To, seed)
			if e.State != StateInsufficientData {
				estimated++
			}
			if o.Slices >= 2 {
				step := o.To.Sub(o.From) / time.Duration(o.Slices)
				for k := range o.Slices {
					from := o.From.Add(time.Duration(k) * step)
					to := from.Add(step)
					if k == o.Slices-1 {
						to = o.To
					}
					s := slice(m, trt, from, to, seed+uint64(1000*(k+1))) //nolint:gosec // small non-negative ints
					s.From = from.UTC().Format(time.DateOnly)
					e.Slices = append(e.Slices, s)
				}
				// Novelty: the first and last slices' relative CIs do not
				// overlap (conservative: a few percent false alarms at most).
				// Relative, because the last slice is right-censored (recent
				// PRs have not merged yet) in both arms alike, which moves
				// absolute differences but not ratios.
				first, last := e.Slices[0], e.Slices[len(e.Slices)-1]
				if first.State != StateInsufficientData && last.State != StateInsufficientData &&
					first.Control != 0 && last.Control != 0 &&
					(first.RelCIHi < last.RelCILo || first.RelCILo > last.RelCIHi) {
					e.Novelty = true
					rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s (%s): the effect moved over time (first slice %+.1f%% [%+.1f%%, %+.1f%%], last slice %+.1f%% [%+.1f%%, %+.1f%%]): a novelty or learning effect; the last slice is the better long-run estimate",
						m.name, e.Arm, 100*first.Rel, 100*first.RelCILo, 100*first.RelCIHi, 100*last.Rel, 100*last.RelCILo, 100*last.RelCIHi))
				}
			}
			rep.Effects = append(rep.Effects, e)
		}
	}
	switch {
	case rep.SRM != nil && rep.SRM.Mismatch:
		rep.Status = StatusSRM
	case estimated == 0:
		rep.Status = StatusInsufficientData
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("insufficient data: every metric needs at least %d developers with PRs per arm", o.MinDevelopers))
	default:
		rep.Status = StatusOK
	}
}

// Markdown renders the report for a promotion PR body. It is informational:
// nothing in Halos promotes on it.
func (rep *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Delivery ROI (%s, informational)\n\n%s\n\n", rep.Design, rep.Claim)
	fmt.Fprintf(&b, "Window %s to %s. Status: **%s**.", rep.From.Format(time.DateOnly), rep.To.Format(time.DateOnly), rep.Status)
	if rep.SRM != nil {
		fmt.Fprintf(&b, " SRM check: p=%.3g (%s).", rep.SRM.PValue, map[bool]string{true: "MISMATCH", false: "ok"}[rep.SRM.Mismatch])
	}
	b.WriteString("\n\n| Arm | Developers | Active | Merged PRs | Cost per merged PR |\n|---|---|---|---|---|\n")
	for _, a := range rep.Arms {
		c := "n/a"
		if a.CostPerMergedPR > 0 {
			c = fmt.Sprintf("$%.2f (%s)", a.CostPerMergedPR, rep.CostSource)
		}
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %s |\n", a.Name, a.Developers, a.Active, a.Merged, c)
	}
	b.WriteString("\n| Metric | Arm vs `" + rep.Control + "` | Control | Treatment | " + effectWord(rep) + " (95% CI) | Relative | State |\n|---|---|---|---|---|---|---|\n")
	for _, e := range rep.Effects {
		if e.State == StateInsufficientData {
			fmt.Fprintf(&b, "| %s | `%s` | | | | | %s (n=%d/%d) |\n", e.Metric, e.Arm, e.State, e.NC, e.NT)
			continue
		}
		state := e.State
		if e.Outcome != "" {
			state += ", " + e.Outcome
		}
		if e.Novelty {
			state += ", novelty"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %.3g | %.3g | %+.3g [%+.3g, %+.3g] | %+.1f%% | %s |\n",
			e.Metric, e.Arm, e.Control, e.Treatment, e.Effect, e.CILo, e.CIHi, 100*e.Rel, state)
	}
	for _, w := range rep.Warnings {
		b.WriteString("\n- " + w)
	}
	b.WriteString("\n\nDeveloper-clustered bootstrap; PRs opened in the window. This section never decides a promotion.\n")
	return b.String()
}

func effectWord(rep *Report) string {
	if rep.Design == DesignObservational {
		return "Difference"
	}
	return "Effect"
}

// PromotionSection is the Markdown for e's promotion PR over [from, to), or
// "" when no rostered developer in the experiment has a PR yet. It is the
// only way ROI reaches internal/promote, and only as text for the reviewer.
func PromotionSection(ctx context.Context, st Store, cost CostSource, ids *Identities, org *policy.Org, e *policy.Experiment, from, to time.Time) (string, error) {
	rep, err := Analyze(ctx, st, cost, ids, Options{Org: org, Experiment: e, From: from, To: to})
	if err != nil {
		return "", err
	}
	for _, a := range rep.Arms {
		if a.Active > 0 {
			return rep.Markdown(), nil
		}
	}
	return "", nil
}
