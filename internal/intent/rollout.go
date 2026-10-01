package intent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/yamledit"
)

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Guardrails the generated experiments carry (EffectiveGuardrails hands them
// to every canary step, so a breach auto-rolls back).
var (
	clientGuardrails = []policy.MetricGoal{
		{Metric: "halo.tool.error_rate", Direction: "decrease", MaxRegression: 0.10},
		{Metric: "halo.api.error_rate", Direction: "decrease", MaxRegression: 0.05},
	}
	trafficGuardrails = []policy.MetricGoal{
		{Metric: "halo.api.error_rate", Direction: "decrease", MaxRegression: 0.05},
		{Metric: "halo.latency.p95_ms", Direction: "decrease", MaxRegression: 0.15},
	}
	stopping = policy.Stopping{Method: "msprt", Alpha: 0.05, MinSamples: 500, MaxDays: 14}
)

func (r *Repo) preset() (policy.RolloutPreset, error) {
	return policy.LookupRolloutPreset(r.Root.Rollout)
}

// Upgrade is `halo upgrade start`: roll tool out at version.
type Upgrade struct {
	Tool, Version string
	// Release is the digest of the release carrying the new pin; Baseline the
	// digest rings return to on rollback. Both may be left empty for PlanUpgrade
	// (the caller builds and publishes the candidate, then calls Finish).
	Release, Baseline string
	// Label is the candidate release's version label (default "<tool>-<version>").
	Label string
}

// Candidate is what to build for an upgrade: Profile (pinning the new
// version) rendered for Ring, labelled Label. When Experiment is set, the
// treatment variant Variant is also built for ExperimentRing and served on its
// client-axis channel, so the canary has a release before any ring moves.
type Candidate struct {
	Profile, Ring, Label                string
	Experiment, Variant, ExperimentRing string
}

// UpgradePlan is an upgrade with every document but the Rollout rendered.
type UpgradePlan struct {
	Name      string
	Candidate Candidate
	// Change holds the treatment profile, the experiment and ring stubs;
	// Change.Load() gives the policy to build the candidate from.
	Change  *Change
	rollout *policy.Rollout
	comment string
	notes   []string
}

// UpgradeStart is PlanUpgrade then Finish with u's digests.
func (r *Repo) UpgradeStart(u Upgrade) (*Change, error) {
	p, err := r.PlanUpgrade(u)
	if err != nil {
		return nil, err
	}
	return p.Finish(u.Release, u.Baseline)
}

// PlanUpgrade lays out a client-axis Rollout from the rollout preset: ring0
// ring-wide, a canary ramp on the first percent ring (backed by a client-axis
// experiment whose treatment profile pins the new version), then ring by ring
// to GA, each later ring behind a human approval. Rings that exist only in
// halos.yaml get a stub document so the rollout's PRs can move their release
// pointer. The Rollout itself is written by Finish once the digests are known.
func (r *Repo) PlanUpgrade(u Upgrade) (*UpgradePlan, error) {
	ga, err := r.GA()
	if err != nil {
		return nil, err
	}
	var canaryRing *policy.Ring
	for _, g := range r.Org.Rings {
		if g.Membership.Percent > 0 {
			canaryRing = g
			break
		}
	}
	baseProfile := ga.Profile
	if canaryRing != nil {
		baseProfile = canaryRing.Profile
	}
	base, err := r.Org.ResolveProfile(baseProfile)
	if err != nil {
		return nil, err
	}
	cur, ok := base.Harnesses[u.Tool]
	if !ok {
		return nil, fmt.Errorf("intent: %s is not enabled in profile %q (have %v)", u.Tool, baseProfile, sortedKeys(base.Harnesses))
	}
	if cur.Version == u.Version {
		return nil, fmt.Errorf("intent: %s is already at %s", u.Tool, u.Version)
	}
	name := u.Tool + "-" + u.Version
	if err := validName("rollout", name); err != nil {
		return nil, err
	}
	for _, x := range r.Org.Rollouts {
		if x.Name == name {
			return nil, fmt.Errorf("intent: rollout %q already exists", name)
		}
	}
	if _, ok := r.Org.Profiles[name]; ok {
		return nil, fmt.Errorf("intent: profile %q already exists", name)
	}
	p, err := r.preset()
	if err != nil {
		return nil, err
	}
	if u.Label == "" {
		u.Label = name
	}
	c := newChange(r.Dir)
	plan := &UpgradePlan{Name: name, Change: c, Candidate: Candidate{Profile: name, Ring: ga.Name, Label: u.Label}}
	ro := &policy.Rollout{Meta: meta(policy.KindRollout, name), Axis: policy.AxisClient, Status: policy.RolloutDraft,
		Change: policy.RolloutChange{Version: u.Label}}
	c.Files["profiles/"+name+".yaml"] = []byte(fmt.Sprintf("# Treatment of rollout %s: profile %s with %s pinned to %s.\n"+
		"apiVersion: %s\nkind: Profile\nname: %s\nextends: %s\nharnesses:\n  %s:\n    version: %s\n",
		name, baseProfile, u.Tool, u.Version, policy.APIVersion, name, baseProfile, u.Tool, u.Version))
	ring := func(g *policy.Ring, bake string) {
		ro.Steps = append(ro.Steps, policy.RolloutStep{Name: g.Name, Strategy: policy.StrategyProgressive, Ring: g.Name, Bake: bake,
			Gates: policy.RolloutGates{Approval: g.Order > r.Org.Rings[0].Order}})
		if !r.has(policy.KindRing, g.Name) {
			c.Files["rings/"+g.Name+".yaml"] = []byte(fmt.Sprintf("# Pins ring %s to a release; membership and profile come from halos.yaml.\n"+
				"# The controller's rollout PRs edit release below. `halo explain` shows the whole ring.\n"+
				"apiVersion: %s\nkind: Ring\nname: %s\n", g.Name, policy.APIVersion, g.Name))
		}
	}
	for _, g := range r.Org.Rings {
		if canaryRing != nil && g == canaryRing && len(p.Canary) > 0 {
			ro.Experiment = name + "-canary"
			ro.Steps = append(ro.Steps, p.Canary...)
			plan.Candidate.Experiment, plan.Candidate.Variant, plan.Candidate.ExperimentRing = ro.Experiment, "next", g.Name
			exp := &policy.Experiment{Meta: meta(policy.KindExperiment, ro.Experiment), Type: policy.ExperimentCanary, Axis: policy.AxisClient,
				Status: "draft", Rings: []string{g.Name},
				Variants: []policy.Variant{{Name: "current", Weight: 100 - p.Canary[0].Percent, Profile: baseProfile, Control: true},
					{Name: "next", Weight: p.Canary[0].Percent, Profile: name}},
				Metrics:  policy.Metrics{Primary: policy.MetricGoal{Metric: "halo.tool.error_rate", Direction: "decrease"}, Guardrails: clientGuardrails},
				Stopping: stopping}
			b, err := docYAML(policy.KindExperiment, fmt.Sprintf("Backs rollout %s: %s %s (next) vs %s (current) in ring %s.\nThe rollout's PRs set status and weights; do not edit by hand.", name, u.Tool, u.Version, cur.Version, g.Name), exp)
			if err != nil {
				return nil, err
			}
			c.Files["experiments/"+ro.Experiment+".yaml"] = b
		}
		bake := p.RingBake
		switch {
		case g.Membership.Default:
			bake = ""
		case canaryRing == nil || g.Order < canaryRing.Order:
			bake = p.TeamBake
		}
		ring(g, bake)
	}
	pin := "halos.yaml tools." + u.Tool
	if !r.Simple() {
		pin = fmt.Sprintf("profile %s harnesses.%s.version", baseProfile, u.Tool)
	}
	plan.rollout = ro
	plan.comment = fmt.Sprintf("Upgrade %s %s -> %s (rollout preset %s). Generated by `halo upgrade start`.\n"+
		"change.release is release %s (profile %s, ring %s); `halo upgrade publish %s` rebuilds and pushes it.\n"+
		"Plan: halo rollout plan %s. Every step is a PR a human merges; a guardrail breach rolls back.",
		u.Tool, cur.Version, u.Version, p.Name, u.Label, name, ga.Name, name, name)
	plan.notes = []string{
		fmt.Sprintf("start it: merge this, then `halo rollout advance %s --reason ...` opens the first step's PR", name),
		fmt.Sprintf("after it completes, set %s to %s so new releases keep the pin", pin, u.Version)}
	return plan, nil
}

// Finish writes the Rollout with the candidate (release) and rollback
// (baseline) digests and returns the whole change.
func (p *UpgradePlan) Finish(release, baseline string) (*Change, error) {
	for _, d := range []struct{ flag, v string }{{"--release", release}, {"--baseline", baseline}} {
		if !digestRe.MatchString(d.v) {
			return nil, fmt.Errorf("intent: %s %q: want a sha256:<64 hex> release digest", d.flag, d.v)
		}
	}
	if release == baseline {
		return nil, fmt.Errorf("intent: the candidate release is the baseline (%s): the new pin changed nothing", release)
	}
	p.rollout.Change.Release, p.rollout.Baseline.Release = release, baseline
	b, err := docYAML(policy.KindRollout, p.comment, p.rollout)
	if err != nil {
		return nil, err
	}
	p.Change.Files["rollouts/"+p.Name+".yaml"] = b
	p.Change.Notes = append(p.Change.Notes, p.notes...)
	return p.Change, nil
}

// CandidateOf is the Candidate a rollout written by `halo upgrade start`
// names: its treatment profile (same name as the rollout) for the GA ring,
// labelled change.version, plus the experiment's treatment variant.
func (r *Repo) CandidateOf(ro *policy.Rollout) (Candidate, error) {
	if ro.Axis != policy.AxisClient {
		return Candidate{}, fmt.Errorf("intent: rollout %s is %s-axis; only client-axis rollouts carry a release", ro.Name, ro.Axis)
	}
	if _, ok := r.Org.Profiles[ro.Name]; !ok {
		return Candidate{}, fmt.Errorf("intent: rollout %s has no treatment profile %q (was it written by `halo upgrade start`?)", ro.Name, ro.Name)
	}
	ga, err := r.GA()
	if err != nil {
		return Candidate{}, err
	}
	c := Candidate{Profile: ro.Name, Ring: ga.Name, Label: ro.Change.Version}
	for _, e := range r.Org.Experiments {
		if e.Name != ro.Experiment {
			continue
		}
		for _, v := range e.Variants {
			if v.Profile == ro.Name && len(e.Rings) > 0 {
				c.Experiment, c.Variant, c.ExperimentRing = e.Name, v.Name, e.Rings[0]
			}
		}
	}
	return c, nil
}

func meta(k policy.Kind, name string) policy.Meta {
	return policy.Meta{APIVersion: policy.APIVersion, Kind: k, Name: name}
}

// ModelSwitch is `halo model switch`: point alias at model.
type ModelSwitch struct {
	Alias, Model string
	Canary       bool
}

// SwitchModel re-points a gateway alias. Without Canary it edits the route in
// place (halos.yaml models.<alias> in simple mode, else the Gateway document).
// With Canary it writes a traffic-axis Rollout from the preset's canary ramp
// plus its two-arm experiment; completing the rollout re-points the alias.
func (r *Repo) SwitchModel(m ModelSwitch) (*Change, error) {
	g := r.Org.Gateway
	if g == nil {
		return nil, fmt.Errorf("intent: no gateway")
	}
	cur, ok := g.Models[m.Alias]
	if !ok {
		return nil, fmt.Errorf("intent: unknown model alias %q (have %v)", m.Alias, sortedKeys(g.Models))
	}
	up, model := policy.SplitModel(m.Model, cur.Primary().Upstream)
	if _, ok := g.Upstreams[up]; !ok {
		return nil, fmt.Errorf("intent: upstream %q not in the gateway (have %v)", up, sortedKeys(g.Upstreams))
	}
	if !m.Canary {
		return r.switchInPlace(m.Alias, up, model)
	}
	p, err := r.preset()
	if err != nil {
		return nil, err
	}
	name := slug(m.Alias + "-" + model)
	if len(name) > 63 {
		name = name[:63]
	}
	if err := validName("rollout", name); err != nil {
		return nil, err
	}
	for _, x := range r.Org.Rollouts {
		if x.Name == name {
			return nil, fmt.Errorf("intent: rollout %q already exists", name)
		}
	}
	steps := slices.Clone(p.Canary)
	steps[len(steps)-1].Gates.Approval = true
	c := newChange(r.Dir)
	exp := &policy.Experiment{Meta: meta(policy.KindExperiment, name), Type: policy.ExperimentCanary, Axis: policy.AxisTraffic,
		Status: "draft", Rings: ringNames(r.Org),
		Variants: []policy.Variant{{Name: "control", Weight: 100 - steps[0].Percent, Control: true},
			{Name: "candidate", Weight: steps[0].Percent, Routes: map[string]policy.ModelRoute{m.Alias: {Upstream: up, Model: model}}}},
		Metrics:  policy.Metrics{Primary: policy.MetricGoal{Metric: "halo.api.error_rate", Direction: "decrease"}, Guardrails: trafficGuardrails},
		Stopping: stopping}
	ro := &policy.Rollout{Meta: meta(policy.KindRollout, name), Axis: policy.AxisTraffic, Status: policy.RolloutDraft,
		Experiment: name, Change: policy.RolloutChange{Alias: m.Alias}, Steps: steps}
	eb, err := docYAML(policy.KindExperiment, fmt.Sprintf("Backs rollout %s: alias %s on %s/%s (candidate) vs its current route.\nThe rollout's PRs set status and weights; do not edit by hand.", name, m.Alias, up, model), exp)
	if err != nil {
		return nil, err
	}
	rb, err := docYAML(policy.KindRollout, fmt.Sprintf("Canary model switch: alias %s -> %s/%s (rollout preset %s). Generated by `halo model switch --canary`.\n"+
		"Completing it re-points gateway.models.%s; a guardrail breach trips the kill switch.", m.Alias, up, model, p.Name, m.Alias), ro)
	if err != nil {
		return nil, err
	}
	c.Files["experiments/"+name+".yaml"], c.Files["rollouts/"+name+".yaml"] = eb, rb
	// Completion edits gateway.models.<alias> in a Gateway document; in simple
	// mode that route lives only in halos.yaml, so pin it in a stub.
	if d, err := yamledit.Find(r.Dir, policy.KindGateway, g.Name); err != nil {
		var route string
		if t := cur.Targets; len(t) > 0 {
			route = "    targets:\n"
			for _, x := range t {
				route += fmt.Sprintf("      - upstream: %s\n        model: %s\n", x.Upstream, yamledit.Quote(x.Model, 0))
				if x.Priority > 0 {
					route += fmt.Sprintf("        priority: %d\n", x.Priority)
				}
			}
		} else {
			route = fmt.Sprintf("    upstream: %s\n    model: %s\n", cur.Upstream, yamledit.Quote(cur.Model, 0))
		}
		c.Files["gateway.yaml"] = []byte(fmt.Sprintf("# Overrides gateway.models.%s from halos.yaml while rollout %s runs; its\n"+
			"# completion PR re-points halos.yaml and deletes this file. `halo explain` shows the merged gateway.\n"+
			"apiVersion: %s\nkind: Gateway\nname: %s\nlabels:\n  %s: %s\nmodels:\n  %s:\n%s",
			m.Alias, name, policy.APIVersion, g.Name, policy.LabelGeneratedBy, policy.GeneratedFor(name), m.Alias, route))
	} else if d.Get("models", m.Alias) == nil {
		return nil, fmt.Errorf("intent: %s has no models.%s for the rollout to re-point; add the current route there first", d.Rel, m.Alias)
	}
	c.Notes = append(c.Notes, fmt.Sprintf("start it: merge this, then `halo rollout advance %s --reason ...`", name))
	return c, nil
}

func (r *Repo) switchInPlace(alias, up, model string) (*Change, error) {
	c := newChange(r.Dir)
	if r.Simple() && len(r.Root.Models[alias]) > 0 && !r.gatewayDefines(alias) {
		if len(r.Root.Models[alias]) > 1 {
			return nil, fmt.Errorf("intent: models.%s in halos.yaml is a failover list; edit it by hand or use --canary", alias)
		}
		d, err := rootDoc(r.Dir)
		if err != nil {
			return nil, err
		}
		id := model
		if up != r.defaultProvider() {
			id = up + "/" + model
		}
		b, err := d.SetPath([]string{"models", alias}, yamledit.Quote(id, 0))
		if err != nil {
			return nil, fmt.Errorf("intent: %w (block-style models: in halos.yaml can be edited)", err)
		}
		c.Files[policy.RootFile] = b
		return c, nil
	}
	d, err := yamledit.Find(r.Dir, policy.KindGateway, r.Org.Gateway.Name)
	if err != nil {
		return nil, fmt.Errorf("intent: %w", err)
	}
	if d.Get("models", alias, "targets") != nil {
		return nil, fmt.Errorf("intent: %s models.%s has failover targets; edit it by hand or use --canary", d.Rel, alias)
	}
	b, err := d.SetPath([]string{"models", alias, "model"}, yamledit.Quote(model, 0))
	if err != nil {
		return nil, fmt.Errorf("intent: %w", err)
	}
	d.Data = b
	if d.Mapping, err = yamledit.Parse(b, policy.KindGateway, r.Org.Gateway.Name); err != nil {
		return nil, fmt.Errorf("intent: %w", err)
	}
	if b, err = d.SetPath([]string{"models", alias, "upstream"}, yamledit.Quote(up, 0)); err != nil {
		return nil, fmt.Errorf("intent: %w", err)
	}
	c.Files[d.Rel] = b
	return c, nil
}

func (r *Repo) defaultProvider() string {
	if p := r.Root.Provider; p != nil {
		return p.Name
	}
	return ""
}

// gatewayDefines reports whether an explicit Gateway document routes alias.
func (r *Repo) gatewayDefines(alias string) bool {
	d, err := yamledit.Find(r.Dir, policy.KindGateway, r.Org.Gateway.Name)
	return err == nil && d.Get("models", alias) != nil
}

// rootDoc is halos.yaml as an editable document.
func rootDoc(dir string) (*yamledit.Doc, error) {
	p := filepath.Join(dir, policy.RootFile)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("intent: %w", err)
	}
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil || len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("intent: %s is not a YAML mapping (%v)", p, err)
	}
	return &yamledit.Doc{Path: p, Rel: policy.RootFile, Data: b, Mapping: n.Content[0]}, nil
}
