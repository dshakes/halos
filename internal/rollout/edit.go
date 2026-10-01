package rollout

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/yamledit"
)

// edit sets one scalar in the kind/name document. str values are top-level
// strings set with SetField (keeps quote style); others are raw YAML.
type edit struct {
	kind policy.Kind
	name string
	path []string
	val  string
	str  bool
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// Plan builds the policy-repo change for act: Advance (to step next),
// Complete, Rollback or Pause. org is the policy the decision was made on; dir
// is the policy repo (files are located there, and the edit re-applies to
// whatever version of them the PR is built from). It writes nothing.
//
//   - canary / holdout: the backing experiment runs as a canary with the step's
//     treatment / control share as variant weights (assignment stays sticky:
//     internal/assign.Pick keeps a growing arm's users).
//   - dark-launch: the experiment runs as a shadow at the step's sample rate.
//   - progressive / blue-green: the ring's release pointer moves to the change
//     (the experiment is paused so the whole ring gets it).
//   - complete: the experiment is concluded; traffic-axis rollouts point the
//     gateway alias at the treatment's route.
//   - rollback: rollout aborted, experiment paused, every ring moved so far
//     re-pointed at baseline.release.
func Plan(dir string, org *policy.Org, r *policy.Rollout, act Action, next int) (*promote.Change, error) {
	var exp *policy.Experiment
	var ctl, trt *policy.Variant
	if r.Experiment != "" {
		if exp = findExp(org, r.Experiment); exp == nil {
			return nil, fmt.Errorf("rollout %s: experiment %q not found", r.Name, r.Experiment)
		}
		var ok bool
		if ctl, trt, ok = exp.Arms(); !ok {
			return nil, fmt.Errorf("rollout %s: experiment %q needs one control and one treatment", r.Name, exp.Name)
		}
	}
	ro := func(key, val string) edit { return edit{policy.KindRollout, r.Name, []string{key}, val, true} }
	ex := func(key, val string) edit { return edit{policy.KindExperiment, r.Experiment, []string{key}, val, true} }
	weight := func(v *policy.Variant, w float64) edit {
		return edit{policy.KindExperiment, r.Experiment, []string{"variants", "name=" + v.Name, "weight"}, num(w), false}
	}
	pauseExp := func() []edit {
		if exp != nil && exp.Status == "running" {
			return []edit{ex("status", "paused")}
		}
		return nil
	}
	var edits []edit
	switch act {
	case Advance:
		if next < 0 || next >= len(r.Steps) {
			return nil, fmt.Errorf("rollout %s: no step %d to advance to", r.Name, next)
		}
		s := r.Steps[next]
		p := s.EffectivePercent()
		edits = []edit{ro("status", policy.RolloutActive), ro("step", s.Name)}
		if exp == nil && !s.RingWide() {
			return nil, fmt.Errorf("rollout %s: %s step %s needs a backing experiment", r.Name, s.Strategy, s.Name)
		}
		switch s.Strategy {
		case policy.StrategyCanary:
			edits = append(edits, ex("type", string(policy.ExperimentCanary)), ex("status", "running"), weight(ctl, 100-p), weight(trt, p))
		case policy.StrategyHoldout:
			edits = append(edits, ex("type", string(policy.ExperimentCanary)), ex("status", "running"), weight(ctl, p), weight(trt, 100-p))
		case policy.StrategyDarkLaunch:
			edits = append(edits, ex("type", string(policy.ExperimentShadow)), ex("status", "running"),
				edit{policy.KindExperiment, r.Experiment, []string{"sampleRate"}, num(p / 100), false})
		case policy.StrategyProgressive, policy.StrategyBlueGreen:
			edits = append(edits, edit{policy.KindRing, s.Ring, []string{"release"}, r.Change.Release, true})
			edits = append(edits, pauseExp()...)
		default:
			return nil, fmt.Errorf("rollout %s: unknown strategy %q", r.Name, s.Strategy)
		}
	case Complete:
		edits = []edit{ro("status", policy.RolloutCompleted)}
		if exp != nil && exp.Status != "concluded" {
			edits = append(edits, ex("status", "concluded"))
		}
		if r.Axis == policy.AxisTraffic {
			if org.Gateway == nil || trt == nil {
				return nil, fmt.Errorf("rollout %s: re-routing needs a Gateway document and a backing experiment", r.Name)
			}
			rt, ok := trt.Routes[r.Change.Alias]
			if !ok {
				return nil, fmt.Errorf("rollout %s: treatment %q has no route for alias %q", r.Name, trt.Name, r.Change.Alias)
			}
			if ManualSteps(org, r, act) != nil {
				break // multi-target route: a human edits it (see ManualSteps)
			}
			gw := func(k, v string) edit {
				return edit{policy.KindGateway, org.Gateway.Name, []string{"models", r.Change.Alias, k}, yamledit.Quote(v, 0), false}
			}
			edits = append(edits, gw("upstream", rt.Upstream), gw("model", rt.Model))
		}
	case Rollback:
		edits = append([]edit{ro("status", policy.RolloutAborted)}, pauseExp()...)
		var rings []string
		for _, s := range r.Steps[:r.StepIndex(r.Step)+1] { // StepIndex is -1 before the first step
			if s.RingWide() && !slices.Contains(rings, s.Ring) && r.Baseline.Release != "" {
				rings = append(rings, s.Ring)
				edits = append(edits, edit{policy.KindRing, s.Ring, []string{"release"}, r.Baseline.Release, true})
			}
		}
	case Pause:
		edits = []edit{ro("status", policy.RolloutPaused)}
	default:
		return nil, fmt.Errorf("rollout %s: %s is not a policy edit", r.Name, act)
	}
	return planEdits(dir, edits)
}

// ManualSteps lists what Plan(act) cannot edit and a human must add to the
// PR before merging: completing a traffic-axis rollout whose gateway alias or
// treatment route has multiple targets (failover tiers are a human call).
func ManualSteps(org *policy.Org, r *policy.Rollout, act Action) []string {
	if act != Complete || r.Axis != policy.AxisTraffic || org.Gateway == nil {
		return nil
	}
	exp := findExp(org, r.Experiment)
	if exp == nil {
		return nil
	}
	_, trt, ok := exp.Arms()
	if !ok {
		return nil
	}
	cur, nw := org.Gateway.Models[r.Change.Alias], trt.Routes[r.Change.Alias]
	if len(cur.Targets) == 0 && len(nw.Targets) == 0 {
		return nil
	}
	var to []string
	for _, t := range nw.Candidates() {
		to = append(to, t.Upstream+"/"+t.Model)
	}
	return []string{fmt.Sprintf("gateway.models.%s has failover targets: re-point it to %s by hand in this PR", r.Change.Alias, strings.Join(to, ", "))}
}

func findExp(org *policy.Org, name string) *policy.Experiment {
	for _, e := range org.Experiments {
		if e.Name == name {
			return e
		}
	}
	return nil
}

// planEdits locates each document's file and applies edits in order, each
// to the bytes the previous one produced.
func planEdits(dir string, edits []edit) (*promote.Change, error) {
	files := map[string]string{} // kind/name -> repo-relative file
	for _, e := range edits {
		k := string(e.kind) + "/" + e.name
		if _, ok := files[k]; ok {
			continue
		}
		d, err := yamledit.Find(dir, e.kind, e.name)
		if err != nil {
			return nil, fmt.Errorf("rollout plan: %w", err)
		}
		files[k] = d.Rel
	}
	apply := func(read promote.ReadFunc) (map[string][]byte, error) {
		out := map[string][]byte{}
		for _, e := range edits {
			f := files[string(e.kind)+"/"+e.name]
			old, ok := out[f]
			if !ok {
				b, err := read(f)
				if err != nil {
					return nil, fmt.Errorf("rollout plan: read %s: %w", f, err)
				}
				old = b
			}
			m, err := yamledit.Parse(old, e.kind, e.name)
			if err != nil {
				return nil, fmt.Errorf("rollout plan: parse %s: %w", f, err)
			}
			if m == nil {
				return nil, fmt.Errorf("rollout plan: no %s %q in %s", e.kind, e.name, f)
			}
			d := &yamledit.Doc{Path: f, Rel: f, Data: old, Mapping: m}
			var nw []byte
			if e.str {
				nw, err = d.SetField(e.path[0], e.val)
			} else {
				nw, err = d.SetPath(e.path, e.val)
			}
			if err != nil {
				return nil, fmt.Errorf("rollout plan: %w", err)
			}
			out[f] = nw
		}
		return out, nil
	}
	read := func(f string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, filepath.FromSlash(f))) }
	nw, err := apply(read)
	if err != nil {
		return nil, err
	}
	ch := &promote.Change{Files: map[string][]byte{}, Edit: apply}
	names := make([]string, 0, len(nw))
	for f := range nw {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		old, err := read(f)
		if err != nil {
			return nil, fmt.Errorf("rollout plan: read %s: %w", f, err)
		}
		if d := promote.UnifiedDiff(f, string(old), string(nw[f])); d != "" {
			ch.Files[f] = nw[f]
			ch.Patch += d
		}
	}
	return ch, nil
}
