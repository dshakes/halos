// Package toggle evaluates feature-toggle targeting rules and composes the
// per-harness settings fragments a release carries for client-axis toggles.
// Rule evaluation is pure and deterministic; percent rollouts hash through
// internal/assign (the single hashing source) under a per-toggle salt.
package toggle

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/assign"
	"github.com/dshakes/halos/internal/policy"
)

// Subject is who a toggle is evaluated for: the authenticated identity plus
// the ring it resolved to. Never built from client-supplied headers.
type Subject struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups,omitempty"`
	Ring   string   `json:"ring,omitempty"`
}

// Decision is one toggle's outcome with the reasoning behind it.
type Decision struct {
	Name string `json:"name"`
	On   bool   `json:"on"`
	// Rule is the index of the deciding rule, -1 when the default applied.
	Rule int `json:"rule"`
	// Killed: the name is on the signed kill list, so On is false whatever the rules say.
	Killed bool     `json:"killed,omitempty"`
	Why    string   `json:"why"`
	Trace  []string `json:"trace"`
}

// Salt is the hash namespace of a toggle's percent rollouts.
func Salt(name string) string { return policy.ToggleSaltPrefix + name }

// Bucket is the subject's bucket in [0, assign.Buckets) for the toggle.
func Bucket(name, subject string) int { return assign.Bucket(Salt(name), subject) }

// Eval walks rules in order; the first match decides, else def applies. A
// killed toggle is off regardless. The trace lists every condition checked.
func Eval(name string, def bool, rules []policy.ToggleRule, s Subject, killed bool) Decision {
	d := Decision{Name: name, Rule: -1}
	for i, r := range rules {
		ok, why := match(name, r, s)
		label := r.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i)
		}
		d.Trace = append(d.Trace, fmt.Sprintf("rule %s: %s", label, why))
		if !ok {
			continue
		}
		d.Rule, d.On = i, r.Effect != policy.EffectOff
		d.Why = fmt.Sprintf("rule %s matched (%s)", label, ifEmpty(r.Effect, policy.EffectOn))
		break
	}
	if d.Rule < 0 {
		d.On = def
		d.Why = fmt.Sprintf("no rule matched; default %s", onOff(def))
	}
	if killed {
		d.Trace = append(d.Trace, "kill list: killed")
		d.On, d.Killed, d.Why = false, true, "killed via the signed kill list"
	}
	return d
}

// match reports whether every condition of r holds, with a one-line trace.
func match(name string, r policy.ToggleRule, s Subject) (bool, string) {
	var parts []string
	ok := true
	check := func(label string, pass bool, detail string) {
		mark := "ok"
		if !pass {
			mark, ok = "no", false
		}
		parts = append(parts, fmt.Sprintf("%s %s%s", label, mark, detail))
	}
	if len(r.Rings) > 0 {
		check("ring", slices.Contains(r.Rings, s.Ring), fmt.Sprintf(" (%q in %v)", s.Ring, r.Rings))
	}
	if len(r.Groups) > 0 {
		check("group", slices.ContainsFunc(r.Groups, func(g string) bool { return slices.Contains(s.Groups, g) }), fmt.Sprintf(" (%v vs %v)", s.Groups, r.Groups))
	}
	if len(r.Users) > 0 {
		check("user", slices.Contains(r.Users, s.ID), "")
	}
	if r.Percent != nil { // explicit 0 matches nobody (bucket < 0 never holds)
		if s.ID == "" { // no identity, no cohort: never roll out to an anonymous caller
			check("percent", false, " (no subject id)")
		} else {
			b, cut := Bucket(name, s.ID), assign.Share(*r.Percent/100)
			check("percent", b < cut, fmt.Sprintf(" (bucket %d < %d of %d)", b, cut, assign.Buckets))
		}
	}
	if len(parts) == 0 {
		return true, "matches everyone"
	}
	return ok, strings.Join(parts, ", ")
}

func onOff(b bool) string {
	if b {
		return policy.EffectOn
	}
	return policy.EffectOff
}

func ifEmpty(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// EvalAll evaluates every toggle of org for s; killed names are forced off.
func EvalAll(org *policy.Org, s Subject, killed []string) []Decision {
	out := make([]Decision, 0, len(org.Toggles))
	for _, t := range org.Toggles {
		out = append(out, Eval(t.Name, t.Default, t.Rules, s, slices.Contains(killed, t.Name)))
	}
	return out
}
