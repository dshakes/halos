// Package impact answers "who is affected" by a policy change (ADR-0030):
// for every member of a population (the enrolled fleet, or a policy-only
// estimate), it resolves ring, experiment variants and effective settings
// under the base policy and under the new one, and counts who changes, per
// member kind and per org unit. Rings and variants resolve through
// policy.ResolveRing and Experiment.ResolveVariant, so internal/assign stays
// the only hashing.
package impact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// Member kinds.
const (
	KindUser   = "user"
	KindDevice = "device"
	KindAgent  = "agent"  // a workload rule's subject (ADR-0023)
	KindGroup  = "group"  // policy estimate: one member of a group policy names
	KindSample = "sample" // policy estimate: an anonymous user in no listed group
)

// Member is one subject a change may reach.
type Member struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups,omitempty"`
	Kind   string   `json:"kind"`
	Device string   `json:"device,omitempty"`
}

// Counts is how many members of a set change, by what.
type Counts struct {
	Total    int `json:"total"`
	Ring     int `json:"ring"`
	Variant  int `json:"variant"`
	Settings int `json:"settings"`
	Any      int `json:"any"`
}

func (c *Counts) add(ch change) {
	c.Total++
	if ch.ring {
		c.Ring++
	}
	if ch.variant {
		c.Variant++
	}
	if ch.settings {
		c.Settings++
	}
	if ch.any() {
		c.Any++
	}
}

// Example is one affected member.
type Example struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Unit       string   `json:"unit,omitempty"`
	RingBefore string   `json:"ringBefore"`
	RingAfter  string   `json:"ringAfter"`
	Before     []string `json:"variantsBefore,omitempty"` // experiment=variant
	After      []string `json:"variantsAfter,omitempty"`
	Settings   bool     `json:"settingsChanged"`
}

// UnitImpact is the counts of one org unit ("" = in no unit).
type UnitImpact struct {
	Unit string `json:"unit"`
	Counts
}

// Report is the impact of a change on a population.
type Report struct {
	// Source is "fleet" (halo-server's enrolled devices) or "policy" (an
	// estimate from the users and groups policy names plus a hashed sample).
	Source   string            `json:"source"`
	ByKind   map[string]Counts `json:"byKind"`
	ByUnit   []UnitImpact      `json:"byUnit"`
	Examples []Example         `json:"examples"`
}

type state struct {
	ring, unit string
	variants   []string
	settings   string
}

type change struct{ ring, variant, settings bool }

func (c change) any() bool { return c.ring || c.variant || c.settings }

// Compute compares every member under before and after, keeping up to
// examples affected members (sorted by unit, then id).
func Compute(before, after *policy.Org, members []Member, examples int) Report {
	rep := Report{ByKind: map[string]Counts{}, ByUnit: []UnitImpact{}, Examples: []Example{}}
	byUnit := map[string]*Counts{}
	var ex []Example
	for _, m := range members {
		b, a := resolve(before, m), resolve(after, m)
		ch := change{ring: b.ring != a.ring, variant: !slices.Equal(b.variants, a.variants), settings: b.settings != a.settings}
		k := rep.ByKind[m.Kind]
		k.add(ch)
		rep.ByKind[m.Kind] = k
		unit := a.unit
		if unit == "" {
			unit = b.unit
		}
		if m.Kind != KindDevice { // a device's user is counted once, as a user
			if byUnit[unit] == nil {
				byUnit[unit] = &Counts{}
			}
			byUnit[unit].add(ch)
		}
		if ch.any() && m.Kind != KindSample {
			ex = append(ex, Example{ID: m.ID, Kind: m.Kind, Unit: unit, RingBefore: b.ring, RingAfter: a.ring, Before: b.variants, After: a.variants, Settings: ch.settings})
		}
	}
	for u, c := range byUnit {
		rep.ByUnit = append(rep.ByUnit, UnitImpact{Unit: u, Counts: *c})
	}
	sort.Slice(rep.ByUnit, func(i, j int) bool { return rep.ByUnit[i].Unit < rep.ByUnit[j].Unit })
	sort.Slice(ex, func(i, j int) bool {
		if ex[i].Unit != ex[j].Unit {
			return ex[i].Unit < ex[j].Unit
		}
		return ex[i].ID < ex[j].ID
	})
	rep.Examples = append(rep.Examples, ex[:min(examples, len(ex))]...)
	return rep
}

// resolve is m's ring, unit, variants and settings fingerprint under org.
func resolve(org *policy.Org, m Member) state {
	s := policy.Subject{ID: m.ID, Groups: m.Groups}
	if m.Kind == KindAgent {
		s.Kind = policy.SubjectWorkload
	}
	var st state
	ring := org.ResolveRing(s)
	if ring != nil {
		st.ring = ring.Name
	}
	if u := org.ResolveUnit(s); u != nil {
		st.unit = u.Name
	}
	profile := ""
	if ring != nil {
		profile = ring.Profile
	}
	// Workloads get control routing and no variants unless policy enrolls them.
	agentsEnrolled := m.Kind != KindAgent || (org.Workloads != nil && org.Workloads.Experiments)
	var routes []any
	for _, e := range org.Experiments {
		if ring == nil || !agentsEnrolled {
			break
		}
		v := e.ResolveVariant(s, ring.Name)
		if v == nil {
			continue
		}
		st.variants = append(st.variants, e.Name+"="+v.Name)
		if e.Axis == policy.AxisClient && v.Profile != "" && !v.Control {
			profile = v.Profile // the variant's release replaces the ring's on the device
		}
		if len(v.Routes) > 0 {
			routes = append(routes, v.Routes)
		}
	}
	sort.Strings(st.variants)
	st.settings = fingerprint(org, ring, profile, st.unit, routes)
	return st
}

// fingerprint hashes everything that shapes m's effective settings: the
// effective profile (with unit overlays), the ring's pinned release, the
// gateway model routes and the variants' route overrides.
func fingerprint(org *policy.Org, ring *policy.Ring, profile, unit string, routes []any) string {
	if ring == nil {
		return "no ring"
	}
	v := map[string]any{"release": ring.Release, "routes": routes}
	if org.Gateway != nil {
		v["models"] = org.Gateway.Models
	}
	if p, err := org.ResolveProfile(profile); err != nil {
		v["profileError"] = err.Error()
	} else if eff, err := org.EffectiveProfile(p, unit); err != nil {
		v["profileError"] = err.Error()
	} else {
		eff.Meta = policy.Meta{} // names and labels change nothing a member gets
		v["profile"] = eff
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "unencodable: " + err.Error()
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// PolicyMembers is the population a policy-only estimate uses: every user
// id the orgs name (ring and unit members), one member of each group they
// name, each workload rule's subject, and samples anonymous users (hashing
// places them like any user in no listed group).
func PolicyMembers(samples int, orgs ...*policy.Org) []Member {
	users, groups, agents := map[string]bool{}, map[string]bool{}, map[string]Member{}
	for _, o := range orgs {
		for _, r := range o.Rings {
			for _, u := range r.Membership.Users {
				users[u] = true
			}
			for _, g := range r.Membership.Groups {
				groups[g] = true
			}
		}
		for _, u := range o.Units {
			for _, id := range u.Members.Users {
				users[id] = true
			}
			for _, g := range u.Members.Groups {
				groups[g] = true
			}
		}
		for _, t := range o.Toggles {
			for _, r := range t.Rules {
				for _, g := range r.Groups {
					groups[g] = true
				}
			}
		}
		if o.Workloads != nil {
			for _, r := range o.Workloads.Rules {
				agents[r.Subject] = Member{ID: r.Subject, Groups: r.Groups, Kind: KindAgent}
			}
		}
	}
	var out []Member
	for _, u := range sortedKeys(users) {
		out = append(out, Member{ID: u, Kind: KindUser})
	}
	for _, g := range sortedKeys(groups) {
		out = append(out, Member{ID: "member-of:" + g, Groups: []string{g}, Kind: KindGroup})
	}
	for _, a := range sortedKeys(agents) {
		out = append(out, agents[a])
	}
	for i := range samples {
		out = append(out, Member{ID: fmt.Sprintf("sample-%05d", i), Kind: KindSample})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FleetHost is the part of a halo-server fleet host impact reads.
type FleetHost struct {
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	Device   string `json:"device,omitempty"`
}

// FleetDevice is the part of a halo-server device record impact reads.
type FleetDevice struct {
	ID     string   `json:"id"`
	UserID string   `json:"userID"`
	Groups []string `json:"groups,omitempty"`
	// Revoked devices get nothing either way.
	Revoked bool `json:"revoked"`
}

// FleetMembers is the enrolled population: each reporting host as a device
// (groups from its enrollment), each distinct user once (their devices'
// groups), plus the orgs' workload subjects as agents.
func FleetMembers(hosts []FleetHost, devices []FleetDevice, orgs ...*policy.Org) []Member {
	byID := map[string]FleetDevice{}
	for _, d := range devices {
		byID[d.ID] = d
	}
	userGroups := map[string][]string{}
	var out []Member
	for _, h := range hosts {
		if h.User == "" {
			continue
		}
		d, enrolled := byID[h.Device]
		if enrolled && d.Revoked {
			continue
		}
		out = append(out, Member{ID: h.User, Groups: d.Groups, Kind: KindDevice, Device: cmpOr(h.Device, h.Hostname)})
		for _, g := range d.Groups {
			if !slices.Contains(userGroups[h.User], g) {
				userGroups[h.User] = append(userGroups[h.User], g)
			}
		}
		if _, ok := userGroups[h.User]; !ok {
			userGroups[h.User] = nil
		}
	}
	for _, u := range sortedKeys(userGroups) {
		gs := userGroups[u]
		sort.Strings(gs)
		out = append(out, Member{ID: u, Groups: gs, Kind: KindUser})
	}
	for _, m := range PolicyMembers(0, orgs...) {
		if m.Kind == KindAgent {
			out = append(out, m)
		}
	}
	return out
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Text renders r for a terminal.
func (r Report) Text(base string) string {
	var b strings.Builder
	src := "enrolled fleet (halo-server)"
	if r.Source == "policy" {
		src = "policy-only estimate: users and groups policy names, workload subjects, and a hashed sample of other users"
	}
	fmt.Fprintf(&b, "Impact vs %s (%s)\n\n", base, src)
	fmt.Fprintf(&b, "  %-26s %7s %7s %8s %9s\n", "", "TOTAL", "RING", "VARIANT", "SETTINGS")
	for _, k := range []string{KindUser, KindDevice, KindAgent, KindGroup, KindSample} {
		c, ok := r.ByKind[k]
		if !ok {
			continue
		}
		label := map[string]string{KindUser: "users", KindDevice: "devices", KindAgent: "agents (workload rules)",
			KindGroup: "named groups (one member)", KindSample: "other users (sample)"}[k]
		fmt.Fprintf(&b, "  %-26s %7d %7s %8s %9s\n", label, c.Total, share(c.Ring, c.Total, k), share(c.Variant, c.Total, k), share(c.Settings, c.Total, k))
	}
	if len(r.ByUnit) > 0 {
		b.WriteString("\n  by unit (people; devices not repeated):\n")
		for _, u := range r.ByUnit {
			name := u.Unit
			if name == "" {
				name = "(no unit)"
			}
			fmt.Fprintf(&b, "  %-26s %7d %7d %8d %9d\n", name, u.Total, u.Ring, u.Variant, u.Settings)
		}
	}
	if len(r.Examples) > 0 {
		b.WriteString("\n  examples:\n")
		for _, e := range r.Examples {
			var what []string
			if e.RingBefore != e.RingAfter {
				what = append(what, fmt.Sprintf("ring %s -> %s", orNone(e.RingBefore), orNone(e.RingAfter)))
			}
			if !slices.Equal(e.Before, e.After) {
				what = append(what, fmt.Sprintf("variants [%s] -> [%s]", strings.Join(e.Before, " "), strings.Join(e.After, " ")))
			}
			if e.Settings {
				what = append(what, "effective settings change")
			}
			unit := ""
			if e.Unit != "" {
				unit = " (" + e.Unit + ")"
			}
			fmt.Fprintf(&b, "    %s %s%s: %s\n", e.Kind, e.ID, unit, strings.Join(what, "; "))
		}
	}
	return b.String()
}

// share prints a count, as a percentage for the sample (it stands for a share of users).
func share(n, total int, kind string) string {
	if kind == KindSample && total > 0 {
		return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(total))
	}
	return fmt.Sprint(n)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
