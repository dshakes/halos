package policy

import (
	"fmt"
	"slices"
	"strings"
)

// Scoped role bindings for halo-server's console (ADR-0037).

// ConsoleRoles are halo-server's roles (ADR-0015), in display order.
// internal/server's Roles is this list.
var ConsoleRoles = []string{"viewer", "operator", "approver", "auditor", "admin"}

// RoleBinding grants Role over Scope to every listed group and user
// (identity.roleBindings). An empty scope is global: the binding means
// exactly what the same group under identity.roles means.
type RoleBinding struct {
	Role   string    `yaml:"role" json:"role"`
	Groups []string  `yaml:"groups,omitempty" json:"groups,omitempty"`
	Users  []string  `yaml:"users,omitempty" json:"users,omitempty"`
	Scope  RoleScope `yaml:"scope,omitempty" json:"scope,omitzero"`
}

// RoleScope bounds a binding: the rings and the units (each with its
// descendants) whose resources it covers. Within a list any value matches;
// across the two lists both must, so {rings: [canary], units: [payments]} is
// payments' resources in canary. Empty is global.
//
// Deliberately not ChangeScope: an approval rule's scope selects changes it
// covers (any listed ring OR unit, ADR-0030); a role scope bounds authority,
// so it is the narrower conjunction and a resource must fall entirely inside it.
type RoleScope struct {
	Rings []string `yaml:"rings,omitempty" json:"rings,omitempty"`
	Units []string `yaml:"units,omitempty" json:"units,omitempty"`
}

// Global reports whether s is unbounded.
func (s RoleScope) Global() bool { return len(s.Rings) == 0 && len(s.Units) == 0 }

// String is s for audit entries and the CLI: "global", or
// "rings=a,b units=c" (sorted, so equal scopes print the same).
func (s RoleScope) String() string {
	if s.Global() {
		return "global"
	}
	var parts []string
	if len(s.Rings) > 0 {
		r := slices.Sorted(slices.Values(s.Rings))
		parts = append(parts, "rings="+strings.Join(r, ","))
	}
	if len(s.Units) > 0 {
		u := slices.Sorted(slices.Values(s.Units))
		parts = append(parts, "units="+strings.Join(u, ","))
	}
	return strings.Join(parts, " ")
}

// Resource is what an authorization decision is about: the rings and units
// whose members it affects. halo-server derives it from current policy and
// its own records, never from the client (a ring in a request body or a
// device's self-reported ring is not trusted).
type Resource struct {
	// Rings it affects; AllRings: members of every ring, and of none (an
	// org-wide toggle, a profile shared by several rings, a change whose
	// reach is unknown).
	Rings    []string `json:"rings,omitempty"`
	AllRings bool     `json:"allRings,omitempty"`
	// Units is the unit chain (root first) of the one member it concerns
	// (a device, an access request). AllUnits: members of every unit and of
	// none: rings, experiments, rollouts and toggles draw from the whole org
	// (ADR-0018), so no unit owns them.
	Units    []string `json:"units,omitempty"`
	AllUnits bool     `json:"allUnits,omitempty"`
}

// RingResource is a change to rings: every unit's members, as RingTarget.
func RingResource(rings ...string) Resource { return Resource{Rings: rings, AllUnits: true} }

// Covers reports whether r lies entirely inside s. A bounded dimension
// never covers a resource that is unbounded, or unknown, in it: deny by
// default when the scope of a resource cannot be determined.
func (s RoleScope) Covers(r Resource) bool {
	if len(s.Rings) > 0 {
		if r.AllRings || len(r.Rings) == 0 {
			return false
		}
		for _, x := range r.Rings {
			if !slices.Contains(s.Rings, x) {
				return false
			}
		}
	}
	if len(s.Units) > 0 {
		// The chain holds the member's unit and every ancestor, so a scope
		// unit covers its own members and its descendants' members.
		if r.AllUnits || len(r.Units) == 0 || !slices.ContainsFunc(s.Units, func(u string) bool { return slices.Contains(r.Units, u) }) {
			return false
		}
	}
	return true
}

// ScopeWithin reports whether every resource inner covers, outer covers too:
// inner's rings are outer's (or outer is ring-unbounded), and each of inner's
// units is one of outer's or a descendant of one. A service token's scope must
// be within its creator's (ADR-0037). An unknown unit is never within anything bounded.
func (o *Org) ScopeWithin(inner, outer RoleScope) bool {
	if len(outer.Rings) > 0 {
		if len(inner.Rings) == 0 {
			return false
		}
		for _, r := range inner.Rings {
			if !slices.Contains(outer.Rings, r) {
				return false
			}
		}
	}
	if len(outer.Units) > 0 {
		if len(inner.Units) == 0 {
			return false
		}
		for _, u := range inner.Units {
			if !slices.ContainsFunc(o.unitChainNames(u), func(c string) bool { return slices.Contains(outer.Units, c) }) {
				return false
			}
		}
	}
	return true
}

// unitChainNames is name's chain (root first), or nil when it does not resolve.
func (o *Org) unitChainNames(name string) []string {
	if o == nil {
		return nil
	}
	chain, err := o.UnitChain(name)
	if err != nil {
		return nil
	}
	out := make([]string, len(chain))
	for i, u := range chain {
		out[i] = u.Name
	}
	return out
}

// SubjectResource is the resource a change for one member is: their ring and
// unit chain under o (nil Rings/Units when none resolves).
func (o *Org) SubjectResource(s Subject) Resource {
	var r Resource
	if ring := o.ResolveRing(s); ring != nil {
		r.Rings = []string{ring.Name}
	}
	if u := o.ResolveUnit(s); u != nil {
		r.Units = o.unitChainNames(u.Name)
	}
	return r
}

// Grant is one console role a subject holds over a scope, and the policy
// field it comes from (for /me, `halo whoami` and audit entries).
type Grant struct {
	Role   string    `json:"role"`
	Scope  RoleScope `json:"scope"`
	Source string    `json:"source"`
}

// Grants returns every console role s holds under id: the global grants of
// identity.adminGroups and identity.roles (in ConsoleRoles order), then
// each identity.roleBindings entry that selects s by group or user, in file
// order. Exact duplicates (same role and scope) are dropped.
func (id Identity) Grants(s Subject) []Grant {
	has := func(gs []string) bool {
		return slices.ContainsFunc(gs, func(g string) bool { return slices.Contains(s.Groups, g) })
	}
	var out []Grant
	add := func(g Grant) {
		if !slices.ContainsFunc(out, func(x Grant) bool { return x.Role == g.Role && sameScope(x.Scope, g.Scope) }) {
			out = append(out, g)
		}
	}
	r := id.Roles
	for _, x := range []struct {
		role   string
		groups []string
	}{{"viewer", r.Viewer}, {"operator", r.Operator}, {"approver", r.Approver}, {"auditor", r.Auditor}, {"admin", r.Admin}} {
		if has(x.groups) {
			add(Grant{Role: x.role, Source: "identity.roles." + x.role})
		} else if x.role == "admin" && has(id.AdminGroups) {
			add(Grant{Role: x.role, Source: "identity.adminGroups"})
		}
	}
	me := CanonicalUser(s.ID)
	for i, b := range id.RoleBindings {
		user := me != "" && slices.ContainsFunc(b.Users, func(u string) bool { return CanonicalUser(u) == me })
		if !slices.Contains(ConsoleRoles, b.Role) || (!user && !has(b.Groups)) {
			continue
		}
		add(Grant{Role: b.Role, Scope: RoleScope{Rings: slices.Clone(b.Scope.Rings), Units: slices.Clone(b.Scope.Units)}, Source: fmt.Sprintf("identity.roleBindings[%d]", i)})
	}
	return out
}

func sameScope(a, b RoleScope) bool { return a.String() == b.String() }

// RoleBindingGroups is every group a role binding selects (halo-server keeps
// these in the session, like the identity.roles groups).
func (id Identity) RoleBindingGroups() []string {
	var out []string
	for _, b := range id.RoleBindings {
		out = append(out, b.Groups...)
	}
	return out
}

// roleBindings validates identity.roleBindings. It sits under the identity
// security path: halo-server refuses a policy with an error here and keeps
// serving the last good one.
func (v *validator) roleBindings() {
	rings := map[string]bool{}
	for _, r := range v.org.Rings {
		rings[r.Name] = true
	}
	for i, b := range v.org.Identity.RoleBindings {
		p := fmt.Sprintf("identity.roleBindings[%d]", i)
		if !slices.Contains(ConsoleRoles, b.Role) {
			v.errf(p+".role", "%q is not a role (want one of %s)", b.Role, strings.Join(ConsoleRoles, ", "))
		}
		if len(b.Groups) == 0 && len(b.Users) == 0 {
			v.errf(p, "a binding needs at least one group or user")
		}
		for j, g := range b.Groups {
			if strings.TrimSpace(g) == "" || g != strings.TrimSpace(g) {
				v.errf(fmt.Sprintf("%s.groups[%d]", p, j), "%q: group names are non-empty, without surrounding space", g)
			}
		}
		for j, u := range b.Users {
			if strings.TrimSpace(u) == "" || u != strings.TrimSpace(u) {
				v.errf(fmt.Sprintf("%s.users[%d]", p, j), "%q: user ids are non-empty, without surrounding space", u)
			}
		}
		seen := map[string]bool{}
		for j, r := range b.Scope.Rings {
			if !rings[r] {
				v.errf(fmt.Sprintf("%s.scope.rings[%d]", p, j), "ring %q not defined", r)
			}
			if seen["r:"+r] {
				v.errf(fmt.Sprintf("%s.scope.rings[%d]", p, j), "ring %q is listed twice", r)
			}
			seen["r:"+r] = true
		}
		for j, u := range b.Scope.Units {
			if v.org.Unit(u) == nil {
				v.errf(fmt.Sprintf("%s.scope.units[%d]", p, j), "unit %q not defined", u)
			}
			if seen["u:"+u] {
				v.errf(fmt.Sprintf("%s.scope.units[%d]", p, j), "unit %q is listed twice", u)
			}
			seen["u:"+u] = true
		}
		if b.Role == "auditor" && !b.Scope.Global() {
			v.warnf(p+".scope", "the audit log and the session ledger are global only (ADR-0037): a scoped auditor binding grants nothing")
		}
	}
}
