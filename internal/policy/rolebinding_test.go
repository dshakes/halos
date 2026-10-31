package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// unitOrg: rings r1..r3, units bu > team > squad and a sibling other.
func unitOrg() *Org {
	return &Org{
		Rings: []*Ring{{Meta: Meta{Name: "r1"}}, {Meta: Meta{Name: "r2"}}, {Meta: Meta{Name: "r3"}}},
		Units: []*Unit{
			{Meta: Meta{Name: "bu"}, Members: UnitMembers{Groups: []string{"g-bu"}}},
			{Meta: Meta{Name: "team"}, Parent: "bu", Members: UnitMembers{Groups: []string{"g-team"}}},
			{Meta: Meta{Name: "squad"}, Parent: "team", Members: UnitMembers{Groups: []string{"g-squad"}}},
			{Meta: Meta{Name: "other"}, Members: UnitMembers{Groups: []string{"g-other"}}},
		},
	}
}

func TestRoleScopeCovers(t *testing.T) {
	ringWide := func(rs ...string) Resource { return RingResource(rs...) }
	member := func(ring string, chain ...string) Resource {
		r := Resource{Units: chain}
		if ring != "" {
			r.Rings = []string{ring}
		}
		return r
	}
	for _, c := range []struct {
		name  string
		scope RoleScope
		res   Resource
		want  bool
	}{
		{"global covers everything", RoleScope{}, Resource{AllRings: true, AllUnits: true}, true},
		{"global covers an unknown reach", RoleScope{}, Resource{}, true},
		{"ring covers its ring-wide resource", RoleScope{Rings: []string{"r1"}}, ringWide("r1"), true},
		{"ring: resource must be wholly inside", RoleScope{Rings: []string{"r1"}}, ringWide("r1", "r2"), false},
		{"two rings cover both", RoleScope{Rings: []string{"r1", "r2"}}, ringWide("r1", "r2"), true},
		{"ring never covers every ring", RoleScope{Rings: []string{"r1", "r2", "r3"}}, Resource{AllRings: true, AllUnits: true}, false},
		{"ring never covers no ring (unknown)", RoleScope{Rings: []string{"r1"}}, Resource{AllUnits: true}, false},
		{"unit covers its member", RoleScope{Units: []string{"bu"}}, member("r1", "bu"), true},
		{"unit covers a descendant's member", RoleScope{Units: []string{"bu"}}, member("r1", "bu", "team", "squad"), true},
		{"descendant does not cover the parent's member", RoleScope{Units: []string{"team"}}, member("r1", "bu"), false},
		{"sibling unit", RoleScope{Units: []string{"other"}}, member("r1", "bu"), false},
		{"unit never covers a ring-wide resource", RoleScope{Units: []string{"bu"}}, ringWide("r1"), false},
		{"unit never covers a member of no unit", RoleScope{Units: []string{"bu"}}, member("r1"), false},
		{"ring and unit: both hold", RoleScope{Rings: []string{"r1"}, Units: []string{"bu"}}, member("r1", "bu", "team"), true},
		{"ring and unit: wrong ring", RoleScope{Rings: []string{"r1"}, Units: []string{"bu"}}, member("r2", "bu"), false},
		{"ring and unit: wrong unit", RoleScope{Rings: []string{"r1"}, Units: []string{"bu"}}, member("r1", "other"), false},
		{"ring and unit: ring-wide", RoleScope{Rings: []string{"r1"}, Units: []string{"bu"}}, ringWide("r1"), false},
		{"unit scope ignores rings of a member", RoleScope{Units: []string{"bu"}}, member("", "bu"), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.scope.Covers(c.res); got != c.want {
				t.Fatalf("%s covers %+v = %v, want %v", c.scope, c.res, got, c.want)
			}
		})
	}
}

func TestScopeWithin(t *testing.T) {
	o := unitOrg()
	for _, c := range []struct {
		name         string
		inner, outer RoleScope
		want         bool
	}{
		{"global in global", RoleScope{}, RoleScope{}, true},
		{"anything in global", RoleScope{Rings: []string{"r1"}, Units: []string{"squad"}}, RoleScope{}, true},
		{"global in a ring", RoleScope{}, RoleScope{Rings: []string{"r1"}}, false},
		{"ring in its ring", RoleScope{Rings: []string{"r1"}}, RoleScope{Rings: []string{"r1", "r2"}}, true},
		{"ring outside", RoleScope{Rings: []string{"r3"}}, RoleScope{Rings: []string{"r1", "r2"}}, false},
		{"descendant unit within", RoleScope{Units: []string{"squad"}}, RoleScope{Units: []string{"bu"}}, true},
		{"parent unit not within child", RoleScope{Units: []string{"bu"}}, RoleScope{Units: []string{"team"}}, false},
		{"sibling unit", RoleScope{Units: []string{"other"}}, RoleScope{Units: []string{"bu"}}, false},
		{"unknown unit is within nothing bounded", RoleScope{Units: []string{"ghost"}}, RoleScope{Units: []string{"bu"}}, false},
		{"rings only, outer has units", RoleScope{Rings: []string{"r1"}}, RoleScope{Units: []string{"bu"}}, false},
		{"unit narrowed by a ring", RoleScope{Units: []string{"team"}, Rings: []string{"r1"}}, RoleScope{Units: []string{"bu"}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := o.ScopeWithin(c.inner, c.outer); got != c.want {
				t.Fatalf("%s within %s = %v, want %v", c.inner, c.outer, got, c.want)
			}
		})
	}
	// Within is consistent with Covers: what inner covers, outer covers.
	for _, res := range []Resource{RingResource("r1"), {Rings: []string{"r1"}, Units: []string{"bu", "team", "squad"}}, {Units: []string{"bu"}}} {
		inner, outer := RoleScope{Units: []string{"squad"}}, RoleScope{Units: []string{"bu"}}
		if inner.Covers(res) && !outer.Covers(res) {
			t.Errorf("%+v: inner covers, outer does not", res)
		}
	}
}

func TestGrants(t *testing.T) {
	id := Identity{
		AdminGroups: []string{"legacy"},
		Roles:       RoleGroups{Viewer: []string{"eng"}, Admin: []string{"plat"}},
		RoleBindings: []RoleBinding{
			{Role: "operator", Groups: []string{"sre"}, Scope: RoleScope{Rings: []string{"r1"}}},
			{Role: "viewer", Users: []string{"Alice@Corp.example"}, Scope: RoleScope{Units: []string{"bu"}}},
			{Role: "viewer", Groups: []string{"eng"}}, // the same global viewer: deduplicated
			{Role: "root", Groups: []string{"sre"}},   // invalid (Validate refuses it); grants nothing
		},
	}
	str := func(gs []Grant) string {
		var out []string
		for _, g := range gs {
			out = append(out, g.Role+"@"+g.Scope.String()+"<"+g.Source)
		}
		return strings.Join(out, " ")
	}
	for _, c := range []struct {
		name string
		sub  Subject
		want string
	}{
		{"nothing", Subject{ID: "x"}, ""},
		{"legacy admin", Subject{ID: "x", Groups: []string{"legacy"}}, "admin@global<identity.adminGroups"},
		{"roles.admin wins the source", Subject{ID: "x", Groups: []string{"legacy", "plat"}}, "admin@global<identity.roles.admin"},
		{"global then scoped", Subject{ID: "x", Groups: []string{"sre", "eng"}}, "viewer@global<identity.roles.viewer operator@rings=r1<identity.roleBindings[0]"},
		{"user binding, case-insensitive", Subject{ID: "alice@corp.example"}, "viewer@units=bu<identity.roleBindings[1]"},
		{"group named like a user does not match users", Subject{ID: "x", Groups: []string{"Alice@Corp.example"}}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := str(id.Grants(c.sub)); got != c.want {
				t.Fatalf("got %q\nwant %q", got, c.want)
			}
		})
	}
	if g := id.RoleBindingGroups(); !slices.Equal(g, []string{"sre", "eng", "sre"}) {
		t.Fatalf("RoleBindingGroups = %v", g)
	}
}

func TestRoleBindingValidation(t *testing.T) {
	for _, c := range []struct {
		name  string
		b     RoleBinding
		paths []string
		warn  bool
	}{
		{"ok", RoleBinding{Role: "operator", Groups: []string{"sre"}, Scope: RoleScope{Rings: []string{"r1"}, Units: []string{"team"}}}, nil, false},
		{"global ok", RoleBinding{Role: "admin", Users: []string{"a@b"}}, nil, false},
		{"unknown role", RoleBinding{Role: "root", Groups: []string{"g"}}, []string{"identity.roleBindings[0].role"}, false},
		{"nobody", RoleBinding{Role: "viewer"}, []string{"identity.roleBindings[0]"}, false},
		{"blank group", RoleBinding{Role: "viewer", Groups: []string{" "}}, []string{"identity.roleBindings[0].groups[0]"}, false},
		{"spaced user", RoleBinding{Role: "viewer", Users: []string{" a@b"}}, []string{"identity.roleBindings[0].users[0]"}, false},
		{"unknown ring", RoleBinding{Role: "viewer", Groups: []string{"g"}, Scope: RoleScope{Rings: []string{"r9"}}}, []string{"identity.roleBindings[0].scope.rings[0]"}, false},
		{"unknown unit", RoleBinding{Role: "viewer", Groups: []string{"g"}, Scope: RoleScope{Units: []string{"ghost"}}}, []string{"identity.roleBindings[0].scope.units[0]"}, false},
		{"duplicate ring", RoleBinding{Role: "viewer", Groups: []string{"g"}, Scope: RoleScope{Rings: []string{"r1", "r1"}}}, []string{"identity.roleBindings[0].scope.rings[1]"}, false},
		{"scoped auditor warns", RoleBinding{Role: "auditor", Groups: []string{"g"}, Scope: RoleScope{Rings: []string{"r1"}}}, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := unitOrg()
			o.Identity.RoleBindings = []RoleBinding{c.b}
			v := &validator{org: o}
			v.identity()
			var errs []string
			warned := false
			for _, i := range v.issues {
				if i.Severity == SeverityError {
					errs = append(errs, i.Path)
				} else if strings.HasPrefix(i.Path, "identity.roleBindings") {
					warned = true
				}
			}
			if !slices.Equal(errs, c.paths) || warned != c.warn {
				t.Fatalf("errors %v (want %v), warned %v (want %v): %+v", errs, c.paths, warned, c.warn, v.issues)
			}
			// Errors here sit under the identity security path: halo-server refuses the policy.
			if len(c.paths) > 0 && !slices.ContainsFunc(SecurityIssues(o), func(i Issue) bool { return strings.HasPrefix(i.Path, "identity.roleBindings") }) {
				t.Fatal("a roleBindings error is not a security issue")
			}
		})
	}
}

// TestProfileReach (review M1): an edit to a profile reaches rings on it, on
// any profile extending it, and the rings of experiments with a variant on one.
func TestProfileReach(t *testing.T) {
	o := &Org{
		Profiles: map[string]*Profile{
			"base": {Meta: Meta{Name: "base"}}, "eng": {Meta: Meta{Name: "eng"}, Extends: "base"},
			"eng-next": {Meta: Meta{Name: "eng-next"}, Extends: "eng"}, "other": {Meta: Meta{Name: "other"}},
			"broken": {Meta: Meta{Name: "broken"}, Extends: "missing"},
		},
		Rings: []*Ring{
			{Meta: Meta{Name: "r0"}, Profile: "eng-next"}, {Meta: Meta{Name: "r1"}, Profile: "eng"},
			{Meta: Meta{Name: "r2"}, Profile: "other"}, {Meta: Meta{Name: "r3"}, Profile: "other"}, {Meta: Meta{Name: "r4"}, Profile: "broken"},
		},
		Experiments: []*Experiment{{Meta: Meta{Name: "e"}, Rings: []string{"r2"}, Variants: []Variant{{Name: "c", Control: true}, {Name: "t", Profile: "eng-next"}}}},
	}
	for _, c := range []struct {
		profile string
		want    []string
	}{
		{"eng-next", []string{"r0", "r2", "r4"}},  // its ring, the experiment's ring, and the unresolvable chain (fail closed)
		{"eng", []string{"r0", "r1", "r2", "r4"}}, // eng-next extends eng
		{"base", []string{"r0", "r1", "r2", "r4"}},
		{"other", []string{"r2", "r3", "r4"}},
	} {
		if got := o.ProfileReach(c.profile); !slices.Equal(got, c.want) {
			t.Errorf("ProfileReach(%s) = %v, want %v", c.profile, got, c.want)
		}
	}
}

// TestQuorumScoped: a scoped approval counts only for changes its scope covers.
func TestQuorumScoped(t *testing.T) {
	o := govOrg(&Governance{Approvals: []ApprovalRule{{Name: "two", Scope: ChangeScope{Rings: []string{"ring1"}}, Quorum: 2, Groups: []string{"leads"}}}})
	at := time.Unix(0, 0)
	global := ScopedApproval("g@x", []string{"leads"}, at, "", nil)
	inScope := ScopedApproval("s1@x", []string{"leads"}, at, "", []RoleScope{{Rings: []string{"ring1"}}})
	outScope := ScopedApproval("s2@x", []string{"leads"}, at, "", []RoleScope{{Rings: []string{"ring2"}}})
	noScopes := ScopedApproval("s3@x", []string{"leads"}, at, "", []RoleScope{})
	res := RingResource("ring1")
	for _, c := range []struct {
		name string
		res  *Resource
		as   []Approval
		have int
	}{
		{"global approvals count as before", &res, []Approval{global}, 1},
		{"in-scope approval counts", &res, []Approval{global, inScope}, 2},
		{"out-of-scope approval is ignored", &res, []Approval{global, outScope}, 1},
		{"no resource: scoped never count", nil, []Approval{global, inScope}, 1},
		{"an empty scope list covers nothing", &res, []Approval{global, noScopes}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := o.QuorumFor(c.res, o.RingTarget("ring1"), "", "", c.as)
			if q == nil || q.Rules[0].Have != c.have {
				t.Fatalf("%+v", q)
			}
			if len(c.as) != c.have && len(q.Ignored) == 0 {
				t.Fatalf("ignored approvals not explained: %+v", q)
			}
		})
	}
	// Quorum (no resource) is QuorumFor(nil): unchanged for global approvals.
	if q := o.Quorum(o.RingTarget("ring1"), "", "", []Approval{global, inScope}); q.Rules[0].Have != 1 {
		t.Fatalf("Quorum counted a scoped approval: %+v", q)
	}

	// Skew: a binary from before ADR-0037 ignores scopes; it must find no
	// groups on a scoped approval (so it counts for no rule), and an empty
	// scope list must not read back as global.
	for _, a := range []Approval{inScope, noScopes} {
		b, _ := json.Marshal(a)
		var old struct{ Groups []string }
		var back Approval
		if json.Unmarshal(b, &old) != nil || len(old.Groups) != 0 || json.Unmarshal(b, &back) != nil || back.Scopes == nil {
			t.Fatalf("%s: old groups %v, scopes read back %v", b, old.Groups, back.Scopes)
		}
	}
}
