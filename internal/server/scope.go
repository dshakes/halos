package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/rollout"
)

// Scoped role bindings (ADR-0037). routePerms says which permission a route
// needs; routeScopes says over what: how the route's resource is found and
// which rings and units it touches. A grant authorizes a request when its
// role has the permission AND its scope covers the resource. A global grant
// covers everything without the resource being looked up, so a policy with
// no scoped bindings behaves exactly as before ADR-0037.

type scopeKind int

const (
	// scopeSelf: the caller's own data (permSession routes).
	scopeSelf scopeKind = iota + 1
	// scopeGlobal: needs a global grant; the route's data or effect cannot be
	// bounded to rings or units (why says so).
	scopeGlobal
	// scopePath: of derives the resource from the path (and server-side
	// records), checked in s.route before the handler runs.
	scopePath
	// scopeFiltered: a list; the handler drops every item outside the
	// caller's scope (counts and aggregates are recomputed from what is left).
	scopeFiltered
	// scopeHandler: the resource is in the body or needs the handler's own
	// lookup; the handler checks it (why names where).
	scopeHandler
)

// resourceFunc derives a route's resource from current policy and the
// server's records. An error is "cannot determine": the request is denied
// to every non-global caller.
type resourceFunc func(s *Server, r *http.Request) (policy.Resource, error)

type scopeRule struct {
	kind scopeKind
	of   resourceFunc // scopePath only
	why  string       // scopeGlobal, scopeHandler: the reason, for reviewers
}

func self() scopeRule                  { return scopeRule{kind: scopeSelf} }
func global(why string) scopeRule      { return scopeRule{kind: scopeGlobal, why: why} }
func byPath(of resourceFunc) scopeRule { return scopeRule{kind: scopePath, of: of} }
func filtered() scopeRule              { return scopeRule{kind: scopeFiltered} }
func inHandler(why string) scopeRule   { return scopeRule{kind: scopeHandler, why: why} }

// routeScopes is the scope half of the authorization table: every routePerms
// entry has one (TestRouteScopesCoverPerms). A route missing here is denied
// to everyone but global grants.
var routeScopes = map[string]scopeRule{
	"GET /api/v1/capabilities":       self(),
	"GET /api/v1/harnesses":          self(),
	"GET /api/v1/whoami":             inHandler("another user needs a global read grant: the subject and groups come from the query, so they cannot bound a scope"),
	"GET /api/v1/me":                 self(),
	"GET /api/v1/me/devices":         self(),
	"GET /api/v1/catalog":            self(),
	"POST /api/v1/launch/{launcher}": self(),
	"POST /api/v1/requests":          self(),
	"GET /api/v1/requests":           inHandler("own requests always; others' where an approve grant covers the request"),

	"GET /api/v1/fleet":              filtered(),
	"GET /api/v1/budgets":            global("spend is aggregated per user, group, ring and org; a per-scope view would leak through the totals"),
	"GET /api/v1/devices":            filtered(),
	"GET /api/v1/devices/{id}":       byPath((*Server).deviceResourceByID),
	"GET /api/v1/policy":             global("the whole policy snapshot (every ring, unit, identity mapping)"),
	"GET /api/v1/releases":           filtered(),
	"GET /api/v1/experiments":        filtered(),
	"GET /api/v1/experiments/{name}": byPath((*Server).experimentResourceByName),
	"GET /api/v1/rollouts":           filtered(),
	"GET /api/v1/rollouts/{name}":    byPath((*Server).rolloutResourceByName),
	"GET /api/v1/toggles":            filtered(),
	"GET /api/v1/toggles/{name}":     byPath((*Server).toggleResourceByName),
	"GET /api/v1/killswitch":         filtered(),
	"GET /api/v1/freeze":             filtered(),
	"GET /api/v1/cloud-agents":       global("cloud agent tasks are keyed by vendor repo and user, not ring or unit"),

	"GET /api/v1/rollouts/{name}/approvals": byPath((*Server).rolloutStepResourceByName),

	"POST /api/v1/experiments/{name}/status": byPath((*Server).experimentResourceByName),
	"POST /api/v1/experiments/{name}/kill":   byPath((*Server).experimentResourceByName),
	"POST /api/v1/experiments/{name}/unkill": byPath((*Server).experimentResourceByName),
	"POST /api/v1/toggles/{name}/kill":       byPath((*Server).toggleResourceByName),
	"POST /api/v1/toggles/{name}/unkill":     byPath((*Server).toggleResourceByName),
	"POST /api/v1/cloud-agents/kill":         global("cancels vendor tasks selected by experiment, repo or user across the org"),

	"POST /api/v1/requests/{id}/approve":   byPath((*Server).requestResourceByID),
	"POST /api/v1/requests/{id}/deny":      byPath((*Server).requestResourceByID),
	"POST /api/v1/rollouts/{name}/approve": byPath((*Server).rolloutStepResourceByName),

	"GET /api/v1/audit":         global("the audit log is one hash chain; separation of duties keeps its review whole"),
	"GET /api/v1/sessions":      global("the session ledger lives in the audit chain"),
	"GET /api/v1/sessions/{id}": global("the session ledger lives in the audit chain"),

	"POST /api/v1/devices/{id}/revoke":        byPath((*Server).deviceResourceByID),
	"POST /api/v1/users/{id}/revoke-sessions": global("a user id alone has no server-side ring or unit (groups live in the session)"),
	"POST /api/v1/toggles/{name}/propose":     global("the proposed rules may target any ring, group or user"),
	"POST /api/v1/sessions":                   global("ingests records for any user"),
	"POST /api/v1/freeze":                     global("the incident freeze holds every ring"),
	"POST /api/v1/revocations":                global("revokes a credential for any subject"),
	"GET /api/v1/revocations":                 global("lists revocations for every subject"),
	"POST /api/v1/service-tokens":             inHandler("the token's scope (body) must be within the creator's admin grants and its role's permissions"),
	"GET /api/v1/service-tokens":              filtered(),
	"POST /api/v1/service-tokens/{id}/revoke": inHandler("the token's recorded scope must be within one of the caller's admin grants"),
	"POST /api/v1/breakglass/unlock":          global("the break-glass lock is global"),
}

// Reasons recorded as authz.deny's "scope" detail.
const (
	scopeWhyGlobal  = "global"       // the route needs a global grant
	scopeWhyUnknown = "unknown"      // the resource's scope could not be determined
	scopeWhyOutside = "out of scope" // no grant covers the resource
)

var errNoResource = errors.New("resource not found")

// authorizeScope is s.route's second check, after p.can(need). It returns r
// carrying the authorizing grant (for audit entries) and true, or writes the
// audited 403 and returns false.
func (s *Server) authorizeScope(w http.ResponseWriter, r *http.Request, p Principal, pattern string, need perm) (*http.Request, bool) {
	if need == permSession {
		return r, true
	}
	if g, ok := p.globalGrant(need); ok {
		return withAuthz(r, p, g), true // global: no lookup, exactly the pre-ADR-0037 behaviour
	}
	rule, ok := routeScopes[pattern]
	if !ok {
		s.cfg.Log.Error("route has no routeScopes entry; denying scoped callers", "route", pattern)
		s.denyScope(w, r, p, pattern, need, scopeWhyGlobal, nil)
		return r, false
	}
	switch rule.kind {
	case scopePath:
		res, err := rule.of(s, r)
		if err != nil {
			s.denyScope(w, r, p, pattern, need, scopeWhyUnknown, nil)
			return r, false
		}
		g, ok := p.grantOn(need, res)
		if !ok {
			s.denyScope(w, r, p, pattern, need, scopeWhyOutside, &res)
			return r, false
		}
		return withAuthz(r, p, g), true
	case scopeFiltered, scopeHandler:
		return r, true // the handler narrows or checks
	default: // scopeGlobal, and scopeSelf on a non-session route (a table mistake): global only
		s.denyScope(w, r, p, pattern, need, scopeWhyGlobal, nil)
		return r, false
	}
}

// ---- grants ----

// grantsFor is p's grants whose role holds x.
func (p Principal) grantsFor(x perm) []policy.Grant {
	var out []policy.Grant
	for _, g := range p.Bindings {
		if slices.Contains(rolePerms[g.Role], x) {
			out = append(out, g)
		}
	}
	return out
}

// globalGrant is p's first global grant holding x.
func (p Principal) globalGrant(x perm) (policy.Grant, bool) {
	for _, g := range p.grantsFor(x) {
		if g.Scope.Global() {
			return g, true
		}
	}
	return policy.Grant{}, false
}

func (p Principal) canGlobal(x perm) bool { _, ok := p.globalGrant(x); return ok }

// grantOn is p's first grant holding x whose scope covers res (a global one first).
func (p Principal) grantOn(x perm, res policy.Resource) (policy.Grant, bool) {
	if g, ok := p.globalGrant(x); ok {
		return g, true
	}
	for _, g := range p.grantsFor(x) {
		if g.Scope.Covers(res) {
			return g, true
		}
	}
	return policy.Grant{}, false
}

func (p Principal) canOn(x perm, res policy.Resource) bool { _, ok := p.grantOn(x, res); return ok }

// approveScopes is what an approval by p records (policy.Approval.Scopes):
// nil for a global approver, else the scope of every scoped approve grant.
func (p Principal) approveScopes() []policy.RoleScope {
	if p.canGlobal(permApprove) {
		return nil
	}
	out := []policy.RoleScope{}
	for _, g := range p.grantsFor(permApprove) {
		out = append(out, g.Scope)
	}
	return out
}

// grantSummary is gs for audit details: "role@scope (source)", ';'-separated.
func grantSummary(gs []policy.Grant) string {
	parts := make([]string, 0, len(gs))
	for _, g := range gs {
		parts = append(parts, g.Role+"@"+g.Scope.String()+" ("+g.Source+")")
	}
	return strings.Join(parts, "; ")
}

func resourceString(r policy.Resource) string {
	rings := "rings=" + strings.Join(r.Rings, ",")
	if r.AllRings {
		rings = "rings=*"
	}
	units := "units=" + strings.Join(r.Units, ",")
	if r.AllUnits {
		units = "units=*"
	}
	return rings + " " + units
}

// ---- the authorizing grant, carried to audit entries ----

type authzKey struct{}

type authzInfo struct {
	actor string
	grant policy.Grant
}

// withAuthz records on r that p's grant g authorized it: every audit entry
// the handler writes as p then names a scoped grant (authzScope,
// authzBinding). A global grant adds nothing, so entries read exactly as
// before ADR-0037 unless a scoped binding was what let the action through.
func withAuthz(r *http.Request, p Principal, g policy.Grant) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authzKey{}, authzInfo{actor: p.ID, grant: g}))
}

// authzDetails adds the authorizing scoped grant to details (a copy) when
// ctx carries one for actor.
func authzDetails(ctx context.Context, actor string, details map[string]string) map[string]string {
	a, ok := ctx.Value(authzKey{}).(authzInfo)
	if !ok || a.actor != actor || a.grant.Scope.Global() {
		return details
	}
	out := make(map[string]string, len(details)+3)
	maps.Copy(out, details)
	out["authzRole"], out["authzScope"], out["authzBinding"] = a.grant.Role, a.grant.Scope.String(), a.grant.Source
	return out
}

// ---- resources ----

func (s *Server) org() (*policy.Org, error) {
	org, _, err := s.pol.Get()
	if org == nil {
		return nil, fmt.Errorf("policy not loaded: %w", err)
	}
	return org, nil
}

// experimentResource: the experiment's rings, every unit's members.
func experimentResource(org *policy.Org, name string) (policy.Resource, error) {
	for _, e := range org.Experiments {
		if e.Name == name {
			return policy.RingResource(slices.Clone(e.Rings)...), nil
		}
	}
	return policy.Resource{}, errNoResource
}

func (s *Server) experimentResourceByName(r *http.Request) (policy.Resource, error) {
	org, err := s.org()
	if err != nil {
		return policy.Resource{}, err
	}
	return experimentResource(org, r.PathValue("name"))
}

// toggleResource: the rings its rules select. A default-on toggle, or a rule
// without a ring condition (groups, users or everyone), reaches every ring.
func toggleResource(org *policy.Org, name string) (policy.Resource, error) {
	i := slices.IndexFunc(org.Toggles, func(t *policy.Toggle) bool { return t.Name == name })
	if i < 0 {
		return policy.Resource{}, errNoResource
	}
	t := org.Toggles[i]
	res := policy.Resource{AllUnits: true, AllRings: t.Default}
	for _, rule := range t.Rules {
		if len(rule.Rings) == 0 {
			res.AllRings = true
		}
		for _, rg := range rule.Rings {
			if !slices.Contains(res.Rings, rg) {
				res.Rings = append(res.Rings, rg)
			}
		}
	}
	return res, nil
}

func (s *Server) toggleResourceByName(r *http.Request) (policy.Resource, error) {
	org, err := s.org()
	if err != nil {
		return policy.Resource{}, err
	}
	return toggleResource(org, r.PathValue("name"))
}

// rolloutResource: every ring any of its steps exposes.
func rolloutResource(org *policy.Org, ro *policy.Rollout) policy.Resource {
	var rings []string
	for i := -1; i < len(ro.Steps)-1; i++ {
		for _, rg := range rollout.Target(org, ro, i).Rings {
			if !slices.Contains(rings, rg) {
				rings = append(rings, rg)
			}
		}
	}
	return policy.RingResource(rings...)
}

func findRolloutIn(org *policy.Org, name string) *policy.Rollout {
	for _, ro := range org.Rollouts {
		if ro.Name == name {
			return ro
		}
	}
	return nil
}

func (s *Server) rolloutResourceByName(r *http.Request) (policy.Resource, error) {
	org, err := s.org()
	if err != nil {
		return policy.Resource{}, err
	}
	ro := findRolloutIn(org, r.PathValue("name"))
	if ro == nil {
		return policy.Resource{}, errNoResource
	}
	return rolloutResource(org, ro), nil
}

// rolloutStepResourceByName: what approving the rollout's next step touches
// (the rings it enters), the same resource QuorumFor counts approvals against.
func (s *Server) rolloutStepResourceByName(r *http.Request) (policy.Resource, error) {
	org, err := s.org()
	if err != nil {
		return policy.Resource{}, err
	}
	ro := findRolloutIn(org, r.PathValue("name"))
	if ro == nil {
		return policy.Resource{}, errNoResource
	}
	return rollout.TargetResource(org, ro, ro.StepIndex(ro.Step)), nil
}

// deviceResource: the device owner's ring and unit chain, resolved now from
// policy and the groups the server holds for them (SCIM wins). Never the ring
// the device reports: a device holder controls that.
func (s *Server) deviceResource(org *policy.Org, d Device) (policy.Resource, error) {
	g, ok := s.directoryGroups(d.UserID, d.Groups)
	if !ok {
		return policy.Resource{}, errors.New("device owner not provisioned")
	}
	return org.SubjectResource(policy.Subject{ID: d.UserID, Groups: g}), nil
}

func (s *Server) deviceResourceByID(r *http.Request) (policy.Resource, error) {
	org, err := s.org()
	if err != nil {
		return policy.Resource{}, err
	}
	d, ok := s.devices.get(r.PathValue("id"))
	if !ok {
		return policy.Resource{}, errNoResource
	}
	return s.deviceResource(org, d)
}

// requestResource is what deciding req changes, from the server's own record
// of it (never the decision's body):
//   - ring-opt-in adds the requester to the requested ring: their ring when
//     filed and that ring, their unit chain;
//   - mcp-server adds the server to their ring's profile, which every ring
//     on that profile, and every unit, shares;
//   - anything else has no automatic change, so its reach is unknown: global only.
func requestResource(org *policy.Org, req *Request) (policy.Resource, error) {
	switch req.Kind {
	case "ring-opt-in":
		res := policy.Resource{AllUnits: true}
		if req.Target != nil {
			res.Rings = slices.Clone(req.Target.Rings)
			res.Units, res.AllUnits = slices.Clone(req.Target.Units), false
		} else if req.Ring != "" {
			res.Rings = []string{req.Ring}
		}
		if !slices.Contains(res.Rings, req.Item) {
			res.Rings = append(res.Rings, req.Item)
		}
		return res, nil
	case "mcp-server":
		ring := ringByName(org, req.Ring)
		if ring == nil {
			return policy.Resource{}, errors.New("requester's ring is unknown")
		}
		var rings []string
		for _, rg := range org.Rings {
			if rg.Profile == ring.Profile {
				rings = append(rings, rg.Name)
			}
		}
		return policy.RingResource(rings...), nil
	default:
		return policy.Resource{AllRings: true, AllUnits: true}, nil
	}
}

func (s *Server) requestResourceByID(r *http.Request) (policy.Resource, error) {
	org, err := s.org()
	if err != nil {
		return policy.Resource{}, err
	}
	l := s.reqs
	l.mu.Lock()
	if err := l.catchup(); err != nil {
		l.mu.Unlock()
		return policy.Resource{}, err
	}
	req, ok := l.byID[r.PathValue("id")]
	var c Request
	if ok {
		c = *req
	}
	l.mu.Unlock()
	if !ok {
		return policy.Resource{}, errNoResource
	}
	return requestResource(org, &c)
}

// ---- list filters ----

// readFilter answers whether p may see an item of a list route under perm x:
// everything with a global grant, else items whose resource a grant covers.
type readFilter struct {
	p   Principal
	x   perm
	all bool
}

func newReadFilter(p Principal, x perm) readFilter {
	return readFilter{p: p, x: x, all: p.canGlobal(x)}
}

// ok reports whether the item with resource res (err: undeterminable) is visible.
func (f readFilter) ok(res policy.Resource, err error) bool {
	if f.all {
		return true
	}
	return err == nil && f.p.canOn(f.x, res)
}
