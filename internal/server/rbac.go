package server

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// Roles (ADR-0015). Policy identity.roles maps IdP groups to them;
// identity.adminGroups also grants RoleAdmin.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleApprover = "approver"
	RoleAuditor  = "auditor"
	RoleAdmin    = "admin"
)

// Roles lists every role in display order.
var Roles = []string{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin}

// perm is what a route needs. Roles grant permissions; routes never name roles,
// so adding a role is one rolePerms line and no route changes.
type perm string

const (
	permSession perm = "session" // any logged-in user: self-service and own data
	permRead    perm = "read"    // fleet, devices, releases, rollouts, experiments, toggles, policy, other users' assignments
	permOperate perm = "operate" // kill switch, experiment status
	permApprove perm = "approve" // decide access requests, see everyone's requests
	permAudit   perm = "audit"   // read and export the audit log
	permAdmin   perm = "admin"   // device and session revocation, toggle proposals, launcher setup
)

// rolePerms: auditor deliberately lacks read (separation of duties: map the
// same group to viewer too if an auditor should also see the fleet).
var rolePerms = map[string][]perm{
	RoleViewer:   {permRead},
	RoleOperator: {permRead, permOperate},
	RoleApprover: {permRead, permApprove},
	RoleAuditor:  {permAudit},
	RoleAdmin:    {permRead, permOperate, permApprove, permAudit, permAdmin},
}

// routePerms is the authorization table: every console/API route that takes a
// session cookie, and the permission it needs. A route registered through
// s.route but missing here is denied to everyone (TestRoutePermsCoverMux keeps
// the two in step). Public and token-authenticated routes are not in it.
var routePerms = map[string]perm{
	"GET /api/v1/capabilities":       permSession,
	"GET /api/v1/harnesses":          permSession,
	"GET /api/v1/whoami":             permSession, // other users need permRead, checked in the handler
	"GET /api/v1/me":                 permSession,
	"GET /api/v1/me/devices":         permSession,
	"GET /api/v1/catalog":            permSession,
	"POST /api/v1/launch/{launcher}": permSession,
	"POST /api/v1/requests":          permSession,
	"GET /api/v1/requests":           permSession, // everyone's need permApprove, filtered in the handler

	"GET /api/v1/fleet":              permRead,
	"GET /api/v1/budgets":            permRead, // spend per user, group, ring and org (ADR-0017)
	"GET /api/v1/devices":            permRead,
	"GET /api/v1/devices/{id}":       permRead,
	"GET /api/v1/policy":             permRead,
	"GET /api/v1/releases":           permRead,
	"GET /api/v1/experiments":        permRead,
	"GET /api/v1/experiments/{name}": permRead,
	"GET /api/v1/rollouts":           permRead,
	"GET /api/v1/rollouts/{name}":    permRead,
	"GET /api/v1/toggles":            permRead,
	"GET /api/v1/toggles/{name}":     permRead,
	"GET /api/v1/killswitch":         permRead,

	"POST /api/v1/experiments/{name}/status": permOperate,
	"POST /api/v1/experiments/{name}/kill":   permOperate,
	"POST /api/v1/experiments/{name}/unkill": permOperate,
	"POST /api/v1/toggles/{name}/kill":       permOperate,
	"POST /api/v1/toggles/{name}/unkill":     permOperate,

	"POST /api/v1/requests/{id}/approve": permApprove,
	"POST /api/v1/requests/{id}/deny":    permApprove,

	"GET /api/v1/audit": permAudit,

	"POST /api/v1/devices/{id}/revoke":        permAdmin,
	"POST /api/v1/users/{id}/revoke-sessions": permAdmin,
	"POST /api/v1/toggles/{name}/propose":     permAdmin,
}

// rolesFor returns the roles groups hold under id, in Roles order.
func rolesFor(id policy.Identity, groups []string) []string {
	has := func(gs []string) bool {
		return slices.ContainsFunc(gs, func(g string) bool { return slices.Contains(groups, g) })
	}
	var out []string
	for _, r := range []struct {
		name   string
		groups []string
	}{
		{RoleViewer, id.Roles.Viewer}, {RoleOperator, id.Roles.Operator}, {RoleApprover, id.Roles.Approver},
		{RoleAuditor, id.Roles.Auditor}, {RoleAdmin, append(slices.Clip(id.AdminGroups), id.Roles.Admin...)},
	} {
		if has(r.groups) {
			out = append(out, r.name)
		}
	}
	return out
}

// roleGroups is every group any role maps to (policyGroups keeps these in the session).
func roleGroups(id policy.Identity) []string {
	r := id.Roles
	return slices.Concat(id.AdminGroups, r.Viewer, r.Operator, r.Approver, r.Auditor, r.Admin)
}

// validRoles rejects unknown role names (the --dev-insecure-roles flag).
func validRoles(roles []string) error {
	for _, r := range roles {
		if !slices.Contains(Roles, r) {
			return fmt.Errorf("unknown role %q (want one of %s)", r, strings.Join(Roles, ", "))
		}
	}
	return nil
}

func (p Principal) can(x perm) bool {
	if x == permSession {
		return true
	}
	return slices.ContainsFunc(p.Roles, func(r string) bool { return slices.Contains(rolePerms[r], x) })
}

// permissions lists what p may do, for the console to hide what it cannot.
func (p Principal) permissions() []string {
	out := []string{}
	for _, x := range []perm{permRead, permOperate, permApprove, permAudit, permAdmin} {
		if p.can(x) {
			out = append(out, string(x))
		}
	}
	return out
}

// route registers a session-authenticated handler under the permission
// routePerms names for pattern; a pattern with no entry denies everyone.
func (s *Server) route(m *routeMux, pattern string, next authedHandler) {
	need, mapped := routePerms[pattern]
	m.guarded = append(m.guarded, pattern)
	m.HandleFunc(pattern, s.user(func(w http.ResponseWriter, r *http.Request, p Principal) {
		if !mapped {
			s.cfg.Log.Error("route has no routePerms entry; denying", "route", pattern)
			s.deny(w, r, p, pattern, "unmapped")
			return
		}
		if !p.can(need) {
			s.deny(w, r, p, pattern, need)
			return
		}
		next(w, r, p)
	}))
}

// deny answers 403 and audits the attempt. Best effort: the request is refused
// either way, and failing it with 500 on an audit error would hide the 403.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, p Principal, route string, need perm) {
	s.Audit(r.Context(), p.ID, "authz.deny", r.URL.Path, map[string]string{
		"route": route, "method": r.Method, "need": string(need), "roles": strings.Join(p.Roles, ","),
	})
	apiErr(w, http.StatusForbidden, string(need)+" permission required")
}

// routeMux records every registered pattern, and which went through s.route,
// so tests can check routePerms against what is actually served and enforced.
type routeMux struct {
	*http.ServeMux
	patterns, guarded []string
}

func (m *routeMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, h)
}
