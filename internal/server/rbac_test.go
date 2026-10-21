package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// publicRoutes authenticate with a bearer token (fleet, device, gateway,
// enrollment) or not at all; they are deliberately outside routePerms. Adding a
// route here is a security review decision, not a way to make a test pass.
var publicRoutes = []string{
	"GET /healthz", "GET /readyz",
	"POST /api/v1/fleet/report", "GET /api/v1/fleet/ring", "GET /api/v1/fleet/killswitch",
	"GET /api/v1/gateway/killswitch", "GET /api/v1/gateway/posture",
	"GET /enroll.sh", "GET /enroll.ps1", "GET /enroll/release.pub", "GET /enroll/killswitch.pub", "POST /api/v1/enroll",
	"GET /auth/login", "GET /auth/callback", "POST /auth/logout",
	// SCIM bearer token only (scimAuth); the gateway directory takes the gateway token.
	"GET /scim/v2/ServiceProviderConfig", "GET /scim/v2/ResourceTypes", "GET /scim/v2/ResourceTypes/{id}",
	"GET /scim/v2/Schemas", "GET /scim/v2/Schemas/{id}",
	"GET /scim/v2/Users", "POST /scim/v2/Users", "GET /scim/v2/Users/{id}", "PUT /scim/v2/Users/{id}", "PATCH /scim/v2/Users/{id}", "DELETE /scim/v2/Users/{id}",
	"GET /scim/v2/Groups", "POST /scim/v2/Groups", "GET /scim/v2/Groups/{id}", "PUT /scim/v2/Groups/{id}", "PATCH /scim/v2/Groups/{id}", "DELETE /scim/v2/Groups/{id}",
	"/scim/v2/", "GET /api/v1/gateway/directory",
	// Gateway token (gatewayAuth): halo-proxy reports usage and asks for verdicts.
	"POST /api/v1/gateway/budget/check", "POST /api/v1/gateway/budget/usage",
	// Authenticated by the CI provider's OIDC token, verified against policy workloads (ADR-0023).
	"POST /api/v1/token/exchange",
	// Bearer: a Halos workload or delegated agent credential signed by this server (ADR-0024).
	"POST /api/v1/agents/egress",
	"/api/", "/",
}

// TestRoutePermsCoverMux walks every pattern the server registers: each one is
// either public (listed above) or in routePerms, and every routePerms entry is
// served. A new cookie route without a table entry fails here; at runtime it is
// denied to everyone (TestUnmappedRouteDenied).
func TestRoutePermsCoverMux(t *testing.T) {
	e := newEnv(t, nil)
	m := e.s.mux()
	for _, p := range m.patterns {
		_, mapped := routePerms[p]
		public := slices.Contains(publicRoutes, p)
		switch {
		case mapped && public:
			t.Errorf("%s is both public and in routePerms", p)
		case !mapped && !public:
			t.Errorf("%s has no routePerms entry: add it to the table with the permission it needs", p)
		}
	}
	for p := range routePerms {
		switch {
		case !slices.Contains(m.patterns, p):
			t.Errorf("routePerms has %s but no such route is registered", p)
		case !slices.Contains(m.guarded, p):
			t.Errorf("%s is in routePerms but registered without s.route, so the table is not enforced", p)
		}
	}
}

func TestUnmappedRouteDenied(t *testing.T) {
	e := newEnv(t, nil)
	m := &routeMux{ServeMux: http.NewServeMux()}
	called := false
	e.s.route(m, "POST /api/v1/new-privileged-thing", func(http.ResponseWriter, *http.Request, Principal) { called = true })
	r := httptest.NewRequest("POST", "/api/v1/new-privileged-thing", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Unix() + 60})})
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("unmapped route as admin: %d called=%v", w.Code, called)
	}
	if d := lastAudit(t, e); d.Action != "authz.deny" || d.Details["need"] != "unmapped" {
		t.Fatalf("denial not audited: %+v", d)
	}
}

// rbacEnv maps one IdP group to each role, on top of the fixture's adminGroups.
func rbacEnv(t *testing.T) *env {
	t.Helper()
	return newEnv(t, func(c *Config) {
		f := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		roles := "  adminGroups: [platform-admins]\n  roles:\n    viewer: [g-viewer]\n    operator: [g-operator]\n" +
			"    approver: [g-approver]\n    auditor: [g-auditor]\n    admin: [g-admin]\n"
		s := strings.Replace(string(b), "  adminGroups: [platform-admins]\n", roles, 1)
		if s == string(b) {
			t.Fatal("fixture changed: no adminGroups line")
		}
		if err := os.WriteFile(f, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	})
}

func lastAudit(t *testing.T, e *env) AuditEntry {
	t.Helper()
	all, err := e.s.auditLog.all()
	if err != nil || len(all) == 0 {
		t.Fatalf("audit log: %d entries, %v", len(all), err)
	}
	return all[len(all)-1]
}

// TestRolePermissionMatrix requests every route in routePerms as every role:
// 403 exactly when the role lacks the route's permission, and every 403 is
// audited with the route and the permission it needed.
func TestRolePermissionMatrix(t *testing.T) {
	e := rbacEnv(t)
	who := map[string]Principal{
		"developer":   dev,
		RoleViewer:    {ID: "v@acme.example", Groups: []string{"g-viewer"}},
		RoleOperator:  {ID: "o@acme.example", Groups: []string{"g-operator"}},
		RoleApprover:  {ID: "a@acme.example", Groups: []string{"g-approver"}},
		RoleAuditor:   {ID: "au@acme.example", Groups: []string{"g-auditor"}},
		RoleAdmin:     {ID: "ad@acme.example", Groups: []string{"g-admin"}},
		"adminGroups": admin,
	}
	grants := map[string][]perm{
		"developer": nil, RoleViewer: {permRead}, RoleOperator: {permRead, permOperate}, RoleApprover: {permRead, permApprove},
		RoleAuditor: {permAudit}, RoleAdmin: {permRead, permOperate, permApprove, permAudit, permAdmin},
		"adminGroups": {permRead, permOperate, permApprove, permAudit, permAdmin},
	}
	fill := strings.NewReplacer("{id}", "x", "{name}", "x", "{launcher}", "laptop")
	for role, p := range who {
		for pattern, need := range routePerms {
			method, path, _ := strings.Cut(pattern, " ")
			path = fill.Replace(path)
			if pattern == "GET /api/v1/whoami" {
				path += "?user=" + p.ID
			}
			w := e.as(p, method, path, "{}")
			want := need == permSession || slices.Contains(grants[role], need)
			if denied := w.Code == http.StatusForbidden; denied == want {
				t.Errorf("%s %s: %d %.120s (allowed=%v)", role, pattern, w.Code, w.Body.String(), want)
				continue
			}
			if !want {
				if d := lastAudit(t, e); d.Action != "authz.deny" || d.Actor != p.ID || d.Details["route"] != pattern || d.Details["need"] != string(need) {
					t.Errorf("%s %s: denial not audited: %+v", role, pattern, d)
				}
			}
		}
	}
}

func TestRolesFor(t *testing.T) {
	id := policy.Identity{AdminGroups: []string{"legacy-admins"}, Roles: policy.RoleGroups{
		Viewer: []string{"eng"}, Operator: []string{"sre"}, Approver: []string{"leads"}, Auditor: []string{"sec"}, Admin: []string{"plat"},
	}}
	for _, tc := range []struct {
		name   string
		groups []string
		want   []string
	}{
		{"no groups", nil, nil},
		{"unmapped group", []string{"marketing"}, nil},
		{"adminGroups still grants admin", []string{"legacy-admins"}, []string{RoleAdmin}},
		{"roles.admin", []string{"plat"}, []string{RoleAdmin}},
		{"several roles, Roles order", []string{"sec", "eng", "sre"}, []string{RoleViewer, RoleOperator, RoleAuditor}},
		{"approver", []string{"leads"}, []string{RoleApprover}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rolesFor(id, tc.groups); !slices.Equal(got, tc.want) {
				t.Fatalf("rolesFor(%v) = %v, want %v", tc.groups, got, tc.want)
			}
		})
	}
	// the session keeps role groups only through policyGroups
	org := &policy.Org{Identity: id}
	if got := policyGroups(org, []string{"sec", "marketing", "plat"}); !slices.Equal(got, []string{"sec", "plat"}) {
		t.Fatalf("policyGroups = %v", got)
	}
	// and an OIDC login gets them from its claims
	p, err := principalFromClaims(map[string]any{"email": "a@b", "email_verified": true, "groups": []any{"sre"}}, id)
	if err != nil || !slices.Equal(p.Roles, []string{RoleOperator}) || p.Admin {
		t.Fatalf("principalFromClaims: %+v %v", p, err)
	}
}

func TestPermissionsExposed(t *testing.T) {
	e := rbacEnv(t)
	op := Principal{ID: "o@acme.example", Groups: []string{"g-operator"}}
	me := decode[Me](t, e.as(op, "GET", "/api/v1/me", ""))
	if !slices.Equal(me.Roles, []string{RoleOperator}) || !slices.Equal(me.Permissions, []string{"read", "operate"}) || me.Admin {
		t.Fatalf("me: roles=%v perms=%v admin=%v", me.Roles, me.Permissions, me.Admin)
	}
	caps := decode[Capabilities](t, e.as(op, "GET", "/api/v1/capabilities", ""))
	if !slices.Equal(caps.Roles, []string{RoleOperator}) || !slices.Equal(caps.Permissions, []string{"read", "operate"}) {
		t.Fatalf("capabilities: %+v", caps)
	}
	if caps := decode[Capabilities](t, e.as(dev, "GET", "/api/v1/capabilities", "")); caps.Roles == nil || len(caps.Roles) != 0 || len(caps.Permissions) != 0 {
		t.Fatalf("developer capabilities: %+v", caps)
	}
	if me := decode[Me](t, e.as(admin, "GET", "/api/v1/me", "")); !me.Admin || len(me.Permissions) != 5 {
		t.Fatalf("admin me: %+v", me.Principal)
	}
}

// Handler-level checks: whoami for another user needs read, and only approvers
// see everyone's requests.
func TestInHandlerAuthorization(t *testing.T) {
	e := rbacEnv(t)
	viewer := Principal{ID: "v@acme.example", Groups: []string{"g-viewer"}}
	approver := Principal{ID: "a@acme.example", Groups: []string{"g-approver"}}
	if c := e.as(viewer, "GET", "/api/v1/whoami?user="+dev.ID, "").Code; c != http.StatusOK {
		t.Fatalf("viewer whoami other: %d", c)
	}
	if c := e.as(dev, "GET", "/api/v1/whoami?user="+viewer.ID, "").Code; c != http.StatusForbidden {
		t.Fatalf("developer whoami other: %d", c)
	}
	if d := lastAudit(t, e); d.Action != "authz.deny" || d.Actor != dev.ID || d.Details["need"] != "read" {
		t.Fatalf("whoami denial not audited: %+v", d)
	}

	rq := decode[Request](t, e.as(dev, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"please"}`))
	for _, tc := range []struct {
		who  Principal
		want int
	}{{dev, 1}, {viewer, 0}, {approver, 1}, {admin, 1}} {
		if got := decode[[]Request](t, e.as(tc.who, "GET", "/api/v1/requests", "")); len(got) != tc.want {
			t.Errorf("%s sees %d requests, want %d", tc.who.ID, len(got), tc.want)
		}
	}
	if c := e.as(approver, "POST", "/api/v1/requests/"+rq.ID+"/approve", "").Code; c != http.StatusOK {
		t.Fatalf("approver approve: %d", c)
	}
}

func TestDevRoles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		roles []string
		admin bool
		want  []string
		err   bool
	}{
		{"none", nil, false, []string{}, false},
		{"auditor", []string{RoleAuditor}, false, []string{RoleAuditor}, false},
		{"DevAdmin adds admin", []string{RoleViewer}, true, []string{RoleViewer, RoleAdmin}, false},
		{"DevAdmin no duplicate", []string{RoleAdmin}, true, []string{RoleAdmin}, false},
		{"unknown role", []string{"superuser"}, false, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := New(Config{PolicyDir: "../../examples/acme-corp", Token: tok, DevUser: "d", DevRoles: tc.roles, DevAdmin: tc.admin})
			if tc.err {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = e.Close() })
			p, _ := e.principal(httptest.NewRequest("GET", "/", nil))
			if !slices.Equal(p.Roles, tc.want) || p.Admin != slices.Contains(tc.want, RoleAdmin) {
				t.Fatalf("roles %v admin %v, want %v", p.Roles, p.Admin, tc.want)
			}
		})
	}
}
