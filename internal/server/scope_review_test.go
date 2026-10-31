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

// Tests for the ADR-0037 security review findings.

// TestReviewMCPRequestReach (M1): an mcp-server request reaches every ring
// whose profile extends the requester's ring's profile, and the rings of
// experiments with a variant on it, for scope checks and approval rules.
func TestReviewMCPRequestReach(t *testing.T) {
	e := scopedEnv(t)
	file := func(p Principal) Request {
		w := e.as(p, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"please"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("file: %d %s", w.Code, w.Body)
		}
		return decode[Request](t, w)
	}
	// olga is in ring1-canary (profile engineering). ring0-harness-team runs
	// engineering-next, which extends engineering: the edit reaches it too.
	canaryReq := file(ownOtherCanary)
	// harry is in ring0-harness-team (engineering-next). claude-cli-2.1.3xx-ab
	// has a variant on engineering-next in ring1-canary and ring2-early.
	harry := Principal{ID: "harry@acme.example", Groups: []string{"ai-platform"}}
	ring0Req := file(harry)

	org, _, _ := e.s.pol.Get()
	for _, c := range []struct {
		req  Request
		want []string
	}{
		{canaryReq, []string{"ring0-harness-team", "ring1-canary", "ring2-early", "ring3-ga"}},
		{ring0Req, []string{"ring0-harness-team", "ring1-canary", "ring2-early"}},
	} {
		res, err := requestResource(org, &c.req)
		if got := slices.Sorted(slices.Values(res.Rings)); err != nil || !slices.Equal(got, c.want) || !res.AllUnits {
			t.Errorf("%s resource: %v %v, want %v", c.req.User, got, err, c.want)
		}
		if got := slices.Sorted(slices.Values(requestTarget(org, &c.req).Rings)); !slices.Equal(got, c.want) {
			t.Errorf("%s approval-rule target: %v, want %v", c.req.User, got, c.want)
		}
	}
	for _, c := range []struct {
		name  string
		who   Principal
		id    string
		allow bool
	}{
		{"ring 1-3 approver: the profile also reaches ring0 by extends", Principal{ID: "a123@acme.example", Groups: []string{"g-123-appr"}}, canaryReq.ID, false},
		{"ring0 approver: a variant on the profile runs in ring1 and ring2", Principal{ID: "a0@acme.example", Groups: []string{"g-r0-appr"}}, ring0Req.ID, false},
		{"global approver decides either", globalAppr, canaryReq.ID, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := e.as(c.who, "POST", "/api/v1/requests/"+c.id+"/deny", "")
			if denied := w.Code == http.StatusForbidden; denied == c.allow {
				t.Fatalf("%d %s (allow=%v)", w.Code, w.Body, c.allow)
			}
		})
	}
	// An opt-in's approval-rule target includes the ring it moves the requester into.
	optIn := decode[Request](t, e.as(ownPayEarly, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"ring1-canary","justification":"please"}`))
	if got := requestTarget(org, &optIn).Rings; !slices.Contains(got, "ring1-canary") || !slices.Contains(got, "ring2-early") {
		t.Fatalf("opt-in target: %v", got)
	}
}

// TestReviewTogglePreview (L1): a scoped reader previews only themselves, or
// a subject in a ring they read; unknown rings answer like out-of-scope ones;
// a ring they do not cover is never named.
func TestReviewTogglePreview(t *testing.T) {
	e := scopedEnv(t)
	type prev struct {
		Preview *TogglePreview `json:"preview"`
	}
	get := func(p Principal, q string) *httptest.ResponseRecorder {
		return e.as(p, "GET", "/api/v1/toggles/github-mcp?"+q, "")
	}
	for _, c := range []struct {
		name, q string
		code    int
	}{
		{"self", "user=" + canaryView.ID, 200},
		{"another user, no ring", "user=" + ownOtherCanary.ID, 403},
		{"another user in a ring they read", "user=" + ownOtherCanary.ID + "&ring=ring1-canary", 200},
		{"another user in a ring they do not read", "user=" + ownOtherCanary.ID + "&ring=ring2-early", 403},
		{"unknown ring answers as out of scope", "user=" + ownOtherCanary.ID + "&ring=nope", 403},
	} {
		t.Run(c.name, func(t *testing.T) {
			if w := get(canaryView, c.q); w.Code != c.code {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	a, b := get(canaryView, "user=x&ring=nope"), get(canaryView, "user=x&ring=ring2-early")
	if a.Body.String() != b.Body.String() {
		t.Fatalf("unknown ring is an oracle: %s vs %s", a.Body, b.Body)
	}
	if c := get(admin, "user=x&ring=nope").Code; c != http.StatusUnprocessableEntity {
		t.Fatalf("global reader, unknown ring: %d", c)
	}
	// Self preview uses the caller's own groups, not the query's.
	pv := decode[prev](t, get(canaryView, "user="+canaryView.ID+"&groups=ai-platform"))
	if pv.Preview == nil || slices.Contains(pv.Preview.Subject.Groups, "ai-platform") {
		t.Fatalf("self preview took query groups: %+v", pv.Preview)
	}
	// A canary viewer who is themselves in ring2-early: the ring is not named,
	// not in the subject and not in the trace.
	inEarly := Principal{ID: "cve@acme.example", Groups: []string{"g-canary-view", "early-members"}}
	w := get(inEarly, "user="+inEarly.ID)
	pv = decode[prev](t, w)
	if w.Code != 200 || pv.Preview.Subject.Ring != "" || strings.Contains(w.Body.String(), "ring2-early") {
		t.Fatalf("uncovered own ring leaked: %d %s", w.Code, w.Body)
	}
	// A global reader sees it all.
	if w := get(admin, "user="+inEarly.ID+"&groups=early-members"); !strings.Contains(w.Body.String(), "ring2-early") {
		t.Fatalf("global preview lost the ring: %s", w.Body)
	}
}

// TestReviewSelfPreviewGroupsResolveRing (R1): a scoped reader's self preview
// is the same with and without query groups: the ring resolves from their
// own groups too, not only the evaluation.
func TestReviewSelfPreviewGroupsResolveRing(t *testing.T) {
	e := scopedEnv(t)
	for _, me := range []Principal{canaryView, {ID: "cve@acme.example", Groups: []string{"g-canary-view", "early-members"}}} {
		a := e.as(me, "GET", "/api/v1/toggles/github-mcp?user="+me.ID, "")
		b := e.as(me, "GET", "/api/v1/toggles/github-mcp?user="+me.ID+"&groups=canary-members", "")
		if a.Code != 200 || a.Body.String() != b.Body.String() {
			t.Errorf("%s: self preview depends on query groups:\n%s\n%s", me.ID, a.Body, b.Body)
		}
	}
}

// TestReviewRenderFromSnapshot (R3): the experiment and rollout views render
// from the snapshot the request was authorized under, not a later reload.
func TestReviewRenderFromSnapshot(t *testing.T) {
	e := scopedEnv(t)
	org, view, _ := e.s.pol.Get()
	for _, f := range []string{"experiments/opus-5-5-canary.yaml", "rollouts/opus-5-5-upgrade.yaml"} {
		if err := os.Remove(filepath.Join(e.s.cfg.PolicyDir, f)); err != nil {
			t.Fatal(err)
		}
	}
	e.s.ReloadPolicy()
	if now, _, _ := e.s.pol.Get(); findRolloutIn(now, "opus-5-5-upgrade") != nil {
		t.Fatal("reload did not drop the rollout")
	}
	for _, c := range []struct {
		path, name string
		h          authedHandler
	}{
		{"/api/v1/experiments/opus-5-5-canary", "opus-5-5-canary", e.s.getExperiment},
		{"/api/v1/rollouts/opus-5-5-upgrade", "opus-5-5-upgrade", e.s.getRollout},
	} {
		serve := func(pinned bool) *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", c.path, nil)
			r.SetPathValue("name", c.name)
			if pinned {
				r = withPolicy(r, org, view)
			}
			w := httptest.NewRecorder()
			c.h(w, r, admin)
			return w
		}
		if w := serve(true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), c.name) {
			t.Errorf("%s from the snapshot: %d %.200s", c.path, w.Code, w.Body)
		}
		if w := serve(false); w.Code != http.StatusNotFound {
			t.Errorf("%s from current policy: %d", c.path, w.Code)
		}
	}
	// And through s.route: the list a check filtered is the list rendered.
	if got := names(decode[[]ExperimentDetail](t, e.as(canaryView, "GET", "/api/v1/experiments", "")), func(x ExperimentDetail) string { return x.Name }); len(got) != 0 {
		t.Fatalf("after reload, canary viewer sees %v", got)
	}
}

// TestReviewTokenCreateOneLoad: service-token create, list and revoke check
// scope names, the admin grant and the role ceiling against one policy load,
// the request's snapshot. The snapshot has unit checkout; a reload deletes it.
// Reading the reload anywhere would turn a valid create into a 400 or 403.
func TestReviewTokenCreateOneLoad(t *testing.T) {
	e := scopedEnv(t)
	org, view, _ := e.s.pol.Get()
	if err := os.RemoveAll(filepath.Join(e.s.cfg.PolicyDir, "units/payments/checkout")); err != nil {
		t.Fatal(err)
	}
	e.s.ReloadPolicy()
	if now, _, err := e.s.pol.Get(); err != nil || now.Unit("checkout") != nil {
		t.Fatalf("reload did not drop checkout: %v", err)
	}
	call := func(h authedHandler, method, path, body string, pinned bool, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if id != "" {
			r.SetPathValue("id", id)
		}
		if pinned {
			r = withPolicy(r, org, view)
		}
		w := httptest.NewRecorder()
		h(w, r, grantPrincipal(payAdmin.ID, payAdmin.Groups, org.Identity.Grants(policy.Subject{ID: payAdmin.ID, Groups: payAdmin.Groups})))
		return w
	}
	const body = `{"name":"co","role":"viewer","scope":{"units":["checkout"]}}`
	w := call(e.s.createServiceToken, "POST", "/api/v1/service-tokens", body, true, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("create under the snapshot: %d %s", w.Code, w.Body)
	}
	id := decode[CreateServiceTokenResponse](t, w).ServiceToken.ID
	if w := call(e.s.createServiceToken, "POST", "/api/v1/service-tokens", strings.Replace(body, `"co"`, `"co2"`, 1), false, ""); w.Code == http.StatusCreated {
		t.Fatalf("without the snapshot, current policy (no checkout) must refuse: %d", w.Code)
	}
	// List and revoke judge the token's scope against the same snapshot.
	lw := call(e.s.listServiceTokens, "GET", "/api/v1/service-tokens", "", true, "")
	if got := decode[ServiceTokensResponse](t, lw).Tokens; len(got) != 1 || got[0].ID != id {
		t.Fatalf("list under the snapshot: %+v", got)
	}
	if w := call(e.s.revokeServiceToken, "POST", "/api/v1/service-tokens/"+id+"/revoke", `{"reason":"x"}`, true, id); w.Code != http.StatusOK {
		t.Fatalf("revoke under the snapshot: %d %s", w.Code, w.Body)
	}
}

// TestCatalogTicketHint: the catalog tells the caller which ticket pattern
// filing each item needs, judged as filing is (requestTarget), and filing
// honours it: 422 without a matching ticket, 201 with one.
func TestCatalogTicketHint(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		f := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		gov := "governance:\n  approvals:\n    - name: ga-two-person\n      scope: {rings: [ring3-ga]}\n      quorum: 2\n      groups: [sre-leads]\n      ticket: CHG[0-9]{7}\n"
		if err := os.WriteFile(f, []byte(strings.Replace(string(b), "selfService:\n", gov+"selfService:\n", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	cat := decode[Catalog](t, e.as(dev, "GET", "/api/v1/catalog", ""))
	i := slices.IndexFunc(cat.Items, func(c CatalogItem) bool { return c.Kind == "mcp-server" && c.Item == "jira" })
	if i < 0 || !slices.Equal(cat.Items[i].Ticket, []string{"CHG[0-9]{7}"}) {
		t.Fatalf("jira hint: %+v", cat.Items)
	}
	file := func(ticket string) *httptest.ResponseRecorder {
		return e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"please","ticket":"`+ticket+`"}`)
	}
	if w := file(""); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "ga-two-person") {
		t.Fatalf("no ticket: %d %s", w.Code, w.Body)
	}
	if w := file("OPS-1"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong ticket: %d %s", w.Code, w.Body)
	}
	if w := file("CHG0000001"); w.Code != http.StatusCreated {
		t.Fatalf("matching ticket: %d %s", w.Code, w.Body)
	}
}

// TestReviewTokenScopeDrift (L2): a token's scope is re-checked against its
// creator's grant scope under current policy on every use.
func TestReviewTokenScopeDrift(t *testing.T) {
	e := scopedEnv(t)
	dv := scopedDevices(t, e)
	w := e.as(payAdmin, "POST", "/api/v1/service-tokens", `{"name":"co","role":"viewer","scope":{"units":["checkout"]}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	tok := decode[CreateServiceTokenResponse](t, w).Token
	if c := e.bearer(tok, "GET", "/api/v1/devices/"+dv["checkout"], "").Code; c != 200 {
		t.Fatalf("before: %d", c)
	}
	// Policy moves checkout out from under payments (a top-level unit now).
	dir := e.s.cfg.PolicyDir
	b, err := os.ReadFile(filepath.Join(dir, "units/payments/checkout/unit.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "units/checkout"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "units/checkout/unit.yaml"), []byte(strings.Replace(string(b), "parent: payments\n", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "units/payments/checkout")); err != nil {
		t.Fatal(err)
	}
	e.s.ReloadPolicy()
	org, _, err := e.s.pol.Get()
	if err != nil || org.Unit("checkout") == nil || org.Unit("checkout").Parent != "" {
		t.Fatalf("policy did not move checkout: %v", err)
	}
	w = e.bearer(tok, "GET", "/api/v1/devices/"+dv["checkout"], "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "no longer within") {
		t.Fatalf("after: %d %s", w.Code, w.Body)
	}
	if d := lastAudit(t, e); d.Action != "authz.deny" || d.Details["creatorScope"] != "units=payments" || d.Details["scope"] != "units=checkout" {
		t.Fatalf("drift denial audit: %+v", d)
	}
}

// TestReviewPrincipalAdmin (b): Admin is a global admin grant only.
func TestReviewPrincipalAdmin(t *testing.T) {
	e := scopedEnv(t)
	m := decode[Me](t, e.as(payAdmin, "GET", "/api/v1/me", ""))
	if m.Admin || !slices.ContainsFunc(m.Bindings, func(g policy.Grant) bool { return g.Role == RoleAdmin && g.Scope.String() == "units=payments" }) {
		t.Fatalf("scoped admin me: admin=%v bindings=%+v", m.Admin, m.Bindings)
	}
	if m := decode[Me](t, e.as(admin, "GET", "/api/v1/me", "")); !m.Admin {
		t.Fatal("global admin lost admin")
	}
}

// TestReviewApprovalsScopedAsRollout (a): a rollout's approvals are read under
// the rollout's own scope, not just its next step's.
func TestReviewApprovalsScopedAsRollout(t *testing.T) {
	e := scopedEnv(t)
	r0 := Principal{ID: "r0v@acme.example", Groups: []string{"g-r0-view"}}
	// engineering-settings-2026-10 is a draft whose next step is ring0; later steps reach ring2 and ring3.
	for _, path := range []string{"/api/v1/rollouts/engineering-settings-2026-10", "/api/v1/rollouts/engineering-settings-2026-10/approvals"} {
		if c := e.as(r0, "GET", path, "").Code; c != http.StatusForbidden {
			t.Errorf("%s: %d", path, c)
		}
	}
}

// TestReviewPolicySnapshot (d): the scope check and the handler read one
// policy snapshot, so a reload in between cannot change what the handler acts on.
func TestReviewPolicySnapshot(t *testing.T) {
	e := scopedEnv(t)
	before, _, _ := e.s.pol.Get()
	// Reload a policy without opus-5-5-canary.
	if err := os.Remove(filepath.Join(e.s.cfg.PolicyDir, "experiments/opus-5-5-canary.yaml")); err != nil {
		t.Fatal(err)
	}
	rollouts := filepath.Join(e.s.cfg.PolicyDir, "rollouts/opus-5-5-upgrade.yaml") // it backs this rollout
	if err := os.Remove(rollouts); err != nil {
		t.Fatal(err)
	}
	e.s.ReloadPolicy()
	if now, _, err := e.s.pol.Get(); err != nil || slices.ContainsFunc(now.Experiments, func(x *policy.Experiment) bool { return x.Name == "opus-5-5-canary" }) {
		t.Fatalf("reload: %v", err)
	}
	kill := func(r *http.Request) int {
		r.SetPathValue("name", "opus-5-5-canary")
		w := httptest.NewRecorder()
		e.s.killHandler(true, "experiment")(w, r, canaryOps)
		return w.Code
	}
	newReq := func() *http.Request {
		return httptest.NewRequest("POST", "/api/v1/experiments/opus-5-5-canary/kill", strings.NewReader(`{"reason":"x"}`))
	}
	if c := kill(withPolicy(newReq(), before, PolicyView{})); c != http.StatusOK {
		t.Fatalf("handler did not act on the snapshot it was authorized under: %d", c)
	}
	if c := kill(newReq()); c != http.StatusNotFound {
		t.Fatalf("without a snapshot the handler reads current policy: %d", c)
	}
	// s.route pins the snapshot for every non-session route.
	m := &routeMux{ServeMux: http.NewServeMux()}
	var pinned bool
	e.s.route(m, "GET /api/v1/policy", func(_ http.ResponseWriter, r *http.Request, _ Principal) {
		snap, ok := r.Context().Value(policyKey{}).(policySnap)
		pinned = ok && snap.org != nil
	})
	r := httptest.NewRequest("GET", "/api/v1/policy", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Unix() + 60})})
	m.ServeHTTP(httptest.NewRecorder(), r)
	if !pinned {
		t.Fatal("s.route did not pin the policy snapshot")
	}
}
