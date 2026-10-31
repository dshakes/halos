package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/rollout"
)

// Tests for ADR-0037: scoped role bindings.

// scopedBindings is the fixture's identity.roleBindings. The index of each
// entry is its audit source (identity.roleBindings[i]).
const scopedBindings = `  roleBindings:
    - role: viewer
      groups: [g-canary-view]
      scope: {rings: [ring1-canary]}
    - role: operator
      groups: [g-canary-ops]
      scope: {rings: [ring1-canary]}
    - role: operator
      groups: [g-early-ops]
      scope: {rings: [ring2-early]}
    - role: viewer
      groups: [g-pay-view]
      scope: {units: [payments]}
    - role: admin
      groups: [g-pay-admin]
      scope: {units: [payments]}
    - role: approver
      groups: [g-canary-appr]
      scope: {rings: [ring1-canary]}
    - role: approver
      groups: [g-pay-appr]
      scope: {units: [payments]}
    - role: operator
      users: [Scoped.User@ACME.example]
      scope: {rings: [ring2-early]}
    - role: operator
      groups: [g-rb-operator]
    - role: viewer
      groups: [g-pay-canary-view]
      scope: {rings: [ring1-canary], units: [payments]}
    - role: approver
      groups: [g-123-appr]
      scope: {rings: [ring1-canary, ring2-early, ring3-ga]}
    - role: approver
      groups: [g-r0-appr]
      scope: {rings: [ring0-harness-team]}
    - role: viewer
      groups: [g-r0-view]
      scope: {rings: [ring0-harness-team]}
`

// scopedGovernance: two approvals from the listed groups for canary changes.
const scopedGovernance = "governance:\n  approvals:\n    - name: canary-two\n      scope: {rings: [ring1-canary]}\n      quorum: 2\n" +
	"      groups: [g-canary-appr, g-approver, g-pay-appr, g-early-appr]\n"

// scopedEnv is rbacEnv plus scopedBindings, the canary-two approval rule,
// a kill key, and group-selected membership for ring1 and ring2 so device
// owners land in a known ring.
func scopedEnv(t *testing.T) *env {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newEnv(t, func(c *Config) {
		c.KillKey = bundle.Ed25519Signer{Key: priv}
		edit := func(name, old, new string) {
			f := filepath.Join(c.PolicyDir, name)
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			s := strings.Replace(string(b), old, new, 1)
			if s == string(b) {
				t.Fatalf("fixture changed: %s has no %q", name, old)
			}
			if err := os.WriteFile(f, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		edit("halos.yaml", "  adminGroups: [platform-admins]\n", "  adminGroups: [platform-admins]\n  roles:\n    viewer: [g-viewer]\n    operator: [g-operator]\n"+
			"    approver: [g-approver]\n    auditor: [g-auditor]\n    admin: [g-admin]\n"+scopedBindings)
		edit("halos.yaml", "selfService:\n", scopedGovernance+"selfService:\n")
		edit("rings/ring1-canary.yaml", "membership:\n", "membership:\n  groups: [canary-members]\n")
		edit("rings/ring2-early.yaml", "membership:\n", "membership:\n  groups: [early-members]\n")
	})
}

var (
	canaryView    = Principal{ID: "cv@acme.example", Groups: []string{"g-canary-view"}}
	canaryOps     = Principal{ID: "co@acme.example", Groups: []string{"g-canary-ops"}}
	earlyOps      = Principal{ID: "eo@acme.example", Groups: []string{"g-early-ops"}}
	payView       = Principal{ID: "pv@acme.example", Groups: []string{"g-pay-view"}}
	payAdmin      = Principal{ID: "pa@acme.example", Groups: []string{"g-pay-admin"}}
	canaryAppr    = Principal{ID: "ca@acme.example", Groups: []string{"g-canary-appr"}}
	payAppr       = Principal{ID: "pap@acme.example", Groups: []string{"g-pay-appr"}}
	globalAppr    = Principal{ID: "ga@acme.example", Groups: []string{"g-approver"}}
	globalOps     = Principal{ID: "go@acme.example", Groups: []string{"g-operator"}}
	userBound     = Principal{ID: "scoped.user@acme.example"} // operator over ring2 by user id, case-insensitive
	payCanaryView = Principal{ID: "pcv@acme.example", Groups: []string{"g-pay-canary-view"}}

	// Device owners: ring by membership group, unit by members group.
	ownPayCanary   = Principal{ID: "alice@acme.example", Groups: []string{"payments-eng", "canary-members"}}
	ownCheckout    = Principal{ID: "carol@acme.example", Groups: []string{"payments-eng", "checkout-eng", "canary-members"}}
	ownOtherCanary = Principal{ID: "olga@acme.example", Groups: []string{"canary-members"}}
	ownPayEarly    = Principal{ID: "pete@acme.example", Groups: []string{"payments-eng", "early-members"}}
)

// scopedDevices enrolls one device per owner and returns their ids.
func scopedDevices(t *testing.T, e *env) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for name, p := range map[string]Principal{"payCanary": ownPayCanary, "checkout": ownCheckout, "otherCanary": ownOtherCanary, "payEarly": ownPayEarly} {
		_, d, err := e.s.devices.mint(p, *e.now)
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = d.ID
	}
	return ids
}

func TestRouteScopesCoverPerms(t *testing.T) {
	for p, need := range routePerms {
		rule, ok := routeScopes[p]
		switch {
		case !ok:
			t.Errorf("%s has no routeScopes entry: say how its resource is scoped (or that it is global, and why)", p)
		case need == permSession && rule.kind != scopeSelf && rule.kind != scopeHandler:
			t.Errorf("%s is a session route but scoped as %d", p, rule.kind)
		case need != permSession && rule.kind == scopeSelf:
			t.Errorf("%s needs %s but is scoped as the caller's own data", p, need)
		case rule.kind == scopePath && rule.of == nil:
			t.Errorf("%s is path-scoped without a resource function", p)
		case (rule.kind == scopeGlobal || rule.kind == scopeHandler) && rule.why == "":
			t.Errorf("%s: say why it is global or checked in the handler", p)
		}
	}
	for p := range routeScopes {
		if _, ok := routePerms[p]; !ok {
			t.Errorf("routeScopes has %s, which routePerms does not", p)
		}
	}
}

func TestRolesMatchPolicy(t *testing.T) {
	if !slices.Equal(Roles, policy.ConsoleRoles) {
		t.Fatalf("server.Roles %v != policy.ConsoleRoles %v", Roles, policy.ConsoleRoles)
	}
	for r := range rolePerms {
		if !slices.Contains(policy.ConsoleRoles, r) {
			t.Errorf("rolePerms has %s, not a policy console role", r)
		}
	}
}

// TestScopedAuthorizationMatrix: role x scope x route x resource. allow is
// "not 403" (a handler may still answer 404, 409 or 501 for its own reasons).
func TestScopedAuthorizationMatrix(t *testing.T) {
	e := scopedEnv(t)
	dv := scopedDevices(t, e)
	cases := []struct {
		name         string
		who          Principal
		method, path string
		body         string
		allow        bool
	}{
		// Experiments: ring-wide, every unit's members.
		{"canary viewer reads canary experiment", canaryView, "GET", "/api/v1/experiments/opus-5-5-canary", "", true},
		{"canary viewer: experiment spanning canary and early", canaryView, "GET", "/api/v1/experiments/claude-cli-2.1.3xx-ab", "", false},
		{"canary viewer: unknown experiment is a 403, not a 404", canaryView, "GET", "/api/v1/experiments/nope", "", false},
		{"unit viewer never covers a ring-wide experiment", payView, "GET", "/api/v1/experiments/opus-5-5-canary", "", false},
		{"ring+unit viewer never covers a ring-wide experiment", payCanaryView, "GET", "/api/v1/experiments/opus-5-5-canary", "", false},
		{"canary viewer cannot kill (no operate at all)", canaryView, "POST", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"x"}`, false},
		{"canary operator kills canary experiment", canaryOps, "POST", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"x"}`, true},
		{"early operator cannot kill canary experiment", earlyOps, "POST", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"x"}`, false},
		{"early operator cannot kill canary+early experiment", earlyOps, "POST", "/api/v1/experiments/claude-cli-2.1.3xx-ab/kill", `{"reason":"x"}`, false},
		{"user-bound early operator: early+ga experiment", userBound, "POST", "/api/v1/experiments/sonnet-next-shadow/kill", `{"reason":"x"}`, false},
		{"canary operator: stale-name unkill has no scope", canaryOps, "POST", "/api/v1/experiments/gone/unkill", "", false},
		{"canary operator opens a status PR in scope", canaryOps, "POST", "/api/v1/experiments/opus-5-5-canary/status", `{"status":"paused"}`, true},
		{"early operator: status PR out of scope", earlyOps, "POST", "/api/v1/experiments/opus-5-5-canary/status", `{"status":"paused"}`, false},

		// Toggles: the rings their rules select; group or default rules reach every ring.
		{"canary operator kills canary-ring toggle", canaryOps, "POST", "/api/v1/toggles/github-mcp/kill", `{"reason":"x"}`, true},
		{"canary operator: group-targeted toggle reaches every ring", canaryOps, "POST", "/api/v1/toggles/format-hook/kill", `{"reason":"x"}`, false},
		{"canary operator: ring0 toggle", canaryOps, "POST", "/api/v1/toggles/sonnet-next-route/kill", `{"reason":"x"}`, false},
		{"canary viewer reads canary toggle", canaryView, "GET", "/api/v1/toggles/github-mcp", "", true},
		{"canary viewer: org-wide toggle", canaryView, "GET", "/api/v1/toggles/format-hook", "", false},

		// Rollouts: read needs every step's ring; approvals the next step's.
		{"canary viewer reads canary-only rollout", canaryView, "GET", "/api/v1/rollouts/opus-5-5-upgrade", "", true},
		{"canary viewer: rollout reaching ga", canaryView, "GET", "/api/v1/rollouts/claude-code-2.1.300", "", false},
		{"canary viewer reads canary rollout approvals", canaryView, "GET", "/api/v1/rollouts/opus-5-5-upgrade/approvals", "", true},

		// Devices: the owner's ring and unit chain, resolved by the server.
		{"unit viewer reads member device", payView, "GET", "/api/v1/devices/" + dv["payCanary"], "", true},
		{"unit viewer reads descendant unit's device", payView, "GET", "/api/v1/devices/" + dv["checkout"], "", true},
		{"unit viewer: device outside the unit", payView, "GET", "/api/v1/devices/" + dv["otherCanary"], "", false},
		{"unit viewer: unknown device is a 403", payView, "GET", "/api/v1/devices/nope", "", false},
		{"canary viewer reads canary device", canaryView, "GET", "/api/v1/devices/" + dv["otherCanary"], "", true},
		{"canary viewer: early device", canaryView, "GET", "/api/v1/devices/" + dv["payEarly"], "", false},
		{"ring+unit viewer: payments device in canary", payCanaryView, "GET", "/api/v1/devices/" + dv["payCanary"], "", true},
		{"ring+unit viewer: payments device in early", payCanaryView, "GET", "/api/v1/devices/" + dv["payEarly"], "", false},
		{"ring+unit viewer: canary device outside payments", payCanaryView, "GET", "/api/v1/devices/" + dv["otherCanary"], "", false},
		{"user-bound early operator reads early device", userBound, "GET", "/api/v1/devices/" + dv["payEarly"], "", true},
		{"unit admin revokes member device", payAdmin, "POST", "/api/v1/devices/" + dv["payEarly"] + "/revoke", "", true},
		{"unit admin: device outside the unit", payAdmin, "POST", "/api/v1/devices/" + dv["otherCanary"] + "/revoke", "", false},

		// Global-only routes refuse every scoped grant.
		{"scoped viewer: policy is global", canaryView, "GET", "/api/v1/policy", "", false},
		{"scoped viewer: budgets are global", canaryView, "GET", "/api/v1/budgets", "", false},
		{"scoped viewer: cloud agents are global", canaryView, "GET", "/api/v1/cloud-agents", "", false},
		{"scoped admin: incident freeze is global", payAdmin, "POST", "/api/v1/freeze", `{"frozen":true,"reason":"x"}`, false},
		{"scoped admin: revocations are global", payAdmin, "GET", "/api/v1/revocations", "", false},
		{"scoped admin: session revocation is global", payAdmin, "POST", "/api/v1/users/" + ownPayCanary.ID + "/revoke-sessions", "", false},
		{"scoped admin: toggle proposals are global", payAdmin, "POST", "/api/v1/toggles/github-mcp/propose", `{"reason":"x"}`, false},
		{"scoped admin: break-glass unlock is global", payAdmin, "POST", "/api/v1/breakglass/unlock", "", false},
		{"scoped admin: audit log is global", payAdmin, "GET", "/api/v1/audit", "", false},
		{"scoped admin: session ledger is global", payAdmin, "GET", "/api/v1/sessions", "", false},
		{"scoped viewer: whoami for another user", canaryView, "GET", "/api/v1/whoami?user=" + ownOtherCanary.ID, "", false},
		{"scoped viewer: whoami for self", canaryView, "GET", "/api/v1/whoami?user=" + canaryView.ID, "", true},

		// Global grants are unchanged, roleBindings without a scope included.
		{"global operator reads policy", globalOps, "GET", "/api/v1/policy", "", true},
		{"global operator kills any experiment", globalOps, "POST", "/api/v1/experiments/claude-cli-2.1.3xx-ab/kill", `{"reason":"x"}`, true},
		{"unscoped roleBinding is global", Principal{ID: "rb@acme.example", Groups: []string{"g-rb-operator"}}, "POST", "/api/v1/toggles/format-hook/kill", `{"reason":"x"}`, true},
		{"admin: unknown experiment still 404 (no lookup for global)", admin, "GET", "/api/v1/experiments/nope", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := e.as(c.who, c.method, c.path, c.body)
			if denied := w.Code == http.StatusForbidden; denied == c.allow {
				t.Fatalf("%s %s as %s: %d %.200s (allow=%v)", c.method, c.path, c.who.ID, w.Code, w.Body, c.allow)
			}
			if !c.allow {
				d := lastAudit(t, e)
				if d.Action != "authz.deny" || d.Actor != c.who.ID {
					t.Fatalf("denial not audited: %+v", d)
				}
			}
		})
	}
	// An unknown resource and an out-of-scope one answer alike.
	a, b := e.as(canaryView, "GET", "/api/v1/experiments/nope", ""), e.as(canaryView, "GET", "/api/v1/experiments/claude-cli-2.1.3xx-ab", "")
	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Fatalf("unknown vs out of scope differ: %d %s / %d %s", a.Code, a.Body, b.Code, b.Body)
	}
	if c := e.as(admin, "GET", "/api/v1/experiments/nope", "").Code; c != http.StatusNotFound {
		t.Fatalf("global admin, unknown experiment: %d", c)
	}
}

// TestUnscopedBindingMatchesRoles: a roleBindings entry without a scope
// authorizes every route exactly as the same role under identity.roles.
func TestUnscopedBindingMatchesRoles(t *testing.T) {
	e := scopedEnv(t)
	bound := Principal{ID: "rb@acme.example", Groups: []string{"g-rb-operator"}}
	fill := strings.NewReplacer("{id}", "x", "{name}", "x", "{launcher}", "laptop")
	for pattern := range routePerms {
		method, path, _ := strings.Cut(pattern, " ")
		path = fill.Replace(path)
		a, b := e.as(bound, method, path, "{}").Code, e.as(globalOps, method, path, "{}").Code
		if (a == http.StatusForbidden) != (b == http.StatusForbidden) {
			t.Errorf("%s: roleBinding %d, identity.roles %d", pattern, a, b)
		}
	}
}

func names[T any](xs []T, name func(T) string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, name(x))
	}
	sort.Strings(out)
	return out
}

// TestScopedListFiltering: list routes show only in-scope items, and counts
// and aggregates come from what is shown.
func TestScopedListFiltering(t *testing.T) {
	e := scopedEnv(t)
	dv := scopedDevices(t, e)
	byID := map[string]string{}
	for k, v := range dv {
		byID[v] = k
	}
	expNames := func(p Principal) []string {
		return names(decode[[]ExperimentDetail](t, e.as(p, "GET", "/api/v1/experiments", "")), func(x ExperimentDetail) string { return x.Name })
	}
	devNames := func(p Principal) []string {
		return names(decode[[]Device](t, e.as(p, "GET", "/api/v1/devices", "")), func(d Device) string { return byID[d.ID] })
	}
	togNames := func(p Principal) []string {
		var v struct{ Toggles []ToggleView }
		if err := json.Unmarshal(e.as(p, "GET", "/api/v1/toggles", "").Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return names(v.Toggles, func(x ToggleView) string { return x.Name })
	}
	roNames := func(p Principal) []string {
		return names(decode[[]RolloutView](t, e.as(p, "GET", "/api/v1/rollouts", "")), func(v RolloutView) string { return v.Rollout.Name })
	}
	for _, c := range []struct {
		name string
		got  func(Principal) []string
		who  Principal
		want []string
	}{
		{"experiments, canary viewer", expNames, canaryView, []string{"opus-5-5-canary"}},
		{"experiments, unit viewer", expNames, payView, []string{}},
		{"experiments, global viewer", expNames, admin, []string{"claude-cli-2.1.3xx-ab", "opus-5-5-canary", "sonnet-next-shadow"}},
		{"devices, unit viewer", devNames, payView, []string{"checkout", "payCanary", "payEarly"}},
		{"devices, canary viewer", devNames, canaryView, []string{"checkout", "otherCanary", "payCanary"}},
		{"devices, ring+unit viewer", devNames, payCanaryView, []string{"checkout", "payCanary"}},
		{"devices, early operator by user id", devNames, userBound, []string{"payEarly"}},
		{"toggles, canary viewer", togNames, canaryView, []string{"github-mcp"}},
		{"toggles, unit viewer", togNames, payView, []string{}},
		{"rollouts, canary viewer", roNames, canaryView, []string{"opus-5-5-upgrade"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.got(c.who); !slices.Equal(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}

	// Fleet: device reports only, placed by the server. otherCanary claims
	// ring2-early in its report; it is still a canary device, so the early
	// operator does not see it and the canary viewer does.
	put := func(device, host, ring string) {
		if err := e.s.cfg.Store.Put(Host{Report: Report{Hostname: host, Device: device, Ring: ring, Digest: "sha256:x"}, LastSeen: *e.now}); err != nil {
			t.Fatal(err)
		}
	}
	put(dv["payCanary"], "h-pay-canary", "ring1-canary")
	put(dv["checkout"], "h-checkout", "ring1-canary")
	put(dv["otherCanary"], "h-other-canary", "ring2-early") // a lie: the server places it in canary
	put(dv["payEarly"], "h-pay-early", "ring2-early")
	put("", "h-fleet-token", "ring1-canary") // no device: the server cannot place it
	fleet := func(p Principal) (int, []string) {
		f := decode[FleetResponse](t, e.as(p, "GET", "/api/v1/fleet", ""))
		sum := 0
		for _, r := range f.Rings {
			sum += r.Hosts
		}
		if sum != f.Total || len(f.Hosts) != f.Total {
			t.Fatalf("fleet counts disagree: total %d hosts %d ring sum %d", f.Total, len(f.Hosts), sum)
		}
		return f.Total, names(f.Hosts, func(h Host) string { return h.Hostname })
	}
	for _, c := range []struct {
		who   Principal
		total int
		hosts []string
	}{
		{admin, 5, []string{"h-checkout", "h-fleet-token", "h-other-canary", "h-pay-canary", "h-pay-early"}},
		{payView, 3, []string{"h-checkout", "h-pay-canary", "h-pay-early"}},
		{canaryView, 3, []string{"h-checkout", "h-other-canary", "h-pay-canary"}},
		{userBound, 1, []string{"h-pay-early"}},
	} {
		if n, hs := fleet(c.who); n != c.total || !slices.Equal(hs, c.hosts) {
			t.Errorf("fleet as %s: %d %v, want %d %v", c.who.ID, n, hs, c.total, c.hosts)
		}
	}

	// Kill list: kills of in-scope experiments and toggles; a stale name has no scope.
	for _, k := range []string{"opus-5-5-canary", "claude-cli-2.1.3xx-ab", toggleKillPrefix + "github-mcp", toggleKillPrefix + "format-hook", "stale-experiment"} {
		if _, err := e.s.kills.Kill(context.Background(), k, "boss", "test"); err != nil {
			t.Fatal(err)
		}
	}
	kills := func(p Principal) []string {
		var v struct {
			Killed []struct{ Experiment string }
		}
		if err := json.Unmarshal(e.as(p, "GET", "/api/v1/killswitch", "").Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return names(v.Killed, func(k struct{ Experiment string }) string { return k.Experiment })
	}
	if got := kills(canaryView); !slices.Equal(got, []string{"opus-5-5-canary", "toggle:github-mcp"}) {
		t.Errorf("canary kill list: %v", got)
	}
	if got := kills(payView); len(got) != 0 {
		t.Errorf("unit viewer kill list: %v", got)
	}
	if got := kills(admin); len(got) != 5 {
		t.Errorf("admin kill list: %v", got)
	}

	// Freeze: only the caller's rings.
	ringsOf := func(p Principal) []string {
		v := decode[FreezeView](t, e.as(p, "GET", "/api/v1/freeze", ""))
		return slices.Sorted(func(yield func(string) bool) {
			for k := range v.Rings {
				if !yield(k) {
					return
				}
			}
		})
	}
	if got := ringsOf(canaryView); !slices.Equal(got, []string{"ring1-canary"}) {
		t.Errorf("canary freeze rings: %v", got)
	}
	if got := ringsOf(payView); len(got) != 0 {
		t.Errorf("unit viewer freeze rings: %v", got)
	}
	if got := ringsOf(admin); len(got) != 4 {
		t.Errorf("admin freeze rings: %v", got)
	}

	// Releases: only the caller's rings (registry faked away).
	e.s.relChannels = func(context.Context, bundle.Pointer) ([]string, error) { return nil, nil }
	e.s.relFetch = func(context.Context, string) (bundle.Pointer, bool, error) { return bundle.Pointer{}, false, nil }
	rel := func(p Principal) []string {
		return names(decode[ReleasesResponse](t, e.as(p, "GET", "/api/v1/releases", "")).Rings, func(r RingRelease) string { return r.Ring })
	}
	if got := rel(canaryView); !slices.Equal(got, []string{"ring1-canary"}) {
		t.Errorf("canary releases: %v", got)
	}
	if got := rel(admin); len(got) != 4 {
		t.Errorf("admin releases: %v", got)
	}
}

// TestScopedRequests: who sees and decides access requests. What deciding a
// request changes comes from the server's record of it, never the decision.
func TestScopedRequests(t *testing.T) {
	e := scopedEnv(t)
	file := func(p Principal, kind, item string) Request {
		w := e.as(p, "POST", "/api/v1/requests", fmt.Sprintf(`{"kind":%q,"item":%q,"justification":"please"}`, kind, item))
		if w.Code != http.StatusCreated {
			t.Fatalf("file %s %s: %d %s", kind, item, w.Code, w.Body)
		}
		return decode[Request](t, w)
	}
	// pete (payments, ring2-early) asks to opt in to ring1-canary: the change
	// touches ring2-early (where he is) and ring1-canary (where he goes).
	optIn := file(ownPayEarly, "ring-opt-in", "ring1-canary")
	// olga (no unit, ring1-canary) asks for an MCP server: her ring's profile
	// is shared by ring1, ring2 and ring3, and every unit.
	mcp := file(ownOtherCanary, "mcp-server", "jira")

	seen := func(p Principal) []string {
		return names(decode[[]Request](t, e.as(p, "GET", "/api/v1/requests", "")), func(r Request) string { return r.ID })
	}
	if got := seen(canaryAppr); len(got) != 0 {
		t.Errorf("canary approver sees %v: the opt-in also moves pete out of ring2-early", got)
	}
	if got := seen(payAppr); !slices.Equal(got, []string{optIn.ID}) {
		t.Errorf("payments approver sees %v, want the payments member's opt-in", got)
	}
	if got := seen(globalAppr); len(got) != 2 {
		t.Errorf("global approver sees %v", got)
	}
	if got := seen(ownPayEarly); !slices.Equal(got, []string{optIn.ID}) {
		t.Errorf("requester sees %v", got)
	}

	for _, c := range []struct {
		name  string
		who   Principal
		id    string
		allow bool
	}{
		{"canary approver: opt-in into canary from early", canaryAppr, optIn.ID, false},
		{"canary approver: mcp request reaching every ring", canaryAppr, mcp.ID, false},
		{"payments approver: mcp request of a non-member", payAppr, mcp.ID, false},
		{"canary approver: unknown request", canaryAppr, "nope", false},
		{"payments approver denies a member's opt-in", payAppr, optIn.ID, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := e.as(c.who, "POST", "/api/v1/requests/"+c.id+"/deny", "")
			if denied := w.Code == http.StatusForbidden; denied == c.allow {
				t.Fatalf("%d %s (allow=%v)", w.Code, w.Body, c.allow)
			}
		})
	}
	if d := lastAudit(t, e); d.Action != "request.deny" || d.Details["authzScope"] != "units=payments" || d.Details["authzBinding"] != "identity.roleBindings[6]" {
		t.Fatalf("decision audit does not name the scoped grant: %+v", d)
	}
}

// TestScopedQuorum: the canary-two rule needs two approvals; a scoped
// approval counts only while its scope covers the step it approves.
func TestScopedQuorum(t *testing.T) {
	e := scopedEnv(t)
	const ro = "opus-5-5-upgrade" // live step canary-5; the next step is in ring1-canary
	approve := func(p Principal) int { return e.as(p, "POST", "/api/v1/rollouts/"+ro+"/approve", "").Code }
	if c := approve(payAppr); c != http.StatusForbidden {
		t.Fatalf("unit-scoped approver on a ring-wide step: %d", c)
	}
	if c := approve(Principal{ID: "ea@acme.example", Groups: []string{"g-early-appr", "g-viewer"}}); c != http.StatusForbidden {
		t.Fatalf("an approver group without an approve grant: %d", c)
	}
	if c := approve(canaryAppr); c != http.StatusOK {
		t.Fatalf("canary approver: %d", c)
	}
	if d := lastAudit(t, e); d.Action != "rollout.approve" || d.Details["authzScope"] != "rings=ring1-canary" {
		t.Fatalf("approval audit lacks its scope: %+v", d)
	}
	got := decode[RolloutApprovals](t, e.as(admin, "GET", "/api/v1/rollouts/"+ro+"/approvals", ""))
	if got.Quorum == nil || got.Quorum.Rules[0].Have != 1 || got.Quorum.Met || len(got.Approvals) != 1 ||
		len(got.Approvals[0].Scopes) != 1 || got.Approvals[0].Scopes[0].String() != "rings=ring1-canary" || len(got.Approvals[0].Groups) != 0 {
		t.Fatalf("after the scoped approval: %+v", got)
	}

	// An approval recorded under a scope that does not cover the step (a
	// retargeted step, or a forged record) is ignored, not counted.
	org, _, _ := e.s.pol.Get()
	key := rollout.ApprovalKey(org, findRolloutIn(org, ro))
	if _, err := e.s.approvals.add(key, policy.ScopedApproval("stale@acme.example", []string{"g-canary-appr"}, *e.now, "", []policy.RoleScope{{Rings: []string{"ring2-early"}}})); err != nil {
		t.Fatal(err)
	}
	got = decode[RolloutApprovals](t, e.as(admin, "GET", "/api/v1/rollouts/"+ro+"/approvals", ""))
	if got.Quorum.Rules[0].Have != 1 || got.Quorum.Met || !slices.ContainsFunc(got.Quorum.Ignored, func(s string) bool { return strings.HasPrefix(s, "stale@acme.example: approve scope") }) {
		t.Fatalf("out-of-scope approval counted: %+v", got.Quorum)
	}
	// The controller's view (rollout.Governance) agrees.
	gov, err := e.s.RolloutGovernance(context.Background(), org, findRolloutIn(org, ro))
	if err != nil {
		t.Fatal(err)
	}
	r := findRolloutIn(org, ro)
	var ev rollout.Evidence
	gov.Apply(org, r, rollout.State{Step: r.StepIndex(r.Step)}, &ev, *e.now)
	if ev.Quorum == nil || ev.Quorum.Rules[0].Have != 1 {
		t.Fatalf("controller quorum: %+v", ev.Quorum)
	}

	if c := approve(globalAppr); c != http.StatusOK {
		t.Fatalf("global approver: %d", c)
	}
	got = decode[RolloutApprovals](t, e.as(admin, "GET", "/api/v1/rollouts/"+ro+"/approvals", ""))
	if !got.Quorum.Met || got.Quorum.Rules[0].Have != 2 {
		t.Fatalf("scoped + global approval: %+v", got.Quorum)
	}
}

// TestScopedAuditFields: an action a scoped grant authorized names it; one a
// global grant authorized reads exactly as before ADR-0037; denials say why.
func TestScopedAuditFields(t *testing.T) {
	e := scopedEnv(t)
	dv := scopedDevices(t, e)
	if c := e.as(canaryOps, "POST", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"bad"}`).Code; c != 200 {
		t.Fatalf("kill: %d", c)
	}
	d := lastAudit(t, e)
	if d.Action != "experiment.kill" || d.Details["authzScope"] != "rings=ring1-canary" || d.Details["authzRole"] != "operator" ||
		d.Details["authzBinding"] != "identity.roleBindings[1]" || d.Details["reason"] != "bad" {
		t.Fatalf("scoped kill audit: %+v", d.Details)
	}
	if c := e.as(globalOps, "POST", "/api/v1/experiments/opus-5-5-canary/unkill", "").Code; c != 200 {
		t.Fatalf("unkill: %d", c)
	}
	if d := lastAudit(t, e); d.Action != "experiment.unkill" || len(d.Details) != 1 {
		t.Fatalf("a global grant adds nothing to the entry: %+v", d.Details)
	}
	if c := e.as(payAdmin, "POST", "/api/v1/devices/"+dv["checkout"]+"/revoke", "").Code; c != http.StatusNoContent {
		t.Fatalf("revoke: %d", c)
	}
	if d := lastAudit(t, e); d.Action != "device.revoke" || d.Details["authzScope"] != "units=payments" || d.Details["authzRole"] != "admin" {
		t.Fatalf("scoped revoke audit: %+v", d.Details)
	}
	for _, c := range []struct {
		who          Principal
		method, path string
		why          string
		resource     string
	}{
		{earlyOps, "POST", "/api/v1/experiments/opus-5-5-canary/kill", scopeWhyOutside, "rings=ring1-canary units=*"},
		{earlyOps, "POST", "/api/v1/experiments/nope/kill", scopeWhyUnknown, ""},
		{canaryView, "GET", "/api/v1/policy", scopeWhyGlobal, ""},
	} {
		e.as(c.who, c.method, c.path, `{"reason":"x"}`)
		d := lastAudit(t, e)
		if d.Action != "authz.deny" || d.Details["scope"] != c.why || d.Details["resource"] != c.resource || !strings.Contains(d.Details["bindings"], "identity.roleBindings[") {
			t.Errorf("%s %s: %+v", c.method, c.path, d.Details)
		}
	}
}

// TestScopedServiceTokens: a token's scope never exceeds its creator's
// grants, is enforced on every request, and bounds who manages it.
func TestScopedServiceTokens(t *testing.T) {
	e := scopedEnv(t)
	dv := scopedDevices(t, e)
	mint := func(p Principal, body string) (int, CreateServiceTokenResponse) {
		w := e.as(p, "POST", "/api/v1/service-tokens", body)
		var out CreateServiceTokenResponse
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	for _, c := range []struct {
		name string
		who  Principal
		body string
		code int
	}{
		{"unit admin: viewer over a descendant unit", payAdmin, `{"name":"co-view","role":"viewer","scope":{"units":["checkout"]}}`, 201},
		{"unit admin: admin over own unit", payAdmin, `{"name":"pay-admin","role":"admin","scope":{"units":["payments"]}}`, 201},
		{"unit admin: own unit narrowed to a ring", payAdmin, `{"name":"pay-canary","role":"operator","scope":{"units":["payments"],"rings":["ring1-canary"]}}`, 201},
		{"unit admin: global token", payAdmin, `{"name":"g","role":"viewer"}`, 403},
		{"empty scope is refused, never global", admin, `{"name":"g","role":"viewer","scope":{}}`, 400},
		{"null scope is refused", admin, `{"name":"g","role":"viewer","scope":null}`, 400},
		{"empty scope lists are refused", admin, `{"name":"g","role":"viewer","scope":{"rings":[],"units":[]}}`, 400},
		{"case-variant key is refused", admin, `{"name":"g","role":"viewer","Scope":{"rings":["ring1-canary"]}}`, 400},
		{"case-variant scope key is refused", admin, `{"name":"g","role":"viewer","scope":{"Rings":["ring1-canary"]}}`, 400},
		{"repeated scope (last would be global) is refused", payAdmin, `{"name":"g","role":"viewer","scope":{"units":["payments"]},"scope":{"rings":[]}}`, 400},
		{"repeated key inside scope is refused", admin, `{"name":"g","role":"viewer","scope":{"units":["payments"],"units":[]}}`, 400},
		{"repeated role (the last would win) is refused", admin, `{"name":"g","role":"viewer","role":"admin"}`, 400},
		{"repeated scope with a valid last value is refused", admin, `{"name":"g","role":"viewer","scope":{"units":["checkout"]},"scope":{"units":["payments"]}}`, 400},
		{"repeated unit list with a valid last value is refused", admin, `{"name":"g","role":"viewer","scope":{"units":["checkout"],"units":["payments"]}}`, 400},
		{"unknown top-level key is refused", admin, `{"name":"g","role":"viewer","scopes":{"units":["payments"]}}`, 400},
		{"unit admin: a ring without the unit", payAdmin, `{"name":"r","role":"viewer","scope":{"rings":["ring1-canary"]}}`, 403},
		{"misspelt scope key is refused, never global", admin, `{"name":"typo","role":"viewer","scope":{"ring":["ring1-canary"]}}`, 400},
		{"unknown ring", admin, `{"name":"x","role":"viewer","scope":{"rings":["ring9"]}}`, 400},
		{"unknown unit", admin, `{"name":"x","role":"viewer","scope":{"units":["nope"]}}`, 400},
		{"duplicate ring", admin, `{"name":"x","role":"viewer","scope":{"rings":["ring1-canary","ring1-canary"]}}`, 400},
		{"scope not an object", admin, `{"name":"x","role":"viewer","scope":["ring1-canary"]}`, 400},
		{"scoped operator holds no admin", canaryOps, `{"name":"x","role":"viewer","scope":{"rings":["ring1-canary"]}}`, 403},
		{"global admin: scoped token", admin, `{"name":"canary-ops","role":"operator","scope":{"rings":["ring1-canary"]}}`, 201},
		{"global admin: global token", admin, `{"name":"global-view","role":"viewer"}`, 201},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code, _ := mint(c.who, c.body); code != c.code {
				t.Fatalf("%d, want %d", code, c.code)
			}
		})
	}
	if d := auditBy(e.auditActions(t), payAdmin.ID, "service-token.create"); len(d) != 3 || d[0].Details["scope"] != "units=checkout" || d[0].Details["authzScope"] != "units=payments" {
		t.Fatalf("scoped create audit: %+v", d)
	}

	_, coView := mint(payAdmin, `{"name":"co-view-2","role":"viewer","scope":{"units":["checkout"]}}`)
	_, payTok := mint(payAdmin, `{"name":"pay-admin-2","role":"admin","scope":{"units":["payments"]}}`)
	if coView.ServiceToken.Role != "viewer" || coView.ServiceToken.Scope.String() != "units=checkout" {
		t.Fatalf("info: %+v", coView.ServiceToken)
	}
	for _, c := range []struct {
		name, tok, method, path string
		code                    int
	}{
		{"checkout token reads checkout device", coView.Token, "GET", "/api/v1/devices/" + dv["checkout"], 200},
		{"checkout token: parent unit's member", coView.Token, "GET", "/api/v1/devices/" + dv["payCanary"], 403},
		{"checkout token: experiments are ring-wide", coView.Token, "GET", "/api/v1/experiments/opus-5-5-canary", 403},
		{"checkout token: policy is global", coView.Token, "GET", "/api/v1/policy", 403},
		{"payments admin token revokes its member's device", payTok.Token, "POST", "/api/v1/devices/" + dv["payEarly"] + "/revoke", 204},
		{"payments admin token: outside device", payTok.Token, "POST", "/api/v1/devices/" + dv["otherCanary"] + "/revoke", 403},
	} {
		t.Run(c.name, func(t *testing.T) {
			if w := e.bearer(c.tok, c.method, c.path, ""); w.Code != c.code {
				t.Fatalf("%d %s, want %d", w.Code, w.Body, c.code)
			}
		})
	}
	if got := names(decode[[]Device](t, e.bearer(coView.Token, "GET", "/api/v1/devices", "")), func(d Device) string { return d.ID }); !slices.Equal(got, []string{dv["checkout"]}) {
		t.Fatalf("checkout token devices: %v", got)
	}
	m := decode[Me](t, e.bearer(coView.Token, "GET", "/api/v1/me", ""))
	if len(m.Bindings) != 1 || m.Bindings[0].Scope.String() != "units=checkout" || m.Bindings[0].Source != "service-token" {
		t.Fatalf("token me: %+v", m.Bindings)
	}

	// Management is bounded too: the payments admin lists and revokes only
	// tokens within payments.
	listed := func(p Principal) []string {
		return names(decode[ServiceTokensResponse](t, e.as(p, "GET", "/api/v1/service-tokens", "")).Tokens, func(i ServiceTokenInfo) string { return i.Name })
	}
	if got := listed(payAdmin); !slices.Equal(got, []string{"co-view", "co-view-2", "pay-admin", "pay-admin-2", "pay-canary"}) {
		t.Fatalf("payments admin lists %v", got)
	}
	if got := listed(admin); len(got) != 7 {
		t.Fatalf("admin lists %v", got)
	}
	var globalID, canaryID string
	for _, i := range decode[ServiceTokensResponse](t, e.as(admin, "GET", "/api/v1/service-tokens", "")).Tokens {
		switch i.Name {
		case "global-view":
			globalID = i.ID
		case "canary-ops":
			canaryID = i.ID
		}
	}
	for _, c := range []struct {
		name, id string
		code     int
	}{
		{"global token", globalID, 403},
		{"canary token (no unit)", canaryID, 403},
		{"unknown id answers as out of scope", strings.Repeat("0", serviceTokenIDLen), 403},
		{"own unit's token", coView.ServiceToken.ID, 200},
	} {
		t.Run("revoke "+c.name, func(t *testing.T) {
			if w := e.as(payAdmin, "POST", "/api/v1/service-tokens/"+c.id+"/revoke", `{"reason":"x"}`); w.Code != c.code {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	if w := e.as(admin, "POST", "/api/v1/service-tokens/"+strings.Repeat("0", serviceTokenIDLen)+"/revoke", `{"reason":"x"}`); w.Code != 404 {
		t.Fatalf("global admin, unknown id: %d", w.Code)
	}
}

// TestScopedTokenRecordSkew: a scoped token's record must not read as a
// global token in a binary from before ADR-0037 (which ignores scope).
func TestScopedTokenRecordSkew(t *testing.T) {
	scoped := newTokenRecord("admin", policy.RoleScope{Units: []string{"payments"}})
	b, _ := json.Marshal(scoped)
	var old struct{ Role string } // the pre-ADR-0037 record's role field
	if err := json.Unmarshal(b, &old); err != nil || validRoles([]string{old.Role}) == nil {
		t.Fatalf("an older binary would accept %s as role %q", b, old.Role)
	}
	for _, c := range []struct {
		name string
		rec  serviceTokenRecord
		role string
		ok   bool
	}{
		{"global", newTokenRecord("viewer", policy.RoleScope{}), "viewer", true},
		{"scoped", scoped, "admin", true},
		{"role and scope together", serviceTokenRecord{Role: "admin", Scope: policy.RoleScope{Units: []string{"payments"}}}, "", false},
		{"scoped role without scope", serviceTokenRecord{ScopedRole: "admin"}, "", false},
		{"both roles", serviceTokenRecord{Role: "viewer", ScopedRole: "admin", Scope: policy.RoleScope{Rings: []string{"r"}}}, "", false},
		{"unknown scoped role", serviceTokenRecord{ScopedRole: "root", Scope: policy.RoleScope{Rings: []string{"r"}}}, "root", false},
		{"empty", serviceTokenRecord{}, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if role, ok := c.rec.role(); ok != c.ok || (ok && role != c.role) {
				t.Fatalf("role() = %q %v", role, ok)
			}
		})
	}
}

// TestScopedRoleCeiling extends TestRoleCeiling to scopes.
func TestScopedRoleCeiling(t *testing.T) {
	e := scopedEnv(t)
	org, _, _ := e.s.pol.Get()
	pay := policy.RoleScope{Units: []string{"payments"}}
	creator := grantPrincipal("c", nil, []policy.Grant{{Role: RoleAdmin, Scope: pay}, {Role: RoleViewer}})
	for _, c := range []struct {
		role  string
		scope policy.RoleScope
		ok    bool
	}{
		{RoleAdmin, pay, true},
		{RoleAdmin, policy.RoleScope{Units: []string{"checkout"}}, true},
		{RoleOperator, policy.RoleScope{Units: []string{"payments"}, Rings: []string{"ring1-canary"}}, true},
		{RoleViewer, policy.RoleScope{}, true}, // read held globally (the admin check is separate: adminGrantOver)
		{RoleOperator, policy.RoleScope{}, false},
		{RoleOperator, policy.RoleScope{Rings: []string{"ring1-canary"}}, false},
		{RoleAdmin, policy.RoleScope{Units: []string{"nope"}}, false},
	} {
		if got := grantWithin(org, c.role, c.scope, creator); got != c.ok {
			t.Errorf("%s over %s: %v, want %v", c.role, c.scope, got, c.ok)
		}
	}
}
