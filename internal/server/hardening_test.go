package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/pgstore/pgtest"
)

// Regression tests for the 2026-10-27 halo-server hardening (CHANGELOG
// Security): each fails with its fix reverted.

// TestSCIMValidTokenFromBlockedIP: bad tokens from the IdP's shared egress
// IP block guesses, never the IdP's real deprovisioning (the valid token is
// checked before the limiter, as in gatewayAuth).
func TestSCIMValidTokenFromBlockedIP(t *testing.T) {
	e := scimEnv(t, true, nil)
	for range authFailBurst + 2 {
		e.scimAs("Bearer wrong", "GET", "/scim/v2/Users", "")
	}
	if !e.s.scimFails.blocked("192.0.2.1") {
		t.Fatal("bad tokens did not block the IP")
	}
	if w := e.scimAs("Bearer wrong", "GET", "/scim/v2/Users", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("bad token from a blocked IP: %d", w.Code)
	}
	if w := e.scim("GET", "/scim/v2/Users", ""); w.Code != http.StatusOK {
		t.Fatalf("valid SCIM token from a blocked IP: %d %s", w.Code, w.Body)
	}
}

// TestLimiterKeysIPv6By64: one IPv6 host controls its /64, so failures from
// any address in it share one budget; another /64 and IPv4 are unaffected.
func TestLimiterKeysIPv6By64(t *testing.T) {
	var l authLimiter
	for i := range authFailBurst {
		l.fail(fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	for _, c := range []struct {
		ip      string
		blocked bool
	}{
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", true},
		{"2001:db8:1:3::1", false},
		{"::ffff:192.0.2.1", false},
		{"192.0.2.1", false},
	} {
		if got := l.blocked(c.ip); got != c.blocked {
			t.Errorf("%s: blocked=%v, want %v", c.ip, got, c.blocked)
		}
	}
	if k := limiterKey("::ffff:192.0.2.1"); k != "192.0.2.1" {
		t.Fatalf("v4-mapped key %q", k)
	}
}

func TestSharedAuthLimiterInMemory(t *testing.T) { testSharedAuthLimiter(t, newMemShared()) }

func TestSharedAuthLimiterPostgres(t *testing.T) {
	db, _ := pgtest.OpenTest(t)
	testSharedAuthLimiter(t, NewPGBackend(db))
}

// testSharedAuthLimiter: with a shared Backend, failures spread over two
// replicas spend one budget. Per replica neither reaches authFailBurst.
func testSharedAuthLimiter(t *testing.T, b Backend) {
	a, c := replicas(t, b)
	const ip = "198.51.100.40"
	for i := range authFailBurst {
		e := a
		if i%2 == 1 {
			e = c
		}
		e.s.scimFails.fail(ip)
	}
	a.s.scimFails.fail(ip) // a learns the shared count at its next failure
	if !a.s.scimFails.blocked(ip) || !c.s.scimFails.blocked(ip) {
		t.Fatalf("%d failures across two replicas: blocked a=%v c=%v", authFailBurst+1, a.s.scimFails.blocked(ip), c.s.scimFails.blocked(ip))
	}
	if a.s.gwFails.blocked(ip) {
		t.Fatal("another endpoint class shares the budget")
	}
}

// TestDecisionNotReportedUnlessPersisted: a decision whose save fails is a
// 500 and the request stays pending; one whose audit append fails is a 500
// too (AuditStrict), never a 200 "approved".
func TestDecisionNotReportedUnlessPersisted(t *testing.T) {
	newReq := func(e *env) string {
		t.Helper()
		w := e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("request: %d %s", w.Code, w.Body)
		}
		return decode[Request](t, w).ID
	}
	for _, verb := range []string{"approve", "deny"} {
		t.Run(verb+" save fails", func(t *testing.T) {
			e := newEnv(t, func(c *Config) { c.DataDir = t.TempDir() })
			id := newReq(e)
			_ = e.s.reqs.log.Close() // every append now errors
			if w := e.as(admin, "POST", "/api/v1/requests/"+id+"/"+verb, ""); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), `"status"`) {
				t.Fatalf("decision not persisted, answered %d %s", w.Code, w.Body)
			}
			if got := e.s.reqs.byID[id].Status; got != StatusPending {
				t.Fatalf("request is %q after a failed save, want pending", got)
			}
		})
		t.Run(verb+" audit fails", func(t *testing.T) {
			e := newEnv(t, func(c *Config) { c.DataDir = t.TempDir() })
			id := newReq(e)
			_ = e.s.auditLog.f.Close()
			if w := e.as(admin, "POST", "/api/v1/requests/"+id+"/"+verb, ""); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), errAuditFailed) {
				t.Fatalf("decision without its audit record answered %d %s", w.Code, w.Body)
			}
		})
	}
}

// TestPostureUnknownWhenRegistryUnreachable: a device whose release cannot
// be checked (registry down, nothing cached) is unknown, not current.
func TestPostureUnknownWhenRegistryUnreachable(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.GatewayToken = "gw-tok" })
	e.s.relFetch = func(context.Context, string) (bundle.Pointer, bool, error) {
		return bundle.Pointer{}, false, errors.New("dial tcp: connection refused")
	}
	tok, _, err := e.s.devices.mint(dev, *e.now)
	if err != nil {
		t.Fatal(err)
	}
	if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+tok, `{"hostname":"laptop-1","digest":"sha256:zz","drift":[]}`).Code; c != 204 {
		t.Fatalf("report: %d", c)
	}
	v := e.s.posture(context.Background(), dev.ID)
	if v.Compliant || !strings.Contains(v.Reason, "posture unknown") {
		t.Fatalf("registry unreachable: %+v, want not compliant (unknown)", v)
	}
	// The channel list unreadable while the device is off the ring digest: unknown too.
	org, _, _ := e.s.pol.Get()
	ring := org.ResolveRing(dev.subject()).Name
	e.s.relCache.byKey = map[string]cachedPointer{}
	e.s.relFetch = func(context.Context, string) (bundle.Pointer, bool, error) {
		return bundle.Pointer{Org: org.Name, Ring: ring, Digest: "sha256:aa", Seq: 1, ExpiresAt: e.now.Add(time.Hour)}, true, nil
	}
	e.s.relChannels = func(context.Context, bundle.Pointer) ([]string, error) { return nil, errors.New("blob unreadable") }
	if v := e.s.posture(context.Background(), dev.ID); v.Compliant || !strings.Contains(v.Reason, "posture unknown") {
		t.Fatalf("channels unreadable: %+v", v)
	}
}

// TestPostureSeesDevicesFromOtherReplica: posture catches up with the shared
// device registry, so a device enrolled on another replica counts.
func TestPostureSeesDevicesFromOtherReplica(t *testing.T) {
	a, c := replicas(t, newMemShared())
	for _, e := range []*env{a, c} {
		e.s.cfg.Portal.Registry = "" // release check off: only the device view matters here
	}
	if _, _, err := a.s.devices.mint(dev, *a.now); err != nil {
		t.Fatal(err)
	}
	if v := c.s.posture(context.Background(), dev.ID); strings.Contains(v.Reason, "no enrolled device") {
		t.Fatalf("device enrolled on a unseen by c's posture: %+v", v)
	}
	bad := newEnv(t, func(cfg *Config) { cfg.Backend = failingShared{newMemShared()} })
	if v := bad.s.posture(context.Background(), dev.ID); v.Compliant || !strings.Contains(v.Reason, "unknown") {
		t.Fatalf("registry unreadable: %+v", v)
	}
}

// TestServerRequestMetrics: requests by route pattern (never the raw path)
// and status class, authz denies, auth failures by reason, limiter blocks
// and gateway lookups.
func TestServerRequestMetrics(t *testing.T) {
	e := scimEnv(t, false, nil)
	e.as(admin, "GET", "/api/v1/devices/some-device-id", "")
	e.as(dev, "GET", "/api/v1/devices", "")
	for range authFailBurst + 1 {
		e.scimAs("Bearer wrong", "GET", "/scim/v2/Users", "")
	}
	r := httptest.NewRequest("POST", "/api/v1/enroll", strings.NewReader(`{"token":"nope"}`))
	r.RemoteAddr = "203.0.113.9:1"
	e.h.ServeHTTP(httptest.NewRecorder(), r)
	do(e.h, "GET", "/api/v1/gateway/directory?subject=x", "Bearer "+gwTok, "")
	do(e.h, "GET", "/api/v1/gateway/directory?revocations=1", "Bearer "+gwTok, "")
	var m strings.Builder
	e.s.WriteMetrics(&m)
	out := m.String()
	for _, want := range []string{
		`halo_server_requests_total{route="GET /api/v1/devices/{id}",status="4xx"} 1`,
		`halo_server_request_duration_seconds_count{route="GET /api/v1/devices/{id}",status="4xx"} 1`,
		`halo_server_requests_total{route="GET /api/v1/devices",status="4xx"} 1`,
		`halo_server_authz_denied_total{route="GET /api/v1/devices"} 1`,
		`halo_server_auth_limited_total{route="GET /scim/v2/Users"} 1`,
		`halo_server_auth_failures_total{flow="enroll",reason="invalid_token"} 1`,
		`halo_server_gateway_lookups_total{kind="directory",outcome="inactive"} 1`,
		`halo_server_gateway_lookups_total{kind="revocations",outcome="ok"} 1`,
		"# TYPE halo_server_request_duration_seconds histogram",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
	if strings.Contains(out, "some-device-id") {
		t.Fatal("a raw path became a label")
	}
}
