package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

const gwTok = "gateway-token-0123456789"

var ksNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// testClock is shared by the server (httptest goroutines) and the test.
type testClock struct{ ns atomic.Int64 }

func (c *testClock) Now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *testClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

func newKillServer(t *testing.T, admin bool) (*Server, http.Handler, ed25519.PublicKey) {
	t.Helper()
	c := &testClock{}
	c.ns.Store(ksNow.UnixNano())
	return newKillServerClock(t, admin, c)
}

func newKillServerClock(t *testing.T, admin bool, clock *testClock) (*Server, http.Handler, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		PolicyDir: "../../examples/acme-corp", Token: tok,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     clock.Now,
		DevUser: "alice@test", DevAdmin: admin,
		KillKey: priv, GatewayToken: gwTok,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, s.Handler(), pub
}

func TestKillEndpointsAuthz(t *testing.T) {
	_, dev, _ := newKillServer(t, false)
	for _, path := range []string{"/api/v1/experiments/opus-5-5-canary/kill", "/api/v1/experiments/opus-5-5-canary/unkill"} {
		if w := do(dev, "POST", path, "", `{"reason":"x"}`); w.Code != http.StatusForbidden {
			t.Fatalf("non-admin %s: %d", path, w.Code)
		}
	}
	if w := do(dev, "GET", "/api/v1/killswitch", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin list: %d", w.Code)
	}

	s, h, _ := newKillServer(t, true)
	// Cross-origin POST is refused even for an admin session.
	r := httptest.NewRequest("POST", "/api/v1/experiments/opus-5-5-canary/kill", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin kill: %d", w.Code)
	}
	for _, tc := range []struct {
		name, path, body string
		code             int
		changed          bool
	}{
		{"unknown experiment", "/api/v1/experiments/nope/kill", `{"reason":"x"}`, 404, false},
		{"no reason", "/api/v1/experiments/opus-5-5-canary/kill", ``, 422, false},
		{"blank reason", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"  "}`, 422, false},
		{"bad json", "/api/v1/experiments/opus-5-5-canary/kill", `{`, 400, false},
		{"reason too long", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"` + strings.Repeat("x", 501) + `"}`, 422, false},
		{"kill", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"error spike"}`, 200, true},
		{"kill again", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"dup"}`, 200, false},
		{"unkill", "/api/v1/experiments/opus-5-5-canary/unkill", `{"reason":"fixed"}`, 200, true},
		{"unkill stale name, no reason", "/api/v1/experiments/gone/unkill", ``, 200, false},
		{"kill for list", "/api/v1/experiments/opus-5-5-canary/kill", `{"reason":"again"}`, 200, true},
	} {
		w := do(h, "POST", tc.path, "", tc.body)
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body)
		}
		if tc.code == 200 {
			var out struct{ Changed bool }
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if out.Changed != tc.changed {
				t.Fatalf("%s: changed=%v", tc.name, out.Changed)
			}
		}
	}
	// Audit: one entry per actual change, with actor and reason.
	entries, err := s.auditLog.all()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Actor+" "+e.Action+" "+e.Target+" "+e.Details["reason"])
	}
	want := []string{"alice@test experiment.kill opus-5-5-canary error spike", "alice@test experiment.unkill opus-5-5-canary fixed", "alice@test experiment.kill opus-5-5-canary again"}
	if !slices.Equal(got, want) {
		t.Fatalf("audit = %q", got)
	}
	w = do(h, "GET", "/api/v1/killswitch", "", "")
	var list struct {
		Version uint64
		Killed  []struct{ Experiment, By, Reason string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Killed) != 1 || list.Killed[0].By != "alice@test" || list.Killed[0].Reason != "again" || list.Version != 3 {
		t.Fatalf("list: %v %s", err, w.Body)
	}
	// The in-process controller path, wired exactly as cmd/halo-server does, kills the
	// experiment (not one named after the actor: found by make uat-k8s) and is audited.
	if ch, err := controller.KillFunc(s.KillExperiment).Kill(context.Background(), "claude-cli-2.1.3xx-ab", controller.Actor, "rollback: guardrail"); err != nil || !ch {
		t.Fatalf("KillExperiment: %v %v", ch, err)
	}
	entries, _ = s.auditLog.all()
	if e := entries[len(entries)-1]; e.Actor != controller.Actor || e.Action != "experiment.kill" {
		t.Fatalf("controller kill not audited: %+v", e)
	}
	w = do(h, "GET", "/api/v1/killswitch", "", "")
	if !strings.Contains(w.Body.String(), `"experiment":"claude-cli-2.1.3xx-ab"`) || strings.Contains(w.Body.String(), `"experiment":"`+controller.Actor+`"`) {
		t.Fatalf("controller kill list: %s", w.Body)
	}
}

// Without a signing key nothing is served to gateways: kills are refused
// (501) and the console is told the kill switch is unavailable.
func TestKillWithoutKeyNotImplemented(t *testing.T) {
	s, err := New(Config{PolicyDir: "../../examples/acme-corp", Token: tok, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DevUser: "alice@test", DevAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	for _, p := range []string{"kill", "unkill"} {
		if w := do(h, "POST", "/api/v1/experiments/opus-5-5-canary/"+p, "", `{"reason":"x"}`); w.Code != http.StatusNotImplemented {
			t.Fatalf("%s without key: %d", p, w.Code)
		}
	}
	for _, tc := range []struct {
		h    http.Handler
		want bool
	}{{h, false}, {func() http.Handler { _, h, _ := newKillServer(t, true); return h }(), true}} {
		var caps map[string]bool
		if w := do(tc.h, "GET", "/api/v1/capabilities", "", ""); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &caps) != nil || caps["killSwitch"] != tc.want {
			t.Fatalf("capabilities = %d %s, want killSwitch=%v", w.Code, w.Body, tc.want)
		}
	}
}

func TestGatewayKillswitchEndpoint(t *testing.T) {
	s, h, pub := newKillServer(t, true)
	if _, err := s.KillExperiment(context.Background(), "opus-5-5-canary", "halo-controller", "r"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, auth string
		code       int
	}{
		{"no token", "", 401},
		{"wrong token", "Bearer nope", 401},
		{"report token is not a gateway token", "Bearer " + tok, 401},
		{"basic scheme", "Basic " + gwTok, 401},
		{"ok", "Bearer " + gwTok, 200},
	} {
		w := do(h, "GET", "/api/v1/gateway/killswitch", tc.auth, "")
		if w.Code != tc.code {
			t.Fatalf("%s: %d", tc.name, w.Code)
		}
		if tc.code != 200 {
			continue
		}
		var env gateway.KillEnvelope
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		l, err := gateway.VerifyKillList(pub, env, ksNow, time.Minute)
		if err != nil || !slices.Equal(l.Experiments, []string{"opus-5-5-canary"}) || l.Version != 1 {
			t.Fatalf("list %+v err %v", l, err)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("kill list cacheable")
		}
	}
	// Not configured: 404 even with a token.
	s2, err := New(Config{PolicyDir: "../../examples/acme-corp", Token: tok, DevUser: "a", Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if w := do(s2.Handler(), "GET", "/api/v1/gateway/killswitch", "Bearer ", ""); w.Code != 404 {
		t.Fatalf("unconfigured: %d", w.Code)
	}
}

// End to end in-process: admin kill on halo-server -> signed list -> gateway
// poller -> PrepareVerified routes the treated user to control; unkill restores.
func TestKillSwitchEndToEnd(t *testing.T) {
	clock := &testClock{}
	clock.ns.Store(ksNow.UnixNano())
	_, h, pub := newKillServerClock(t, true, clock)
	srv := httptest.NewServer(h)
	defer srv.Close()
	org, err := policy.Load("../../examples/acme-corp")
	if err != nil {
		t.Fatal(err)
	}
	// Only the traffic canary (the example's client-axis A/B would claim the users first).
	org.Experiments = slices.DeleteFunc(org.Experiments, func(e *policy.Experiment) bool { return e.Name != "opus-5-5-canary" })
	var sub *policy.Subject
	for i := 0; i < 50000 && sub == nil; i++ {
		s := &policy.Subject{ID: fmt.Sprintf("user%d@acme.example", i)}
		if d := gateway.Decide(org, gateway.RequestInfo{UserID: s.ID, ModelAlias: "opus"}); d.Experiment == "opus-5-5-canary" && d.Variant == "opus-5-5" {
			sub = s
		}
	}
	if sub == nil {
		t.Fatal("no user in the opus-5-5 treatment")
	}
	ks, err := gateway.NewKillSwitch(srv.URL+"/api/v1/gateway/killswitch", gwTok, pub, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	if err != nil {
		t.Fatal(err)
	}
	ks.Now = clock.Now
	body := []byte(`{"model":"opus","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`)
	route := func() gateway.Decision {
		t.Helper()
		res := gateway.PrepareVerified(ks.Apply(org), sub, http.Header{}, "/v1/messages", body)
		if res.Reject != nil {
			t.Fatalf("rejected: %v", res.Reject)
		}
		return res.Decision
	}
	ctx := context.Background()
	if err := ks.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if d := route(); d.Variant != "opus-5-5" {
		t.Fatalf("before kill: %+v", d)
	}
	if w := do(h, "POST", "/api/v1/experiments/opus-5-5-canary/kill", "", `{"reason":"errors"}`); w.Code != 200 {
		t.Fatalf("kill: %d", w.Code)
	}
	// Gateways see it on their next poll; the server clock must move for a strictly newer list.
	if err := ks.Refresh(ctx); err == nil {
		t.Fatal("same-instant list accepted (replay protection)")
	}
	clock.Advance(time.Second)
	if err := ks.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	d := route()
	if d.Experiment != "" || d.Variant != "" || d.Headers[gateway.HeaderExperiment] != "" {
		t.Fatalf("killed experiment still routed: %+v", d)
	}
	if want := org.Gateway.Models["opus"].Primary(); d.UpstreamName != want.Upstream || d.UpstreamModel != want.Model {
		t.Fatalf("not on control route: %+v want %+v", d, want)
	}
	// halo-server down: the kill stays in force.
	srv.Close()
	if err := ks.Refresh(ctx); err == nil {
		t.Fatal("refresh against a closed server succeeded")
	}
	if d := route(); d.Variant != "" {
		t.Fatalf("kill lapsed while control plane down: %+v", d)
	}
}

// Enrolled devices fetch the same signed list with their device token; the
// gateway endpoint and its token are unchanged.
func TestFleetKillswitchEndpoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *Config) { c.KillKey, c.GatewayToken = priv, gwTok })
	dt := enrollDevice(t, e, dev)
	if _, err := e.s.KillExperiment(context.Background(), "cli-ab", "halo-controller", "r"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, auth string
		code       int
	}{
		{"no token", "", 401},
		{"gateway token is not a device token", "Bearer " + gwTok, 401},
		{"report token is not a device token", "Bearer " + tok, 401},
		{"device token", "Bearer " + dt, 200},
	} {
		w := do(e.h, "GET", "/api/v1/fleet/killswitch", tc.auth, "")
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body)
		}
		if tc.code != 200 {
			continue
		}
		var env gateway.KillEnvelope
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if l, err := gateway.VerifyKillList(pub, env, *e.now, time.Minute); err != nil || !slices.Equal(l.Experiments, []string{"cli-ab"}) {
			t.Fatalf("list %+v err %v", l, err)
		}
		gw := do(e.h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
		if gw.Code != 200 || gw.Body.String() != w.Body.String() { // same clock: byte-identical envelope
			t.Fatalf("gateway endpoint changed: %d %s vs %s", gw.Code, gw.Body, w.Body)
		}
	}
	// The public key is served for enrollment and matches the signing key.
	if w := do(e.h, "GET", "/enroll/killswitch.pub", "", ""); w.Code != 200 {
		t.Fatalf("killswitch.pub: %d", w.Code)
	} else if v, err := bundle.ParseEd25519Verifier(w.Body.Bytes()); err != nil || !v.Key.Equal(pub) {
		t.Fatalf("killswitch.pub: %v", err)
	}
	// Enrollment names the kill-switch url and pubkey path (per OS).
	lt := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	var cfg struct {
		KillSwitch struct{ URL, PubKey string } `yaml:"killSwitch"`
	}
	if w := do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+lt+`","os":"darwin"}`); w.Code != 200 || yaml.Unmarshal(w.Body.Bytes(), &cfg) != nil {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	if cfg.KillSwitch.URL != "https://halo.acme.example/api/v1/fleet/killswitch" || cfg.KillSwitch.PubKey != "/Library/Halos/etc/killswitch.pub" {
		t.Fatalf("enroll killSwitch = %+v", cfg.KillSwitch)
	}
	if sh := do(e.h, "GET", "/enroll.sh", "", "").Body.String(); !strings.Contains(sh, `"$SERVER/enroll/killswitch.pub"`) {
		t.Fatalf("enroll.sh does not fetch killswitch.pub:\n%s", sh)
	}
	// Revoked device: refused.
	for _, d := range e.s.devices.list() {
		if _, err := e.s.devices.revoke(d.ID); err != nil {
			t.Fatal(err)
		}
	}
	if c := do(e.h, "GET", "/api/v1/fleet/killswitch", "Bearer "+dt, "").Code; c != 401 {
		t.Fatalf("revoked device: %d", c)
	}
	// Failed attempts are rate limited like the other device endpoints.
	for i := 0; i < authFailBurst; i++ {
		do(e.h, "GET", "/api/v1/fleet/killswitch", "Bearer bad", "")
	}
	if c := do(e.h, "GET", "/api/v1/fleet/killswitch", "Bearer bad", "").Code; c != 429 {
		t.Fatalf("want 429 after burst, got %d", c)
	}
	// Not configured: 404, and enrollment omits killSwitch.
	bare := newEnv(t, nil)
	bt := enrollDevice(t, bare, dev)
	if c := do(bare.h, "GET", "/api/v1/fleet/killswitch", "Bearer "+bt, "").Code; c != 404 {
		t.Fatalf("unconfigured: %d", c)
	}
	if c := do(bare.h, "GET", "/enroll/killswitch.pub", "", "").Code; c != 404 {
		t.Fatalf("unconfigured pub: %d", c)
	}
}

// Toggle kills share the experiment kill store, auth, audit and signed list,
// but surface in KillList.Toggles, never in Experiments.
func TestToggleKillEndpoints(t *testing.T) {
	_, dev, _ := newKillServer(t, false)
	if w := do(dev, "POST", "/api/v1/toggles/github-mcp/kill", "", `{"reason":"x"}`); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin toggle kill: %d", w.Code)
	}

	_, h, pub := newKillServer(t, true)
	for _, tc := range []struct {
		name, path, body string
		code             int
	}{
		{"unknown toggle", "/api/v1/toggles/nope/kill", `{"reason":"x"}`, 404},
		{"experiment name is not a toggle", "/api/v1/toggles/opus-5-5-canary/kill", `{"reason":"x"}`, 404},
		{"no reason", "/api/v1/toggles/github-mcp/kill", ``, 422},
		{"kill", "/api/v1/toggles/github-mcp/kill", `{"reason":"bad MCP"}`, 200},
		{"kill again is a no-op", "/api/v1/toggles/github-mcp/kill", `{"reason":"bad MCP"}`, 200},
	} {
		if w := do(h, "POST", tc.path, "", tc.body); w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body)
		}
	}
	fetch := func() gateway.KillList {
		t.Helper()
		w := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
		var env gateway.KillEnvelope
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		l, err := gateway.VerifyKillList(pub, env, ksNow, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if l := fetch(); !slices.Equal(l.Toggles, []string{"github-mcp"}) || len(l.Experiments) != 0 {
		t.Fatalf("after kill: %+v", l)
	}
	if w := do(h, "POST", "/api/v1/toggles/github-mcp/unkill", "", ``); w.Code != 200 {
		t.Fatalf("unkill: %d %s", w.Code, w.Body)
	}
	if l := fetch(); len(l.Toggles) != 0 {
		t.Fatalf("after unkill: %+v", l)
	}
}

// The experiment endpoints cannot reach toggle kills (or any malformed key).
func TestKillRejectsInvalidNames(t *testing.T) {
	_, h, pub := newKillServer(t, true)
	if w := do(h, "POST", "/api/v1/toggles/github-mcp/kill", "", `{"reason":"x"}`); w.Code != 200 {
		t.Fatalf("setup kill: %d", w.Code)
	}
	for _, path := range []string{
		"/api/v1/experiments/toggle:github-mcp/unkill",
		"/api/v1/experiments/toggle:github-mcp/kill",
		"/api/v1/toggles/toggle:github-mcp/unkill",
		"/api/v1/toggles/Bad%20Name/unkill",
		"/api/v1/experiments/Bad%20Name/unkill",
	} {
		if w := do(h, "POST", path, "", `{"reason":"x"}`); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d, want 400", path, w.Code)
		}
	}
	w := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
	var env gateway.KillEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if l, err := gateway.VerifyKillList(pub, env, ksNow, time.Minute); err != nil || !slices.Equal(l.Toggles, []string{"github-mcp"}) {
		t.Fatalf("toggle kill was removed: %+v %v", l, err)
	}
}

// ADR-0009 (9o): a kill stays applied when its audit append fails (fail safe);
// a failed unkill is reverted so the kill stays in force. Both answer 500.
func TestKillAuditFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		PolicyDir: "../../examples/acme-corp", Token: tok, DataDir: t.TempDir(),
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DevUser: "alice@test", DevAdmin: true, KillKey: priv, GatewayToken: gwTok,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	const exp = "/api/v1/experiments/opus-5-5-canary/"
	killed := func() int {
		recs, _, err := s.kills.Killed()
		if err != nil {
			t.Fatal(err)
		}
		return len(recs)
	}

	_ = s.auditLog.f.Close() // every append now errors
	if w := do(h, "POST", exp+"kill", "", `{"reason":"spike"}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("kill with broken audit: %d %s", w.Code, w.Body)
	}
	if killed() != 1 {
		t.Fatal("kill must stay applied when the audit append fails")
	}
	if w := do(h, "POST", exp+"unkill", "", `{"reason":"fixed"}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("unkill with broken audit: %d %s", w.Code, w.Body)
	}
	if killed() != 1 {
		t.Fatal("unrecorded unkill must be reverted: kill stays in force")
	}
}
