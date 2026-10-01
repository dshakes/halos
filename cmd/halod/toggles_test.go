package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// publishToggles publishes a canary ring release whose profile carries toggle
// "on" (rule: user "u" or group "ops" or 100% percent, per rules).
func (e *env) publishToggles(t *testing.T, tg ...*policy.Toggle) {
	t.Helper()
	mu.Lock()
	files = func(string) []harness.File {
		return []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`1`)}}
	}
	mu.Unlock()
	org := &policy.Org{Name: "acme", Toggles: tg, Profiles: map[string]*policy.Profile{
		"p": {Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: "2.0.0"}}},
	}}
	rel, err := release.Build(org, "p", "canary", release.Options{Version: "1", Org: "acme", OSes: []harness.OS{harness.Linux}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Publish(context.Background(), e.store, rel, e.sign, "canary"); err != nil {
		t.Fatal(err)
	}
}

func envToggle(name string, rules ...policy.ToggleRule) *policy.Toggle {
	return &policy.Toggle{
		Meta: policy.Meta{Name: name}, Owner: "me", Axis: policy.AxisClient, Rules: rules,
		Client: &policy.ToggleClient{Harnesses: map[string]policy.TogglePatch{"claude-code": {Env: map[string]string{"TOG_" + name: "on"}}}},
	}
}

func settingsEnv(t *testing.T, e *env) map[string]any {
	t.Helper()
	var doc struct{ Env map[string]any }
	if err := json.Unmarshal([]byte(e.read(settings)), &doc); err != nil {
		t.Fatalf("settings not JSON: %v\n%s", err, e.read(settings))
	}
	return doc.Env
}

func TestTogglesAppliedAndKilled(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.a.Install, e.a.Log, e.a.Cfg.Subject = false, quietLog(), "u"
	e.a.User = "u"
	e.publishToggles(t,
		envToggle("userrule", policy.ToggleRule{Users: []string{"u"}}),
		envToggle("grouprule", policy.ToggleRule{Groups: []string{"ops"}}),
		envToggle("otheruser", policy.ToggleRule{Users: []string{"someone-else"}}),
		envToggle("ringrule", policy.ToggleRule{Rings: []string{"canary"}}),
	)
	ks := newKillServer(t)
	e.a.Kill = ks.switchFor(t)

	// Cfg.Ring pins the ring, so no groups are known: the group rule stays off.
	st, err := e.a.Once(ctx)
	if err != nil {
		t.Fatal(err)
	}
	envv := settingsEnv(t, e)
	if envv["TOG_userrule"] != "on" || envv["TOG_ringrule"] != "on" {
		t.Fatalf("matching toggles not applied: %v", envv)
	}
	if _, ok := envv["TOG_otheruser"]; ok {
		t.Fatalf("non-matching toggle applied: %v", envv)
	}
	if got := st.Toggles; len(got) != 2 || got[0] != "ringrule" || got[1] != "userrule" {
		t.Fatalf("status toggles = %v", got)
	}
	if len(st.Drift) != 0 {
		t.Fatalf("drift %v", st.Drift)
	}
	if e.read(settings) == "" || !strings.Contains(e.read(settings), `"requiredMinimumVersion"`) {
		t.Fatal("base settings lost in the merge")
	}

	// Kill one toggle: the cached verified release is re-applied with no registry
	// round trip, the killed fragment disappears, the other stays.
	ks.set(func(k *killServer) { k.toggles = []string{"userrule"} })
	e.a.Open = noRegistry(t)
	if err := e.a.PollKill(ctx); err != nil {
		t.Fatal(err)
	}
	envv = settingsEnv(t, e)
	if _, ok := envv["TOG_userrule"]; ok || envv["TOG_ringrule"] != "on" {
		t.Fatalf("after kill: %v", envv)
	}
	s := e.a.loadState().Status
	if len(s.Toggles) != 1 || s.Toggles[0] != "ringrule" || len(s.KilledToggles) != 1 || len(s.Drift) != 0 {
		t.Fatalf("status after kill: %+v", s)
	}
	if err := e.a.PollKill(ctx); err != nil { // steady state: nothing to do
		t.Fatal(err)
	}

	// Unkill: back on, still without the registry.
	ks.set(func(k *killServer) { k.toggles = nil })
	if err := e.a.PollKill(ctx); err != nil {
		t.Fatal(err)
	}
	if settingsEnv(t, e)["TOG_userrule"] != "on" {
		t.Fatalf("unkill did not restore the toggle: %v", settingsEnv(t, e))
	}
}

func serveRing(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

// A device with no subject id never lands in a percent rollout; with one it
// follows the same bucket the gateway computes.
func TestTogglePercentNeedsSubject(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.a.Install, e.a.Log = false, quietLog()
	e.publishToggles(t, envToggle("everyone", policy.ToggleRule{Percent: 100}))
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := settingsEnv(t, e)["TOG_everyone"]; ok {
		t.Fatal("anonymous device joined a percent rollout")
	}
	e.a.Cfg.Subject = "u"
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if settingsEnv(t, e)["TOG_everyone"] != "on" {
		t.Fatal("identified device missed a 100% rollout")
	}
}

// Group rules need the groups the ring endpoint reports for the device.
func TestToggleGroupsFromRingEndpoint(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.a.Install, e.a.Log, e.a.Cfg.Subject = false, quietLog(), "u"
	e.publishToggles(t, envToggle("ops-only", policy.ToggleRule{Groups: []string{"ops"}}))
	e.a.Cfg.Ring = "" // use the endpoint
	e.a.Cfg.RingEndpoint = serveRing(t, `{"ring":"canary","subject":"u","groups":["ops","x"]}`)
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if settingsEnv(t, e)["TOG_ops-only"] != "on" {
		t.Fatalf("group rule not applied: %v", settingsEnv(t, e))
	}
	if g := e.a.loadState().Groups; len(g) != 2 {
		t.Fatalf("groups not persisted for offline fallback: %v", g)
	}
}
