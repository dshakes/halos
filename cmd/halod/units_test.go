package main

import (
	"context"
	"testing"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// TestUnitFilesApplied: the device's unit (picked from the signed manifest
// with its subject) replaces the release's own files, toggles still merge on
// top, and a device in no unit gets the release's own files.
func TestUnitFilesApplied(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.a.Install, e.a.Log, e.a.Cfg.Subject, e.a.User = false, quietLog(), "u", "u"
	mu.Lock()
	files = func(string) []harness.File {
		return []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`1`)}}
	}
	mu.Unlock()
	unit := func(name, parent, user, bu string) *policy.Unit {
		return &policy.Unit{Meta: policy.Meta{Name: name}, Parent: parent, Owners: []string{"@acme/" + name},
			Members: policy.UnitMembers{Users: []string{user}}, Overlay: policy.Overlay{Env: map[string]string{"BU_" + name: bu}}}
	}
	org := &policy.Org{Name: "acme", Toggles: []*policy.Toggle{envToggle("userrule", policy.ToggleRule{Users: []string{"u"}})},
		Units:    []*policy.Unit{unit("payments", "", "u", "payments"), unit("checkout", "payments", "u", "checkout"), unit("search", "", "x", "search")},
		Profiles: map[string]*policy.Profile{"p": {Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: "2.0.0"}}}},
	}
	rel, err := release.Build(org, "p", "canary", release.Options{Version: "1", Org: "acme", OSes: []harness.OS{harness.Linux}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Publish(ctx, e.store, rel, e.sign, "canary"); err != nil {
		t.Fatal(err)
	}

	st, err := e.a.Once(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env := settingsEnv(t, e)
	if st.Unit != "checkout" || env["BU_payments"] != "payments" || env["BU_checkout"] != "checkout" || env["TOG_userrule"] != "on" {
		t.Fatalf("unit %q, env %v: want checkout (with its parent's overlay) plus the toggle", st.Unit, env)
	}
	if _, ok := env["BU_search"]; ok {
		t.Fatalf("another unit's overlay applied: %v", env)
	}

	e.a.Cfg.Subject, e.a.User = "nobody", "nobody"
	if st, err = e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	env = settingsEnv(t, e)
	if st.Unit != "" || env["BU_payments"] != nil {
		t.Fatalf("device in no unit: unit %q, env %v", st.Unit, env)
	}
}
