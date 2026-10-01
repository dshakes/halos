package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

func orgWithRouteToggle() *policy.Org {
	org := testOrg()
	org.Toggles = []*policy.Toggle{{
		Meta: policy.Meta{Name: "sonnet-next"}, Axis: policy.AxisTraffic,
		Rules: []policy.ToggleRule{{Rings: []string{"ring0"}}},
		Traffic: &policy.ToggleTraffic{Routes: map[string]policy.ModelRoute{
			"sonnet": {Upstream: "anthropic", Model: "claude-sonnet-5-5"},
		}},
	}}
	return org
}

func TestTrafficToggleRoutesAlias(t *testing.T) {
	org := orgWithRouteToggle()
	ring0 := RequestInfo{UserID: "alice", Groups: []string{"ai-platform"}, ModelAlias: "sonnet"}
	tests := []struct {
		name      string
		req       RequestInfo
		wantModel string
	}{
		{"ring0 user is routed by the toggle", ring0, "claude-sonnet-5-5"},
		{"other alias unaffected", RequestInfo{UserID: "alice", Groups: ring0.Groups, ModelAlias: "opus"}, ""}, // control route of opus
		{"anonymous caller keeps the default route", RequestInfo{ModelAlias: "sonnet", Groups: ring0.Groups}, "us.anthropic.claude-sonnet-4-5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(org, tc.req)
			if tc.wantModel != "" && d.UpstreamModel != tc.wantModel {
				t.Fatalf("model = %q, want %q (%+v)", d.UpstreamModel, tc.wantModel, d)
			}
			if tc.wantModel == "claude-sonnet-5-5" && d.Upstream != "https://api.anthropic.com" {
				t.Fatalf("upstream = %q", d.Upstream)
			}
			if tc.req.ModelAlias == "opus" && d.UpstreamModel == "claude-sonnet-5-5" {
				t.Fatal("toggle leaked onto another alias")
			}
		})
	}

	// A user outside ring0 stays on the default route.
	for i := 0; i < 200; i++ {
		d := Decide(org, RequestInfo{UserID: "ga-user-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), ModelAlias: "sonnet"})
		if d.Ring != "ring0" && d.UpstreamModel == "claude-sonnet-5-5" {
			t.Fatalf("user in ring %q got the ring0 toggle", d.Ring)
		}
	}
}

// Killed toggles are dropped by KillSwitch.Apply, so the alias routes as before.
func TestKilledTrafficToggleIsOff(t *testing.T) {
	org := orgWithRouteToggle()
	req := RequestInfo{UserID: "alice", Groups: []string{"ai-platform"}, ModelAlias: "sonnet"}
	k := &KillSwitch{}
	k.Restore(KillList{Toggles: []string{"sonnet-next"}, IssuedAt: time.Unix(1, 0)})
	d := Decide(k.Apply(org), req)
	if d.UpstreamModel != "us.anthropic.claude-sonnet-4-5" {
		t.Fatalf("killed toggle still routes: %+v", d)
	}
	if len(org.Toggles) != 1 {
		t.Fatal("Apply mutated the shared policy snapshot")
	}
	if Decide(org, req).UpstreamModel != "claude-sonnet-5-5" {
		t.Fatal("unkilled org changed")
	}
	// A kill for an unrelated toggle leaves it on.
	k2 := &KillSwitch{}
	k2.Restore(KillList{Toggles: []string{"other"}, IssuedAt: time.Unix(1, 0)})
	if k2.Apply(org) != org {
		t.Fatal("unrelated toggle kill must return org unchanged")
	}
}

// The toggle names ride in the signed payload: tampering with them breaks the
// signature, and the freshness and monotonicity rules apply unchanged.
func TestKillListTogglesSignedFreshMonotonic(t *testing.T) {
	pub, priv := killKeys(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	good, err := SignKillList(priv, KillList{Version: 1, Toggles: []string{"a"}, IssuedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	l, err := VerifyKillList(pub, good, now, 10*time.Minute)
	if err != nil || !slices.Equal(l.Toggles, []string{"a"}) {
		t.Fatalf("verify: %+v %v", l, err)
	}
	tampered := KillEnvelope{Payload: []byte(`{"version":1,"experiments":[],"issuedAt":"2026-09-01T12:00:00Z"}`), Signature: good.Signature}
	if _, err := VerifyKillList(pub, tampered, now, 10*time.Minute); err == nil {
		t.Fatal("dropping a killed toggle must break the signature")
	}
	stale, _ := SignKillList(priv, KillList{Toggles: []string{"a"}, IssuedAt: now.Add(-time.Hour)})
	if _, err := VerifyKillList(pub, stale, now, 10*time.Minute); err == nil {
		t.Fatal("stale list accepted")
	}

	// Poller: a toggle kill is applied, an older (replayed) list cannot undo it.
	ks := &killServer{}
	srv := httptest.NewServer(ks)
	defer srv.Close()
	k, err := NewKillSwitch(srv.URL, "tok", pub, 0, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	if err != nil {
		t.Fatal(err)
	}
	k.Now = func() time.Time { return now }
	sign := func(at time.Time, toggles ...string) KillEnvelope {
		env, err := SignKillList(priv, KillList{Toggles: toggles, IssuedAt: at})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	ctx := context.Background()
	ks.set(200, sign(now.Add(-time.Second), "a"))
	if err := k.Refresh(ctx); err != nil || !slices.Equal(k.Killed().Toggles, []string{"a"}) {
		t.Fatalf("kill not applied: %v %+v", err, k.Killed())
	}
	ks.set(200, sign(now.Add(-time.Minute))) // replay of an older, empty list
	if err := k.Refresh(ctx); err == nil || !slices.Equal(k.Killed().Toggles, []string{"a"}) {
		t.Fatalf("replay undid a toggle kill: %v %+v", err, k.Killed())
	}
	ks.set(200, sign(now)) // newer list without it: unkill
	if err := k.Refresh(ctx); err != nil || len(k.Killed().Toggles) != 0 {
		t.Fatalf("unkill: %v %+v", err, k.Killed())
	}
}

// percent: 0 must route nobody, not everybody (it once meant "no condition").
func TestTrafficTogglePercentZeroRoutesNobody(t *testing.T) {
	org := orgWithRouteToggle()
	zero := 0.0
	org.Toggles[0].Rules = []policy.ToggleRule{{Rings: []string{"ring0"}, Percent: &zero}, {Percent: &zero}}
	for _, req := range []RequestInfo{
		{UserID: "alice", Groups: []string{"ai-platform"}, ModelAlias: "sonnet"},
		{ModelAlias: "sonnet"}, // anonymous
	} {
		if d := Decide(org, req); d.UpstreamModel == "claude-sonnet-5-5" {
			t.Fatalf("%+v routed by a percent:0 toggle", req)
		}
	}
}
