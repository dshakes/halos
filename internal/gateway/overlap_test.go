package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// overlapOrg adds a second running canary routing "sonnet" on ring1/ga, named so
// it sorts before sonnet-canary but is listed after it (snapshot order != name order).
func overlapOrg() *policy.Org {
	org := testOrg()
	org.Experiments = append(org.Experiments, &policy.Experiment{
		Meta: policy.Meta{Name: "a-sonnet-rival"}, Type: policy.ExperimentCanary, Axis: policy.AxisTraffic,
		Status: "running", Rings: []string{"ring1", "ga"},
		Variants: []policy.Variant{
			{Name: "control", Weight: 50, Control: true},
			{Name: "rival", Weight: 50, Routes: map[string]policy.ModelRoute{"sonnet": {Upstream: "anthropic", Model: "rival"}}},
		},
	})
	return org
}

// Overlapping traffic experiments: the gateway picks the first BY NAME, whatever
// the snapshot order, so every gateway replica and halo-kong agree.
func TestDecideOverlapFirstByName(t *testing.T) {
	org := overlapOrg()
	rev := overlapOrg()
	slices.Reverse(rev.Experiments)
	for i := 0; i < 50; i++ {
		req := RequestInfo{UserID: fmt.Sprintf("user%d", i), ModelAlias: "sonnet"}
		a, b := Decide(org, req), Decide(rev, req)
		if a.Experiment != "a-sonnet-rival" || b.Experiment != a.Experiment || b.Variant != a.Variant || b.UpstreamModel != a.UpstreamModel {
			t.Fatalf("%s: listed order %s/%s vs reversed %s/%s", req.UserID, a.Experiment, a.Variant, b.Experiment, b.Variant)
		}
	}
	if !slices.Equal(expNames(byName(org.Experiments)), []string{"a-sonnet-rival", "sonnet-canary", "sonnet-shadow"}) {
		t.Fatalf("byName = %v", expNames(byName(org.Experiments)))
	}
	if expNames(org.Experiments)[0] != "sonnet-canary" {
		t.Fatal("byName must not reorder the snapshot in place")
	}
}

func expNames(es []*policy.Experiment) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

// A snapshot that was never validated still loads, but the overlap is logged.
func TestSnapshotWarnsOnOverlap(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := filepath.Join(t.TempDir(), "policy.json")
	b, _ := json.Marshal(overlapOrg())
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if o, err := NewSnapshot(p).Get(); err != nil || o == nil {
		t.Fatalf("load: %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "overlapping traffic experiments") ||
		!strings.Contains(out, `\"a-sonnet-rival\" and \"sonnet-canary\" both route alias \"sonnet\"`) {
		t.Fatalf("no overlap warning:\n%s", out)
	}
}

// Concurrent canaries on different aliases share a ring: each claims only the
// requests for the alias it routes, so both get traffic and every request
// carries exactly the experiment that routed it.
func TestDecidePerAliasExperiments(t *testing.T) {
	org := testOrg()
	org.Gateway.Models["opus"] = policy.ModelRoute{Upstream: "orch", Model: "opus-base"}
	org.Gateway.Models["haiku"] = policy.ModelRoute{Upstream: "orch", Model: "haiku-base"}
	canary := func(name, alias string) *policy.Experiment {
		return &policy.Experiment{Meta: policy.Meta{Name: name}, Type: policy.ExperimentCanary, Axis: policy.AxisTraffic,
			Status: "running", Rings: []string{"ga"},
			Variants: []policy.Variant{
				{Name: "control", Weight: 50, Control: true},
				{Name: "next", Weight: 50, Routes: map[string]policy.ModelRoute{alias: {Upstream: "anthropic", Model: alias + "-next"}}},
			}}
	}
	// "a-opus" sorts first: before per-alias selection it claimed every request.
	org.Experiments = []*policy.Experiment{canary("a-opus", "opus"), canary("b-sonnet", "sonnet")}
	seen := map[string]int{} // alias/experiment/variant
	for i := 0; i < 400; i++ {
		user := fmt.Sprintf("user%d", i)
		for _, alias := range []string{"opus", "sonnet", "haiku"} {
			d := Decide(org, RequestInfo{UserID: user, ModelAlias: alias})
			if d.Ring != "ga" {
				break
			}
			want := map[string]string{"opus": "a-opus", "sonnet": "b-sonnet", "haiku": ""}[alias]
			if d.Experiment != want || d.Headers[HeaderExperiment] != want || (want == "") != (d.Headers[HeaderVariant] == "") {
				t.Fatalf("%s %s: experiment %q headers %v, want %q", user, alias, d.Experiment, d.Headers, want)
			}
			if d.Variant == "next" && d.UpstreamModel != alias+"-next" || d.Variant == "control" && d.UpstreamModel == alias+"-next" {
				t.Fatalf("%s %s: variant %s routed to %s", user, alias, d.Variant, d.UpstreamModel)
			}
			seen[alias+"/"+d.Experiment+"/"+d.Variant]++
		}
	}
	for _, k := range []string{"opus/a-opus/next", "opus/a-opus/control", "sonnet/b-sonnet/next", "sonnet/b-sonnet/control"} {
		if seen[k] < 20 {
			t.Errorf("%s got %d requests: %v", k, seen[k], seen)
		}
	}
}
