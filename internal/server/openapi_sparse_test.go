package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/cloudagents"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/rollout"
)

// TestOpenAPISparseViews is the empty-state pass for bodies the live test
// cannot make sparse because they are built from policy: a ring, experiment,
// toggle, rollout and profile with nothing optional set must still encode
// every list the schema declares as a list, never as null. The fix for a
// failure belongs in the view (return []), not in the schema.
func TestOpenAPISparseViews(t *testing.T) {
	_, doc := loadSpec(t)
	sc := specCompiler(t, doc)
	org := &policy.Org{
		Name:        "sparse",
		Profiles:    map[string]*policy.Profile{"p": {}},
		Rings:       []*policy.Ring{{Profile: "p"}},
		Experiments: []*policy.Experiment{{}},
		Toggles:     []*policy.Toggle{{}},
		Rollouts:    []*policy.Rollout{{Steps: []policy.RolloutStep{{}}}},
	}
	org.Profiles["p"].Name, org.Rings[0].Name, org.Experiments[0].Name, org.Toggles[0].Name, org.Rollouts[0].Name = "p", "r", "e", "t", "ro"
	pv := buildPolicyView(org)
	ev := ExperimentDetail{ExperimentView: pv.Experiments[0]}
	tv := toggleView(org.Toggles[0], nil, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	rv := RolloutView{Rollout: org.Rollouts[0], Timeline: rollout.BuildTimeline(org, org.Rollouts[0])}
	for name, v := range map[string]any{
		"PolicyView":        pv,
		"ExperimentDetail":  ev,
		"ToggleView":        tv,
		"togglesResponse":   togglesResponse{Toggles: []ToggleView{tv}},
		"RolloutView":       rv,
		"CloudKillResponse": CloudKillResponse{Actions: cloudagents.Plan(nil, cloudagents.OpCancel), NextSteps: []string{}},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var inst any
		if err := json.Unmarshal(b, &inst); err != nil {
			t.Fatal(err)
		}
		validateAt(t, sc, specURL+"#/components/schemas/"+name, inst, name+" built from sparse policy")
	}
}
