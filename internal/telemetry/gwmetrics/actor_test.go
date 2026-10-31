package gwmetrics

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestActorAttributes: a delegated agent's call carries halo.actor.agent and
// halo.actor.depth on the halo.gateway.* series, halo.actor.agent on the GenAI
// metrics, and gen_ai.agent.name plus the chain on the span; the unit stays
// the root's hash, never the agent's.
func TestActorAttributes(t *testing.T) {
	e, _ := New(Config{OTLPEndpoint: "http://c", UnitSalt: "x-salt-0123456789", GenAI: GenAIConfig{Traces: true}})
	root := genaiReq(200, 10, 5, 0)
	root.Subject = "alice"
	agent := root
	agent.Actor, agent.Chain, agent.ActorDepth = "reviewer", "planner>reviewer", 2
	e.Record(root)
	e.Record(agent)
	b, err := json.Marshal(encodeJSON(e.series, e.gen, e.start, e.now()))
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, want := range []string{`"key":"halo.actor.agent","value":{"stringValue":"reviewer"}`, `"key":"halo.actor.depth","value":{"stringValue":"2"}`} {
		if !strings.Contains(js, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if len(e.series) != 2 {
		t.Fatalf("agent and root calls must be separate series: %d", len(e.series))
	}
	for k := range e.series {
		if k.unit != e.Unit("alice") {
			t.Fatalf("unit is not the root's: %+v", k)
		}
	}
	sp, _ := json.Marshal(encodeSpansJSON(e.spans))
	for _, want := range []string{`"key":"gen_ai.agent.name","value":{"stringValue":"reviewer"}`, `"key":"halo.actor.chain","value":{"stringValue":"planner\u003ereviewer"}`, `"key":"halo.actor.depth","value":{"intValue":"2"}`} {
		if !strings.Contains(string(sp), want) {
			t.Errorf("span lacks %s: %s", want, sp)
		}
	}
	if strings.Count(string(sp), "gen_ai.agent.name") != 1 {
		t.Errorf("the root's own call must not carry an agent name: %s", sp)
	}
}
