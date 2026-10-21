package gateway

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func agentOrg() *policy.Org {
	org := testOrg()
	org.Gateway.Models["haiku"] = policy.ModelRoute{Upstream: "orch", Model: "us.anthropic.claude-haiku-4-5"}
	org.Agents = &policy.Agents{
		AllowedModels: []string{"sonnet", "haiku"},
		DeniedTools:   []string{"Bash"},
		Actors:        []policy.AgentActor{{Name: "planner"}, {Name: "reviewer"}, {Name: "haiku-only", Models: []string{"haiku"}}},
	}
	return org
}

func delegated(id string, groups []string, chain ...string) *policy.Subject {
	d := &policy.DelegationChain{ID: "j"}
	for _, a := range chain {
		d.Actors = append(d.Actors, policy.Actor{Agent: a})
	}
	return &policy.Subject{ID: id, Groups: groups, Delegation: d}
}

func msg(model string, extra string) []byte {
	return []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]` + extra + `}`)
}

// directUser finds a subject the sonnet-canary puts in its "direct" arm.
func directUser(t *testing.T, org *policy.Org) string {
	t.Helper()
	for i := range 10_000 {
		id := fmt.Sprintf("user-%d", i)
		if d := Decide(org, RequestInfo{UserID: id, ModelAlias: "sonnet"}); d.Variant == "direct" {
			return id
		}
	}
	t.Fatal("no user in the direct arm")
	return ""
}

// TestDelegatedCohortIsRoot: a delegated agent routes as its root (ring,
// release), stays out of experiments by default, and with
// agents.experiments gets exactly the root's arm, never one of its own.
func TestDelegatedCohortIsRoot(t *testing.T) {
	org := agentOrg()
	id := directUser(t, org)
	root := PrepareVerified(org, &policy.Subject{ID: id}, http.Header{}, PathMessages, msg("sonnet", ""))
	agent := PrepareVerified(org, delegated(id, nil, "planner"), http.Header{}, PathMessages, msg("sonnet", ""))
	if agent.Reject != nil || agent.Decision.Ring != root.Decision.Ring || agent.Decision.Release != root.Decision.Release {
		t.Fatalf("agent cohort %+v, root %+v", agent.Decision, root.Decision)
	}
	if agent.Decision.Experiment != "" || len(agent.Decision.Shadow) != 0 || agent.Decision.UpstreamModel != "us.anthropic.claude-sonnet-4-5" {
		t.Fatalf("agent enrolled by default: %+v", agent.Decision)
	}
	org.Agents.Experiments = true
	agent = PrepareVerified(org, delegated(id, nil, "planner", "reviewer"), http.Header{}, PathMessages, msg("sonnet", ""))
	if agent.Decision.Experiment != root.Decision.Experiment || agent.Decision.Variant != root.Decision.Variant {
		t.Fatalf("agent arm %s/%s, root %s/%s", agent.Decision.Experiment, agent.Decision.Variant, root.Decision.Experiment, root.Decision.Variant)
	}
	// A workload root stays out unless workloads.experiments allows it too.
	wl := delegated("workload:gh:acme/app", nil, "planner")
	wl.Kind = policy.SubjectWorkload
	if d := PrepareVerified(org, wl, http.Header{}, PathMessages, msg("sonnet", "")).Decision; d.Experiment != "" {
		t.Fatalf("workload's agent enrolled: %+v", d)
	}
}

// TestDelegatedAdmission: the current policy bounds every delegated call.
func TestDelegatedAdmission(t *testing.T) {
	scoped := delegated("alice", nil, "planner")
	scoped.Delegation.Models = []string{"sonnet"}
	for _, tc := range []struct {
		name  string
		org   func(*policy.Org)
		sub   *policy.Subject
		body  []byte
		allow bool
	}{
		{"allowed", nil, delegated("alice", nil, "planner"), msg("sonnet", ""), true},
		{"model outside allowedModels", func(o *policy.Org) { o.Agents.AllowedModels = []string{"haiku"} }, delegated("alice", nil, "planner"), msg("sonnet", ""), false},
		{"model outside actor's models", nil, delegated("alice", nil, "haiku-only"), msg("sonnet", ""), false},
		{"model outside credential scope", nil, scoped, msg("haiku", ""), false},
		{"actor removed from policy", nil, delegated("alice", nil, "rogue"), msg("sonnet", ""), false},
		{"depth over a lowered maxDepth", func(o *policy.Org) { o.Agents.MaxDepth = 1 }, delegated("alice", nil, "planner", "reviewer"), msg("sonnet", ""), false},
		{"agents removed from policy", func(o *policy.Org) { o.Agents = nil }, delegated("alice", nil, "planner"), msg("sonnet", ""), false},
		{"denied tool", nil, delegated("alice", nil, "planner"), msg("sonnet", `,"tools":[{"name":"Read"},{"name":"bash"}]`), false},
		{"denied tool in a duplicate key", nil, delegated("alice", nil, "planner"), msg("sonnet", `,"tools":[{"name":"Bash"}],"tools":[]`), false},
		{"denied tool in a case variant", nil, delegated("alice", nil, "planner"), msg("sonnet", `,"tools":[{"name":"Bash"}],"TOOLS":[]`), false},
		{"denied tool in a duplicate name", nil, delegated("alice", nil, "planner"), msg("sonnet", `,"tools":[{"name":"Bash","NAME":"Read"}]`), false},
		{"denied tool for the root itself", nil, &policy.Subject{ID: "alice"}, msg("sonnet", `,"tools":[{"name":"Bash"}]`), true},
	} {
		org := agentOrg()
		if tc.org != nil {
			tc.org(org)
		}
		res := PrepareVerified(org, tc.sub, http.Header{}, PathMessages, tc.body)
		if got := res.Reject == nil; got != tc.allow {
			t.Errorf("%s: allowed=%v reject=%v", tc.name, got, res.Reject)
		}
		if res.Reject != nil && (res.Reject.Status != http.StatusBadRequest || res.Reject.Code != "agent_not_permitted") {
			t.Errorf("%s: rejection %+v", tc.name, res.Reject)
		}
	}
}

// TestActorHeadersStripped: client x-halo-actor values never reach the
// upstream; the gateway stamps the verified chain instead, and nothing for a
// caller that is not delegated.
func TestActorHeadersStripped(t *testing.T) {
	org := agentOrg()
	h := http.Header{}
	h.Set("X-Halo-Actor", "ceo-agent")
	h.Set("X-Halo-Actor-Depth", "0")
	// halo-kong's header list is capped: the actor names are cleared even
	// when the client's copies did not make it into the list.
	if res := PrepareVerified(org, nil, http.Header{}, PathMessages, msg("sonnet", "")); !slices.Contains(res.ClearHeaders, HeaderActor) || !slices.Contains(res.ClearHeaders, HeaderActorDepth) {
		t.Fatalf("actor headers not always cleared: %v", res.ClearHeaders)
	}
	for _, sub := range []*policy.Subject{nil, {ID: "alice"}, delegated("alice", nil, "planner", "reviewer")} {
		res := PrepareVerified(org, sub, h, PathMessages, msg("sonnet", ""))
		for _, n := range []string{HeaderActor, HeaderActorDepth} {
			if !slices.Contains(res.ClearHeaders, n) {
				t.Fatalf("%s not cleared: %v", n, res.ClearHeaders)
			}
		}
		want := map[string]string{}
		if sub != nil && sub.Delegation != nil {
			want = map[string]string{HeaderActor: "planner>reviewer", HeaderActorDepth: "2"}
		}
		for _, n := range []string{HeaderActor, HeaderActorDepth} {
			if res.Decision.Headers[n] != want[n] {
				t.Fatalf("sub %+v: %s=%q want %q", sub, n, res.Decision.Headers[n], want[n])
			}
		}
	}
}

func TestToolNames(t *testing.T) {
	for _, tc := range []struct {
		proto, body string
		want        []string
	}{
		{ProtoAnthropic, `{"tools":[{"name":"Bash","input_schema":{"properties":{"name":{"type":"string"}}}},{"type":"web_search_20250305","name":"web_search"}]}`, []string{"Bash", "web_search_20250305", "web_search"}},
		{ProtoResponses, `{"tools":[{"type":"function","name":"shell"},{"type":"web_search"}]}`, []string{"function", "shell", "web_search"}},
		{ProtoGemini, `{"tools":[{"functionDeclarations":[{"name":"run_shell"},{"name":"read"}]},{"googleSearch":{}}]}`, []string{"run_shell", "read"}},
		{ProtoAnthropic, `not json`, nil},
		{ProtoAnthropic, `{"messages":[]}`, nil},
	} {
		if got := ToolNames(tc.proto, []byte(tc.body)); !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: %v want %v", tc.proto, tc.body, got, tc.want)
		}
	}
}
