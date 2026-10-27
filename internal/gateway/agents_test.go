package gateway

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func agentOrg() *policy.Org {
	org := testOrg()
	org.Gateway.Models["haiku"] = policy.ModelRoute{Upstream: "orch", Model: "us.anthropic.claude-haiku-5-5"}
	org.Agents = &policy.Agents{
		AllowedModels: []string{"sonnet", "haiku"},
		DeniedTools:   []string{"Bash"},
		Actors:        []policy.AgentActor{{Name: "planner"}, {Name: "reviewer"}, {Name: "haiku-only", Models: []string{"haiku"}}},
	}
	// Agent depth resolves the root's ring profile, so every ring needs one.
	org.Profiles = map[string]*policy.Profile{"base": {Meta: policy.Meta{Name: "base"}}}
	for _, r := range org.Rings {
		r.Profile = "base"
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
	if agent.Decision.Experiment != "" || len(agent.Decision.Shadow) != 0 || agent.Decision.UpstreamModel != "us.anthropic.claude-sonnet-5-5" {
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

const (
	gemPath      = "/v1beta/models/gemini-pro:generateContent"
	conversePath = "/model/sonnet/converse"
)

func TestToolNames(t *testing.T) {
	fn := func(n ...string) []Tool {
		out := make([]Tool, len(n))
		for i, s := range n {
			out[i] = Tool{Name: s}
		}
		return out
	}
	hosted := func(n string) Tool { return Tool{Name: n, Hosted: true} }
	for _, tc := range []struct {
		name, proto, path, body string
		want                    []Tool
	}{
		{"anthropic function and server tool", ProtoAnthropic, PathMessages, `{"tools":[{"name":"Bash","input_schema":{"properties":{"name":{"type":"string"}}}},{"type":"web_search_20250305","name":"web_search"},{"type":"custom","name":"Read"}]}`,
			[]Tool{{Name: "Bash"}, {Name: "web_search"}, hosted("web_search_20250305"), {Name: "Read"}}},
		{"anthropic mcp_servers", ProtoAnthropic, PathMessages, `{"mcp_servers":[{"type":"url","url":"https://mcp.example","name":"github"}]}`, []Tool{hosted("mcp:github")}},
		{"count_tokens", ProtoAnthropic, PathCountTokens, `{"tools":[{"name":"Bash"}]}`, fn("Bash")},
		{"responses", ProtoResponses, PathResponses, `{"tools":[{"type":"function","name":"shell"},{"type":"web_search_preview"},{"type":"mcp","server_label":"jira"}]}`,
			[]Tool{{Name: "shell"}, hosted("web_search_preview"), hosted("mcp:jira")}},
		{"gemini camelCase and hosted", ProtoGemini, gemPath, `{"tools":[{"functionDeclarations":[{"name":"run_shell"},{"name":"read"}]},{"googleSearch":{}},{"codeExecution":{}}]}`,
			[]Tool{{Name: "run_shell"}, {Name: "read"}, hosted("googleSearch"), hosted("codeExecution")}},
		{"gemini snake_case", ProtoGemini, gemPath, `{"tools":[{"function_declarations":[{"name":"Bash"}]},{"url_context":{}}]}`, []Tool{{Name: "Bash"}, hosted("url_context")}},
		{"gemini countTokens request", ProtoGemini, "/v1beta/models/gemini-pro:countTokens", `{"generateContentRequest":{"tools":[{"functionDeclarations":[{"name":"Bash"}]}]}}`, fn("Bash")},
		{"bedrock converse", ProtoBedrock, conversePath, `{"toolConfig":{"tools":[{"toolSpec":{"name":"Bash","inputSchema":{"json":{}}}},{"cachePoint":{"type":"default"}},{"systemTool":{"name":"nova_grounding"}}]}}`,
			[]Tool{{Name: "Bash"}, hosted("nova_grounding")}},
		{"bedrock converse additional fields", ProtoBedrock, "/model/sonnet/converse-stream", `{"additionalModelRequestFields":{"tools":[{"type":"computer_20250124","name":"computer"}]}}`,
			[]Tool{{Name: "computer"}, hosted("computer_20250124")}},
		{"bedrock invoke", ProtoBedrock, "/model/sonnet/invoke", `{"tools":[{"name":"Bash"}]}`, fn("Bash")},
		{"no tools", ProtoAnthropic, PathMessages, `{"messages":[]}`, nil},
	} {
		got, err := ToolNames(tc.proto, tc.path, []byte(tc.body))
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v %v want %v", tc.name, got, err, tc.want)
		}
	}
}

// TestToolNamesFailClosed: bodies or tool declarations the gateway cannot
// read are errors, never "no tools".
func TestToolNamesFailClosed(t *testing.T) {
	deep := strings.Repeat("[", maxJSONDepth+2) + strings.Repeat("]", maxJSONDepth+2)
	for _, tc := range []struct{ name, proto, path, body string }{
		{"not json", ProtoAnthropic, PathMessages, `not json`},
		{"nested past the depth cap", ProtoAnthropic, PathMessages, `{"tools":[{"name":"Bash"}],"metadata":{"x":` + deep + `}}`},
		{"trailing value", ProtoAnthropic, PathMessages, `{"messages":[]}{"tools":[{"name":"Bash"}]}`},
		{"not an object", ProtoAnthropic, PathMessages, `[]`},
		{"tools not an array", ProtoAnthropic, PathMessages, `{"tools":{"name":"Bash"}}`},
		{"tool not an object", ProtoAnthropic, PathMessages, `{"tools":["Bash"]}`},
		{"name not a string", ProtoAnthropic, PathMessages, `{"tools":[{"name":["Bash"]}]}`},
		{"tool without name or type", ProtoAnthropic, PathMessages, `{"tools":[{"input_schema":{}}]}`},
		{"responses function without name", ProtoResponses, PathResponses, `{"tools":[{"type":"function","function":{"name":"Bash"}}]}`},
		{"responses mcp without label", ProtoResponses, PathResponses, `{"tools":[{"type":"mcp"}]}`},
		{"converse toolSpec without name", ProtoBedrock, conversePath, `{"toolConfig":{"tools":[{"toolSpec":{"Name ":"Bash"}}]}}`},
		{"gemini declaration without name", ProtoGemini, gemPath, `{"tools":[{"functionDeclarations":[{}]}]}`},
		{"unknown protocol", "openai-chat", "/v1/chat/completions", `{"tools":[]}`},
		{"unknown path", ProtoAnthropic, "/v1/messages/batches", `{}`},
	} {
		if got, err := ToolNames(tc.proto, tc.path, []byte(tc.body)); err == nil {
			t.Errorf("%s: read as %v, want an error", tc.name, got)
		}
	}
}

// TestDelegatedToolBypasses reproduces the review's bypasses of
// agents.deniedTools; each one is refused in the protocol's error shape.
func TestDelegatedToolBypasses(t *testing.T) {
	deep := strings.Repeat("[", 70) + strings.Repeat("]", 70)
	org := agentOrg()
	org.Agents.DeniedTools = []string{"Bash", "web_search", "code_execution", "mcp"}
	org.Gateway.Models["gemini-pro"] = policy.ModelRoute{Upstream: "orch", Model: "gemini-pro"}
	org.Agents.AllowedModels = append(org.Agents.AllowedModels, "gemini-pro")
	for _, tc := range []struct{ name, path, body string }{
		{"H1 tools hidden behind deep nesting", PathMessages, `{"model":"sonnet","tools":[{"name":"Bash"}],"metadata":{"x":` + deep + `},"messages":[{"role":"user","content":"hi"}]}`},
		{"M1 gemini snake_case declarations", gemPath, `{"tools":[{"function_declarations":[{"name":"Bash"}]}],"contents":[{"parts":[{"text":"hi"}]}]}`},
		{"M2 bedrock converse toolSpec", conversePath, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"Bash","inputSchema":{"json":{"type":"object"}}}}]}}`},
		{"M2 converse additionalModelRequestFields", conversePath, `{"messages":[],"additionalModelRequestFields":{"tools":[{"type":"bash_20250124","name":"bash"}]}}`},
		{"hosted anthropic web search, versioned", PathMessages, `{"model":"sonnet","tools":[{"type":"web_search_20250305","name":"search"}],"messages":[]}`},
		{"hosted anthropic mcp server", PathMessages, `{"model":"sonnet","mcp_servers":[{"type":"url","url":"https://x","name":"github"}],"messages":[]}`},
		{"hosted gemini code execution", gemPath, `{"tools":[{"codeExecution":{}}],"contents":[]}`},
		{"hosted openai mcp", PathResponses, `{"model":"sonnet","tools":[{"type":"mcp","server_label":"jira","server_url":"https://x"}],"input":"hi"}`},
		{"hosted openai web search preview", PathResponses, `{"model":"sonnet","tools":[{"type":"web_search_preview"}],"input":"hi"}`},
	} {
		res := PrepareVerified(org, delegated("alice", nil, "planner"), http.Header{}, tc.path, []byte(tc.body))
		if res.Reject == nil || res.Reject.Code != "agent_not_permitted" || res.Reject.Protocol != ProtocolForPath(tc.path) {
			t.Errorf("%s: %+v", tc.name, res.Reject)
		}
	}
	// Hosted tools that are not denied, and readable bodies, pass.
	for _, body := range []string{
		`{"model":"sonnet","tools":[{"type":"text_editor_20250124","name":"str_replace_editor"}],"messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"sonnet","tools":[{"name":"Read"}],"metadata":{"x":[[[]]]},"messages":[{"role":"user","content":"hi"}]}`,
	} {
		if res := PrepareVerified(org, delegated("alice", nil, "planner"), http.Header{}, PathMessages, []byte(body)); res.Reject != nil {
			t.Errorf("%s: %+v", body, res.Reject)
		}
	}
	// Without deniedTools nothing is inspected, so nothing is refused for it.
	org.Agents.DeniedTools = nil
	if res := PrepareVerified(org, delegated("alice", nil, "planner"), http.Header{}, PathMessages, []byte(`{"model":"sonnet","metadata":{"x":`+deep+`},"messages":[]}`)); res.Reject != nil {
		t.Errorf("no deniedTools: %+v", res.Reject)
	}
}

// TestDelegatedChainRecheck (L3): the gateway re-checks every actor of the
// chain against today's policy (groups, models) and the root's profile and
// unit maxDepth, not only the current actor and the org cap.
func TestDelegatedChainRecheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		org  func(*policy.Org)
		sub  *policy.Subject
	}{
		{"current actor's groups no longer held", func(o *policy.Org) { o.Agents.Actors[1].Groups = []string{"platform-admins"} }, delegated("alice", []string{"eng"}, "planner", "reviewer")},
		{"parent actor's groups no longer held", func(o *policy.Org) { o.Agents.Actors[0].Groups = []string{"platform-admins"} }, delegated("alice", []string{"eng"}, "planner", "reviewer")},
		{"parent actor narrowed to haiku", func(o *policy.Org) { o.Agents.Actors[0].Models = []string{"haiku"} }, delegated("alice", nil, "planner", "reviewer")},
		{"parent actor removed", func(o *policy.Org) { o.Agents.Actors = o.Agents.Actors[1:] }, delegated("alice", nil, "planner", "reviewer")},
		{"profile maxDepth lowered", func(o *policy.Org) { o.Profiles["base"].Agents.MaxDepth = 1 }, delegated("alice", nil, "planner", "reviewer")},
		{"unit maxDepth lowered", func(o *policy.Org) {
			o.Units = []*policy.Unit{{Meta: policy.Meta{Name: "payments"}, Members: policy.UnitMembers{Users: []string{"alice"}}, Overlay: policy.Overlay{Agents: policy.AgentLimits{MaxDepth: 1}}}}
		}, delegated("alice", nil, "planner", "reviewer")},
	} {
		org := agentOrg()
		if res := PrepareVerified(org, tc.sub, http.Header{}, PathMessages, msg("sonnet", "")); res.Reject != nil {
			t.Fatalf("%s: baseline refused: %+v", tc.name, res.Reject)
		}
		org = agentOrg()
		tc.org(org)
		if res := PrepareVerified(org, tc.sub, http.Header{}, PathMessages, msg("sonnet", "")); res.Reject == nil || res.Reject.Code != "agent_not_permitted" {
			t.Errorf("%s: %+v", tc.name, res.Reject)
		}
	}
}
