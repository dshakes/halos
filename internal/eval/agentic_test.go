package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/shadow"
)

// A Claude Code-shaped session: the developer asks for a fix, the agent runs
// the tests (terminal output comes back as a tool_result), edits, re-runs.
const ccTools = `[{"name":"Bash","input_schema":{"type":"object","required":["command"]}},
{"name":"Edit","input_schema":{"type":"object","required":["file_path","old_string","new_string"]}},
{"name":"Read","input_schema":{"type":"object","required":["file_path"]}}]`

var ccHistory = []string{
	`{"role":"user","content":[{"type":"text","text":"make the tests pass","cache_control":{"type":"ephemeral"}}]}`,
	`{"role":"assistant","content":[{"type":"text","text":"Running the tests."},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"go test ./..."}}]}`,
	`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"--- FAIL: TestAdd\n    add_test.go:9: got 3, want 4\nFAIL"}]}`,
	`{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Edit","input":{"file_path":"add.go","old_string":"a + b - 1","new_string":"a + b"}}]}`,
	`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","content":"ok"}]}`,
}

// ccRequest is the request at step n: the first 2n+1 history turns. Cache
// markers move to the last turn as Claude Code does.
func ccRequest(n int) json.RawMessage {
	h := make([]string, 2*n+1)
	copy(h, ccHistory[:2*n+1])
	if n > 0 {
		h[0] = strings.Replace(h[0], `,"cache_control":{"type":"ephemeral"}`, "", 1)
	}
	return json.RawMessage(fmt.Sprintf(`{"model":"sonnet","max_tokens":8192,"tools":%s,"messages":[%s]}`, ccTools, strings.Join(h, ",")))
}

func ccResp(blocks string) json.RawMessage {
	return json.RawMessage(`{"type":"message","role":"assistant","content":[` + blocks + `],"usage":{"input_tokens":10,"output_tokens":5}}`)
}

func okSide(resp json.RawMessage) shadow.Side {
	return shadow.Side{Status: 200, Response: resp}
}

const (
	bashTest = `{"type":"tool_use","id":"x","name":"Bash","input":{"command":"go test ./..."}}`
	editFix  = `{"type":"tool_use","id":"y","name":"Edit","input":{"new_string":"a + b","old_string":"a + b - 1","file_path":"add.go"}}`
	done     = `{"type":"text","text":"Fixed."}`
)

func TestAnalyzeAgentSession(t *testing.T) {
	pairs := []shadow.Pair{
		// Step 0: both run the tests, as production did.
		{ID: "p0", SessionID: "s1", Protocol: gateway.ProtoAnthropic, Request: ccRequest(0), Control: okSide(ccResp(bashTest)), Candidate: okSide(ccResp(bashTest))},
		// Step 1 (after the FAIL output): control edits like production; the
		// candidate stops early.
		{ID: "p1", SessionID: "s1", Protocol: gateway.ProtoAnthropic, Request: ccRequest(1), Control: okSide(ccResp(editFix)), Candidate: okSide(ccResp(done))},
		// Step 2: control re-runs tests; the candidate calls a tool it was not
		// offered and an Edit missing a required argument.
		{ID: "p2", SessionID: "s1", Protocol: gateway.ProtoAnthropic, Request: ccRequest(2), Control: okSide(ccResp(bashTest)),
			Candidate: okSide(ccResp(`{"type":"tool_use","id":"z","name":"RunTests","input":{}},{"type":"tool_use","id":"w","name":"Edit","input":{"file_path":"a.go"}}`))},
		// A subagent conversation under the same session id: different prefix,
		// must never be taken as production's next action for s1's steps.
		{ID: "p3", SessionID: "s1", Protocol: gateway.ProtoAnthropic,
			Request: json.RawMessage(`{"model":"sonnet","tools":` + ccTools + `,"messages":[{"role":"user","content":"find callers of Add"},{"role":"assistant","content":[{"type":"tool_use","id":"q","name":"Read","input":{"file_path":"x.go"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"q","content":"..."}]}]}`),
			Control: okSide(ccResp(done)), Candidate: okSide(ccResp(done))},
		// An errored side is not a step.
		{ID: "p4", SessionID: "s2", Protocol: gateway.ProtoAnthropic, Request: ccRequest(0), Control: okSide(ccResp(bashTest)), Candidate: shadow.Side{Status: 529, Error: "overloaded"}},
	}
	r := AnalyzeAgent(pairs, 1)
	if r == nil {
		t.Fatal("no result")
	}
	if r.Steps != 4 || r.Sessions != 1 || r.MultiTurn != 3 {
		t.Fatalf("steps=%d sessions=%d multi=%d, want 4 1 3", r.Steps, r.Sessions, r.MultiTurn)
	}
	// Agreement: p0 and p3 agree, p1 and p2 do not.
	if r.ToolAgreement.Mean != 0.5 || r.ToolAgreement.N != 4 {
		t.Fatalf("tool agreement %+v, want 0.5 over 4", r.ToolAgreement)
	}
	// Edit arguments match despite key order.
	if !SameCalls(mustAction(t, editFix), mustAction(t, `{"type":"tool_use","name":"Edit","input":{"file_path":"add.go","old_string":"a + b - 1","new_string":"a + b"}}`)) {
		t.Fatal("argument key order changed equality")
	}
	// References: p0 -> Bash (from p1's history), p1 -> Edit (from p2's).
	// p2 is the last mirrored step and p3 has no later step: unreferenced.
	if r.Referenced != 2 {
		t.Fatalf("referenced %d, want 2", r.Referenced)
	}
	if r.Control.Fidelity.Mean != 1 || r.Candidate.Fidelity.Mean != 0.5 {
		t.Fatalf("fidelity ctl %v cand %v, want 1 and 0.5", r.Control.Fidelity.Mean, r.Candidate.Fidelity.Mean)
	}
	if r.FidelityDelta.Mean != -0.5 || r.FidelityDelta.Baseline != 1 {
		t.Fatalf("fidelity delta %+v", r.FidelityDelta)
	}
	// Production kept working at both referenced steps; the candidate stopped at one.
	if r.Candidate.PrematureStopRate != 0.5 || r.Control.PrematureStopRate != 0 {
		t.Fatalf("premature stop ctl %v cand %v", r.Control.PrematureStopRate, r.Candidate.PrematureStopRate)
	}
	if r.Candidate.InvalidToolRate != 0.25 || r.Candidate.SchemaErrorRate != 0.25 || r.Control.InvalidToolRate != 0 || r.Control.SchemaErrorRate != 0 {
		t.Fatalf("validity ctl %+v cand %+v", r.Control, r.Candidate)
	}
	if r.Diverged != 1 || r.FirstDivergence != 1 {
		t.Fatalf("diverged %v first %v, want 1 and 1", r.Diverged, r.FirstDivergence)
	}
	if len(r.ByDepth) != 2 || r.ByDepth[0].Steps != "0" || r.ByDepth[1].Steps != "1-4" || r.ByDepth[1].N != 3 {
		t.Fatalf("by depth %+v", r.ByDepth)
	}
	for _, x := range []Rate{r.ToolAgreement, r.ArgAgreement, r.Control.Fidelity, r.Candidate.Fidelity} {
		if x.CILo > x.Mean || x.CIHi < x.Mean || math.IsNaN(x.CILo) {
			t.Fatalf("CI does not cover the mean: %+v", x)
		}
	}
}

func mustAction(t *testing.T, blocks string) Action {
	t.Helper()
	a, ok := parseResponse(gateway.ProtoAnthropic, ccResp(blocks))
	if !ok {
		t.Fatalf("unparsed %s", blocks)
	}
	return a
}

func TestParseProtocols(t *testing.T) {
	tests := []struct {
		name, proto, req, resp string
		steps                  int
		want                   []Call
	}{
		{"codex responses", gateway.ProtoResponses,
			`{"model":"gpt","tools":[{"type":"function","name":"shell","parameters":{"required":["command"]}},{"type":"custom","name":"apply_patch"}],
			 "input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"fix"}]},
			          {"type":"reasoning","summary":[]},{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":[\"go\",\"test\"]}"},
			          {"type":"function_call_output","call_id":"c1","output":"FAIL"}]}`,
			`{"output":[{"type":"reasoning"},{"type":"custom_tool_call","name":"apply_patch","input":"*** Begin Patch"}]}`,
			1, []Call{{Name: "apply_patch", Input: "*** Begin Patch"}}},
		{"gemini", gateway.ProtoGemini,
			`{"tools":[{"functionDeclarations":[{"name":"run_shell_command","parameters":{"required":["command"]}}]}],
			 "contents":[{"role":"user","parts":[{"text":"fix"}]},{"role":"model","parts":[{"functionCall":{"name":"run_shell_command","args":{"command":"npm test"}}}]},{"role":"user","parts":[{"functionResponse":{"name":"run_shell_command","response":{"output":"1 failing"}}}]}]}`,
			`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"run_shell_command","args":{"command":"npm test -- -g add"}}}]}}]}`,
			1, []Call{{Name: "run_shell_command", Input: `{"command":"npm test -- -g add"}`}}},
		{"bedrock converse", gateway.ProtoBedrock,
			`{"toolConfig":{"tools":[{"toolSpec":{"name":"Bash","inputSchema":{"json":{"required":["command"]}}}}]},"messages":[{"role":"user","content":[{"text":"fix"}]}]}`,
			`{"output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"a","name":"Bash","input":{"command":"ls"}}}]}},"stopReason":"tool_use"}`,
			0, []Call{{Name: "Bash", Input: `{"command":"ls"}`}}},
		{"anthropic end turn", gateway.ProtoAnthropic,
			`{"messages":[{"role":"user","content":"hi"}]}`, `{"content":[{"type":"text","text":"hello"}]}`, 0, nil},
	}
	for _, tc := range tests {
		c, ok := parseRequest(tc.proto, []byte(tc.req))
		if !ok {
			t.Fatalf("%s: request unparsed", tc.name)
		}
		if c.steps() != tc.steps {
			t.Errorf("%s: steps %d, want %d", tc.name, c.steps(), tc.steps)
		}
		a, ok := parseResponse(tc.proto, []byte(tc.resp))
		if !ok {
			t.Fatalf("%s: response unparsed", tc.name)
		}
		if fmt.Sprint(a.Calls) != fmt.Sprint(tc.want) {
			t.Errorf("%s: calls %v, want %v", tc.name, a.Calls, tc.want)
		}
		if inv, sch := c.tools.validity(a); inv || sch {
			t.Errorf("%s: valid call flagged invalid=%v schema=%v", tc.name, inv, sch)
		}
	}
	// Codex reference: the next request's new model items are production's action.
	p0 := `{"model":"gpt","tools":[{"type":"function","name":"shell","parameters":{"required":["command"]}}],"input":[{"type":"message","role":"user","content":"fix"}]}`
	p1 := `{"model":"gpt","tools":[{"type":"function","name":"shell","parameters":{"required":["command"]}}],"input":[{"type":"message","role":"user","content":"fix"},{"type":"function_call","name":"shell","arguments":"{\"command\":[\"ls\"]}"},{"type":"function_call_output","output":"a.go"}]}`
	resp := `{"output":[{"type":"function_call","name":"shell","arguments":"{\"command\": [\"ls\"]}"}]}`
	r := AnalyzeAgent([]shadow.Pair{
		{ID: "a", SessionID: "c", Protocol: gateway.ProtoResponses, Request: json.RawMessage(p0), Control: okSide(json.RawMessage(resp)), Candidate: okSide(json.RawMessage(resp))},
		{ID: "b", SessionID: "c", Protocol: gateway.ProtoResponses, Request: json.RawMessage(p1), Control: okSide(json.RawMessage(resp)), Candidate: okSide(json.RawMessage(resp))},
	}, 1)
	if r.Referenced != 1 || r.Candidate.Fidelity.Mean != 1 || r.ArgAgreement.Mean != 1 {
		t.Fatalf("codex reference: %+v", r)
	}
	if AnalyzeAgent(nil, 1) != nil {
		t.Fatal("empty input should yield nil")
	}
}

// End to end through RunOnline and the exporter: the agent reading rides on
// the online result, judge CIs resample sessions, and the exported samples
// are per hashed session (raw session ids never leave the eval host).
func TestOnlineAgentExport(t *testing.T) {
	var src fakePairs
	for s := range 3 {
		for n := range 3 {
			ctl := []string{bashTest, editFix, bashTest}[n]
			cand := ctl
			if s == 2 && n == 1 {
				cand = done
			}
			src = append(src, shadow.Pair{ID: fmt.Sprintf("p%d%d", s, n), Experiment: "agentic", SessionID: fmt.Sprintf("raw-session-%d", s),
				Protocol: gateway.ProtoAnthropic, Request: ccRequest(n), Control: okSide(ccResp(ctl)), Candidate: okSide(ccResp(cand))})
		}
	}
	o := OnlineOptions{Judge: &Judge{LLM: &fakeLLM{reply: scoreByText}, Model: "judge-1"}, Rubric: testRubric(t), Seed: 3}
	rs, err := RunOnline(context.Background(), src, o)
	if err != nil {
		t.Fatal(err)
	}
	a := rs[0].Agent
	if a == nil || a.Steps != 9 || a.Sessions != 3 || a.Referenced != 6 || len(rs[0].AgentSteps) != 9 || len(rs[0].AgentPairIDs) != 9 {
		t.Fatalf("agent %+v", a)
	}
	if a.Candidate.Fidelity.Mean != 5.0/6 || a.Control.Fidelity.Mean != 1 {
		t.Fatalf("fidelity ctl %v cand %v", a.Control.Fidelity.Mean, a.Candidate.Fidelity.Mean)
	}
	if !strings.Contains(OnlineTable(rs), "TOOL AGREE") {
		t.Fatal("table lacks the step-level section")
	}
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { body, _ = io.ReadAll(r.Body) }))
	defer srv.Close()
	if err := (&OTLPExporter{URL: srv.URL}).Export(context.Background(), rs, time.Unix(0, 0), time.Unix(60, 0)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{MetricAgentFidelity, MetricAgentInvalidCall, MetricAgentToolAgreement, MetricAgentPrematureStop, SessionUnit("raw-session-0")} {
		if !strings.Contains(string(body), want) {
			t.Errorf("OTLP body missing %s", want)
		}
	}
	if strings.Contains(string(body), "raw-session") {
		t.Fatal("raw session id exported")
	}
	// A rerun with the history skips graded pairs for the judge but still
	// reads every step; nothing is exported twice.
	o.Skip, o.AgentSkip = map[string]bool{}, map[string]bool{}
	for _, id := range rs[0].PairIDs {
		o.Skip[id] = true
	}
	for _, id := range rs[0].AgentPairIDs {
		o.AgentSkip[id] = true
	}
	again, err := RunOnline(context.Background(), src, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("rerun produced %d results, want none (nothing new)", len(again))
	}
	// A step without a recovered reference waits AgentQuiet for its next step.
	o.Skip, o.AgentSkip = nil, nil
	o.Now = func() time.Time { return time.Unix(0, 0).Add(time.Minute) }
	for i := range src {
		src[i].Time = time.Unix(0, 0)
	}
	fresh, err := RunOnline(context.Background(), src, o)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(fresh[0].AgentSteps); n != 6 {
		t.Fatalf("fresh run exported %d steps, want the 6 referenced ones", n)
	}
}

func TestAgentEdgeCases(t *testing.T) {
	anth := func(id, sess string, req json.RawMessage, ctl, cand json.RawMessage) shadow.Pair {
		return shadow.Pair{ID: id, SessionID: sess, Protocol: gateway.ProtoAnthropic, Request: req, Control: okSide(ctl), Candidate: okSide(cand)}
	}
	trunc := json.RawMessage(`{"content":[{"type":"text","text":"I will now"}],"stop_reason":"max_tokens"}`)
	aux := json.RawMessage(`{"model":"sonnet","messages":[{"role":"user","content":"summarise this conversation"}]}`)
	r := AnalyzeAgent([]shadow.Pair{
		anth("a", "s", ccRequest(0), ccResp(bashTest), ccResp(bashTest)),
		anth("b", "s", ccRequest(0), ccResp(bashTest), ccResp(bashTest)), // retry: same bytes
		anth("c", "s", ccRequest(1), ccResp(editFix), trunc),             // truncated: excluded
		anth("d", "s", aux, ccResp(done), ccResp(done)),                  // compaction: auxiliary
	}, 1)
	if r.Steps != 1 || r.Retries != 1 || r.Truncated != 1 || r.Auxiliary != 1 {
		t.Fatalf("steps %d retries %d truncated %d aux %d, want 1 1 1 1", r.Steps, r.Retries, r.Truncated, r.Auxiliary)
	}
	// The truncated step still supplies step 0's reference.
	if r.Referenced != 1 {
		t.Fatalf("referenced %d, want 1", r.Referenced)
	}

	// Gemini MALFORMED_FUNCTION_CALL is an invalid call, not a stop.
	g, ok := parseResponse(gateway.ProtoGemini, []byte(`{"candidates":[{"content":{"role":"model"},"finishReason":"MALFORMED_FUNCTION_CALL"}]}`))
	if !ok || !g.Malformed || g.Stopped() {
		t.Fatalf("malformed gemini: %+v", g)
	}
	if _, sch := (toolSpec{}).validity(g); !sch {
		t.Fatal("malformed call not counted invalid")
	}
	if SameTools(g, Action{}) || !SameTools(g, g) {
		t.Fatal("malformed agreement")
	}

	// Hosted tools: remote MCP and versioned web search are offered by type.
	c, _ := parseRequest(gateway.ProtoResponses, []byte(`{"tools":[{"type":"mcp","server_label":"gh"},{"type":"web_search_preview"}],"input":"x"}`))
	a, _ := parseResponse(gateway.ProtoResponses, []byte(`{"output":[{"type":"mcp_call","name":"create_issue","arguments":"{}"},{"type":"web_search_call","action":{"query":"q"}}]}`))
	if inv, sch := c.tools.validity(a); inv || sch {
		t.Fatalf("hosted calls flagged invalid=%v schema=%v: %+v", inv, sch, a)
	}
	if inv, _ := c.tools.validity(Action{Calls: []Call{{Name: "file_search"}}}); !inv {
		t.Fatal("un-offered hosted tool accepted")
	}

	// Codex parallel calls: [fc A, out A, fc B, out B] is one step calling A and B.
	par, ok := parseRequest(gateway.ProtoResponses, []byte(`{"parallel_tool_calls":true,"tools":[{"type":"function","name":"shell","parameters":{}}],"input":[
		{"type":"message","role":"user","content":"x"},{"type":"reasoning"},
		{"type":"function_call","name":"shell","arguments":"{\"command\":[\"ls\"]}"},{"type":"function_call_output","output":"a"},
		{"type":"function_call","name":"shell","arguments":"{\"command\":[\"pwd\"]}"},{"type":"function_call_output","output":"b"},
		{"type":"reasoning"},{"type":"function_call","name":"shell","arguments":"{\"command\":[\"cat\"]}"},{"type":"function_call_output","output":"c"}]}`))
	if !ok || par.steps() != 2 || len(par.entries[1].action.Calls) != 2 {
		t.Fatalf("parallel grouping: steps %d, first step %+v", par.steps(), par.entries)
	}
}

func TestClipKeepsTail(t *testing.T) {
	b := []byte(strings.Repeat("a", judgeSideCap) + "LATEST TERMINAL OUTPUT")
	c := clip(b)
	if !strings.HasPrefix(c, "aaa") || !strings.HasSuffix(c, "LATEST TERMINAL OUTPUT") || len(c) > judgeSideCap+64 {
		t.Fatalf("clip lost head or tail (len %d)", len(c))
	}
}
