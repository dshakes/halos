package mcpserver

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/promote"
)

// raw calls a tool and returns the whole result (errors included).
func raw(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

// envelopeOf decodes a result's structured content and requires non-empty
// next_steps whose entries each name a tool or a command, and a why.
func envelopeOf(t *testing.T, name string, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		t.Fatalf("%s: structured content is not an object (%s): %v", name, b, err)
	}
	steps, _ := m["next_steps"].([]any)
	if len(steps) == 0 {
		t.Fatalf("%s (isError %v): empty next_steps: %s", name, res.IsError, b)
	}
	for _, s := range steps {
		st, ok := s.(map[string]any)
		if !ok || st["why"] == nil || st["why"] == "" {
			t.Fatalf("%s: step without why: %v", name, s)
		}
	}
	if _, old := m["next"]; old {
		t.Fatalf("%s: deprecated key next is still present: %s", name, b)
	}
	return m
}

func stepTools(m map[string]any) []string {
	var out []string
	for _, s := range m["next_steps"].([]any) {
		if tl, _ := s.(map[string]any)["tool"].(string); tl != "" {
			out = append(out, tl)
		}
	}
	return out
}

// Every registered tool, with write tools and ClickHouse enabled so the whole
// registry is present, answers success AND error with next_steps. The tool
// list is read from the server, so a new tool is covered without editing this.
func TestEveryToolAnswersWithNextSteps(t *testing.T) {
	cs := connect(t, Options{PolicyDir: copyExample(t), AllowWrites: true, ClickHouse: &promote.ClickHouse{}, Onboard: fakeMachine()})
	lr, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lr.Tools) < 40 {
		t.Fatalf("only %d tools registered", len(lr.Tools))
	}
	mustSucceed := []string{"doctor", "detect_harnesses", "validate", "list_rings", "list_experiments", "harness_matrix", "status",
		"init_policy", "local_install", "local_proxy", "verify_harness", "plan", "render_preview", "whoami", "show_experiment"}
	succeeded := map[string]bool{}
	for _, tl := range lr.Tools {
		t.Run(tl.Name, func(t *testing.T) {
			// error: an unknown field fails argument validation on every tool.
			res := raw(t, cs, tl.Name, map[string]any{"no_such_field": 1})
			if !res.IsError {
				t.Fatalf("unknown field accepted")
			}
			m := envelopeOf(t, tl.Name, res)
			if e, _ := m["error"].(map[string]any); e == nil || e["message"] == "" || e["kind"] != "invalid_arguments" {
				t.Fatalf("error object: %v", m["error"])
			}
			// the retry step carries a complete valid example: call it.
			var ex map[string]any
			for _, s := range m["next_steps"].([]any) {
				if st := s.(map[string]any); st["tool"] == tl.Name {
					ex, _ = st["args"].(map[string]any)
				}
			}
			res = raw(t, cs, tl.Name, ex)
			envelopeOf(t, tl.Name, res) // success or error: both carry next_steps
			if !res.IsError {
				succeeded[tl.Name] = true
			}
		})
	}
	for _, n := range mustSucceed {
		if !succeeded[n] {
			t.Errorf("%s did not succeed with the example args its own error handed out", n)
		}
	}
}

// The error text is for humans and agents alike: it names the field, type,
// an example and the allowed values.
func TestArgumentErrorsAreActionable(t *testing.T) {
	cs := connect(t, Options{PolicyDir: copyExample(t), Onboard: fakeMachine()})
	res := raw(t, cs, "plan", nil)
	if !res.IsError {
		t.Fatal("plan {} succeeded")
	}
	m := envelopeOf(t, "plan", res)
	e := m["error"].(map[string]any)
	msg, _ := e["message"].(string)
	for _, want := range []string{`"ring" is required`, "type string", "example:", "ring0-harness-team", "ring1-canary"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	if e["field"] != "ring" || e["expected"] != "string" || len(e["allowed"].([]any)) < 3 {
		t.Errorf("structured error: %v", e)
	}
	if !slices.Contains(stepTools(m), "list_rings") {
		t.Errorf("no list_rings step: %v", m["next_steps"])
	}

	res = raw(t, cs, "render_preview", map[string]any{"ring": "ring1-canary", "os": 5})
	msg = res.Content[0].(*mcp.TextContent).Text
	if !res.IsError || !strings.Contains(msg, `"os" has the wrong type`) || !strings.Contains(msg, "darwin, linux, windows") {
		t.Errorf("wrong type: %s", msg)
	}
	res = raw(t, cs, "plan", map[string]any{"ring": "ring1-canary", "rnig": "x"})
	if msg = res.Content[0].(*mcp.TextContent).Text; !res.IsError || !strings.Contains(msg, `unknown field "rnig"`) || !strings.Contains(msg, "against") {
		t.Errorf("unknown field: %s", msg)
	}
}

// The advertised schemas carry the contract: next_steps on every output,
// onboard_company needs only org, and defaults and examples are visible.
func TestToolSchemasCarryExamplesDefaultsAndNextSteps(t *testing.T) {
	cs := connect(t, Options{PolicyDir: copyExample(t), Onboard: fakeMachine()})
	lr, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range lr.Tools {
		b, _ := json.Marshal(tl)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		out, _ := m["outputSchema"].(map[string]any)
		props, _ := out["properties"].(map[string]any)
		if _, ok := props["next_steps"]; out != nil && !ok {
			t.Errorf("%s: output schema lacks next_steps", tl.Name)
		}
		if _, ok := props["next"]; ok {
			t.Errorf("%s: output schema still has next", tl.Name)
		}
		if tl.Name != "onboard_company" {
			continue
		}
		in := m["inputSchema"].(map[string]any)
		var req []string
		for _, r := range in["required"].([]any) {
			req = append(req, r.(string))
		}
		if !slices.Equal(req, []string{"org"}) {
			t.Errorf("onboard_company required = %v, want [org]", req)
		}
		p := in["properties"].(map[string]any)
		if d := p["gateway_kind"].(map[string]any)["default"]; d != "halo-proxy" {
			t.Errorf("gateway_kind default = %v", d)
		}
		if ex := p["org"].(map[string]any)["examples"]; ex == nil {
			t.Errorf("org has no examples")
		}
	}
}
