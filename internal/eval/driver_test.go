package eval

import (
	"strings"
	"testing"
)

func TestClaudeDriver(t *testing.T) {
	task := &Task{Prompt: "fix it", BudgetUSD: 0.5}
	got := strings.Join(ClaudeDriver{}.Command(task, Variant{Model: "sonnet"}).Args, " ")
	for _, w := range []string{"claude -p fix it", "--restricted", "--output-format stream-json", "--max-budget-usd 0.5", "--max-turns 30", "--model sonnet", "--permission-mode acceptEdits"} {
		if !strings.Contains(got, w) {
			t.Errorf("command %q missing %q", got, w)
		}
	}
	out := `banner noise
{"type":"system","subtype":"init","future_field":1}
{"type":"assistant","message":{"content":[{"type":"text","text":"hi"},{"type":"tool_use","name":"Bash"},{"type":"tool_use","name":"Edit"}]}}
{"type":"user","message":{"content":[{"type":"tool_result","is_error":true},{"type":"tool_result"}]}}
{"type":"result","subtype":"success","is_error":false,"total_cost_usd":0.42,"num_turns":7,"duration_ms":9000,"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100,"new_thing":9}}
`
	u, err := ClaudeDriver{}.Parse([]byte(out))
	if err != nil || u.CostUSD != 0.42 || u.Turns != 7 || u.DurationMs != 9000 || u.Tokens != 115 || u.ToolErrors != 1 || u.ToolCalls != 2 || u.Failed {
		t.Fatalf("got %+v err %v", u, err)
	}
	u, _ = ClaudeDriver{}.Parse([]byte(`{"type":"result","subtype":"error_max_turns","total_cost_usd":1}`))
	if !u.Failed || u.Error != "error_max_turns" {
		t.Fatalf("got %+v", u)
	}
	if _, err := (ClaudeDriver{}).Parse([]byte("nothing")); err == nil {
		t.Fatal("want error without result message")
	}
}

func TestCodexDriver(t *testing.T) {
	c := CodexDriver{}.Command(&Task{Prompt: "p"}, Variant{Model: "gpt-5"})
	if strings.Join(c.Args, " ") != "codex exec --json --sandbox workspace-write -m gpt-5 -" || c.Stdin != "p" {
		t.Fatalf("got %+v", c)
	}
	out := `{"type":"thread.started","thread_id":"x"}
{"type":"item.completed","item":{"type":"command_execution","exit_code":1}}
{"type":"item.completed","item":{"type":"file_change"}}
{"type":"item.completed","item":{"type":"agent_message"}}
{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":5,"output_tokens":2}}
{"type":"turn.failed","error":{"message":"boom"}}
`
	u, err := CodexDriver{}.Parse([]byte(out))
	if err != nil || u.Turns != 1 || u.Tokens != 12 || u.ToolErrors != 1 || u.ToolCalls != 2 || !u.Failed || u.Error != "boom" {
		t.Fatalf("got %+v err %v", u, err)
	}
	if _, err := (CodexDriver{}).Parse([]byte("{}")); err == nil {
		t.Fatal("want error without events")
	}
}

func TestGeminiDriver(t *testing.T) {
	out := `log noise
{"response":"ok","stats":{"models":{"m":{"tokens":{"total":50}}},"tools":{"totalCalls":3,"totalFail":1}}}`
	u, err := GeminiDriver{}.Parse([]byte(out))
	if err != nil || u.Tokens != 50 || u.ToolErrors != 1 || u.ToolCalls != 3 || u.Failed {
		t.Fatalf("got %+v err %v", u, err)
	}
	if _, err := (GeminiDriver{}).Parse([]byte("nope")); err == nil {
		t.Fatal("want error without JSON")
	}
}
