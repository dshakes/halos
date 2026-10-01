package eval

import (
	"os"
	"path/filepath"
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
	if strings.Join(c.Args, " ") != "codex exec --json --skip-git-repo-check --sandbox workspace-write -m gpt-5 -" || c.Stdin != "p" {
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

// Codex tool errors from what the JSONL does emit (G6): non-zero exit codes,
// failed/declined statuses, and tool items that started but never completed
// (0.99's exec_command emits no completion when its sandbox cannot start).
func TestCodexToolErrors(t *testing.T) {
	for _, tc := range []struct {
		name          string
		out           string
		calls, errors int
	}{
		{"clean run", `{"type":"thread.started"}
{"type":"item.started","item":{"id":"i1","type":"command_execution","status":"in_progress"}}
{"type":"item.completed","item":{"id":"i1","type":"command_execution","exit_code":0,"status":"completed"}}
{"type":"item.completed","item":{"id":"i2","type":"agent_message","text":"done"}}`, 1, 0},
		{"non-zero exit", `{"type":"thread.started"}
{"type":"item.completed","item":{"id":"i1","type":"command_execution","exit_code":2,"status":"completed"}}`, 1, 1},
		{"failed and declined statuses", `{"type":"thread.started"}
{"type":"item.completed","item":{"id":"i1","type":"command_execution","status":"failed"}}
{"type":"item.completed","item":{"id":"i2","type":"command_execution","status":"declined"}}
{"type":"item.completed","item":{"id":"i3","type":"mcp_tool_call","status":"failed"}}
{"type":"item.completed","item":{"id":"i4","type":"mcp_tool_call","status":"completed"}}`, 4, 3},
		{"started, never completed (cut off by a timeout)", `{"type":"thread.started"}
{"type":"item.started","item":{"id":"c1","type":"command_execution","command":"go test ./...","status":"in_progress"}}
{"type":"item.started","item":{"id":"c2","type":"command_execution","command":"ls","status":"in_progress"}}
{"type":"item.completed","item":{"id":"m1","type":"agent_message","text":"I could not run commands"}}
{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`, 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := CodexDriver{}.Parse([]byte(tc.out))
			if err != nil || u.ToolCalls != tc.calls || u.ToolErrors != tc.errors {
				t.Fatalf("calls %d errors %d (want %d %d) err %v", u.ToolCalls, u.ToolErrors, tc.calls, tc.errors, err)
			}
		})
	}
}

// Real codex-cli 0.99.0 --json streams (uat-clis, testdata/codex).
func TestCodex099Transcripts(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "codex", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range []struct {
		file          string
		calls, errors int
	}{
		{"tool-success.jsonl", 1, 0},   // exit_code 0, status completed
		{"command-failed.jsonl", 1, 1}, // exit_code 1, status failed
		// Landlock denied: no command item at all (the one error item is a
		// config warning, not a tool), so the parser reports no tool activity
		// rather than inventing it; the sandbox preflight covers this case.
		{"sandbox-denied.jsonl", 0, 0},
	} {
		u, err := CodexDriver{}.Parse(read(tc.file))
		if err != nil || u.ToolCalls != tc.calls || u.ToolErrors != tc.errors || u.Failed || u.Turns != 1 || u.Tokens != 38 {
			t.Errorf("%s: %+v %v", tc.file, u, err)
		}
	}
	// The preflight's signal is what the model saw for the denied call.
	if fco := string(read("sandbox-denied.function_call_output.txt")); !strings.Contains(fco, "exit_code: 101") || !strings.Contains(fco, "Sandbox(LandlockRestrict)") {
		t.Fatalf("function_call_output fixture changed:\n%s", fco)
	}
}
