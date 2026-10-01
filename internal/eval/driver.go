package eval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Command is an argv plus optional stdin, run inside the environment.
type Command struct {
	Args  []string
	Stdin string
}

// Usage is what a driver extracts from a headless run's output.
type Usage struct {
	CostUSD    float64
	Turns      int
	DurationMs int64
	Tokens     int64 // input + output (+ cache) tokens
	ToolErrors int
	ToolCalls  int
	Failed     bool   // harness reported the run as failed/errored
	Error      string // message when Failed
}

// Driver knows how to run one harness headlessly and read its output. Unknown
// output fields are always tolerated.
type Driver interface {
	Name() string
	Command(t *Task, v Variant) Command
	// SettingsPath is where the rendered managed settings must appear inside
	// the environment for the CLI to pick them up.
	SettingsPath() string
	Parse(stdout []byte) (Usage, error)
}

// Drivers returns the built-in drivers keyed by Variant.Harness.
func Drivers() map[string]Driver {
	return map[string]Driver{"claude": ClaudeDriver{}, "codex": CodexDriver{}, "gemini": GeminiDriver{}}
}

// jsonLines calls fn for each line that parses as a JSON object; other lines
// (progress noise, banners) are skipped.
func jsonLines(b []byte, fn func(map[string]any)) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			fn(m)
		}
	}
}

func num(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }
func obj(m map[string]any, k string) map[string]any {
	o, _ := m[k].(map[string]any)
	return o
}
func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// ClaudeDriver runs `claude -p` with stream-json output.
type ClaudeDriver struct{}

func (ClaudeDriver) Name() string { return "claude" }

// SettingsPath is Claude Code's Linux managed-settings location.
func (ClaudeDriver) SettingsPath() string { return "/etc/claude-code/managed-settings.json" }

// Command: UNVERIFIED against a real CLI: --restricted is taken from the
// design notes, and stream-json in print mode is believed to require --verbose.
func (ClaudeDriver) Command(t *Task, v Variant) Command {
	turns := t.MaxTurns
	if turns == 0 {
		turns = 30
	}
	args := []string{"claude", "-p", t.Prompt, "--restricted", "--output-format", "stream-json", "--verbose",
		"--max-turns", strconv.Itoa(turns), "--permission-mode", "acceptEdits"}
	if t.BudgetUSD > 0 {
		args = append(args, "--max-budget-usd", strconv.FormatFloat(t.BudgetUSD, 'f', -1, 64))
	}
	if v.Model != "" {
		args = append(args, "--model", v.Model)
	}
	return Command{Args: args}
}

// Parse reads the final `result` message of the stream.
func (ClaudeDriver) Parse(out []byte) (Usage, error) {
	var u Usage
	found := false
	jsonLines(out, func(m map[string]any) {
		switch str(m, "type") {
		case "assistant": // each tool_use block is one tool call
			content, _ := obj(m, "message")["content"].([]any)
			for _, c := range content {
				if cm, ok := c.(map[string]any); ok && str(cm, "type") == "tool_use" {
					u.ToolCalls++
				}
			}
		case "user": // tool results flagged is_error
			content, _ := obj(m, "message")["content"].([]any)
			for _, c := range content {
				if cm, ok := c.(map[string]any); ok && str(cm, "type") == "tool_result" && cm["is_error"] == true {
					u.ToolErrors++
				}
			}
		case "result":
			found = true
			u.CostUSD = num(m, "total_cost_usd")
			u.Turns = int(num(m, "num_turns"))
			u.DurationMs = int64(num(m, "duration_ms"))
			us := obj(m, "usage")
			u.Tokens = int64(num(us, "input_tokens") + num(us, "output_tokens") +
				num(us, "cache_read_input_tokens") + num(us, "cache_creation_input_tokens"))
			if m["is_error"] == true || (str(m, "subtype") != "" && str(m, "subtype") != "success") {
				u.Failed, u.Error = true, str(m, "subtype")
			}
		}
	})
	if !found {
		return u, fmt.Errorf("claude: no result message in stream output")
	}
	return u, nil
}

// CodexDriver runs `codex exec --json` with the prompt on stdin.
type CodexDriver struct{}

func (CodexDriver) Name() string { return "codex" }

// SettingsPath is the verified Unix managed_config.toml location (internal/harness/FACTS.md).
func (CodexDriver) SettingsPath() string { return "/etc/codex/managed_config.toml" }

func (CodexDriver) Command(t *Task, v Variant) Command {
	args := []string{"codex", "exec", "--json", "--sandbox", "workspace-write"}
	if v.Model != "" {
		args = append(args, "-m", v.Model)
	}
	return Command{Args: append(args, "-"), Stdin: t.Prompt}
}

// Parse reads JSONL events. Codex reports no cost, so CostUSD stays 0.
// Event shapes verified against codex-rs/exec/src/exec_events.rs (FACTS.md).
func (CodexDriver) Parse(out []byte) (Usage, error) {
	var u Usage
	seen := false
	jsonLines(out, func(m map[string]any) {
		switch str(m, "type") {
		case "thread.started":
			seen = true
		case "turn.completed":
			seen = true
			u.Turns++
			us := obj(m, "usage")
			u.Tokens += int64(num(us, "input_tokens") + num(us, "output_tokens"))
		case "turn.failed", "error":
			seen = true
			u.Failed = true
			if msg := str(obj(m, "error"), "message"); msg != "" {
				u.Error = msg
			} else if msg := str(m, "message"); msg != "" {
				u.Error = msg
			}
		case "item.completed":
			it := obj(m, "item")
			switch str(it, "type") {
			case "command_execution", "file_change", "mcp_tool_call", "web_search":
				u.ToolCalls++
			}
			if str(it, "type") == "command_execution" && num(it, "exit_code") != 0 {
				u.ToolErrors++
			}
		}
	})
	if !seen {
		return u, fmt.Errorf("codex: no recognised events in output")
	}
	return u, nil
}

// GeminiDriver runs `gemini -p ... --output-format json`.
// Flags, settings path and the JSON stats shape are verified against the docs and
// source (internal/harness/FACTS.md); not run against a real CLI.
type GeminiDriver struct{}

func (GeminiDriver) Name() string { return "gemini" }

func (GeminiDriver) SettingsPath() string { return "/etc/gemini-cli/settings.json" }

func (GeminiDriver) Command(t *Task, v Variant) Command {
	args := []string{"gemini", "-p", t.Prompt, "--output-format", "json"}
	if v.Model != "" {
		args = append(args, "-m", v.Model)
	}
	return Command{Args: args}
}

func (GeminiDriver) Parse(out []byte) (Usage, error) {
	var u Usage
	var doc map[string]any
	// The output is one JSON document, possibly preceded by log noise.
	if i := bytes.IndexByte(out, '{'); i >= 0 {
		_ = json.Unmarshal(out[i:], &doc)
	}
	if doc == nil {
		return u, fmt.Errorf("gemini: no JSON document in output")
	}
	stats := obj(doc, "stats")
	for _, mv := range obj(stats, "models") {
		if mm, ok := mv.(map[string]any); ok {
			u.Tokens += int64(num(obj(mm, "tokens"), "total"))
		}
	}
	tools := obj(stats, "tools")
	u.ToolErrors = int(num(tools, "totalFail"))
	u.ToolCalls = int(num(tools, "totalCalls"))
	if e := obj(doc, "error"); e != nil {
		u.Failed, u.Error = true, str(e, "message")
	}
	return u, nil
}
