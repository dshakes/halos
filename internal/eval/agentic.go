package eval

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/shadow"
	"github.com/dshakes/halos/internal/stats"
)

// Step-level (teacher-forced) evaluation of agentic shadow pairs, ADR-0014.
//
// A shadow pair at step N holds the real conversation prefix: the developer's
// prompt, the actions production took and the real tool results (terminal
// output, file contents, test failures). Both arms answer that same prefix, so
// what is compared is each arm's NEXT ACTION given the real state, never a
// trajectory the candidate did not produce. Nothing is executed.
//
// When the session's following step was mirrored too, its request carries the
// action production actually took at step N. That is the reference: agreement
// of the control replay with it is the measurement noise floor (the same model
// re-sampled), and the candidate is read against that floor.

// Call is one tool invocation; Input is canonical JSON (sorted keys).
type Call struct {
	Name  string `json:"name"`
	Input string `json:"input,omitempty"`
}

// Action is one model step: the tool calls it made, in order. No calls means
// the model ended its turn (answered or gave up).
type Action struct {
	Calls []Call `json:"calls,omitempty"`
	// Malformed: the model tried to call a tool and produced something the
	// API rejected (Gemini MALFORMED_FUNCTION_CALL, Converse malformed_tool_use).
	// An invalid call, not a stop.
	Malformed bool `json:"malformed,omitempty"`
	// Truncated: the output token cap cut the step; it says nothing about the
	// model's decision, so the step is excluded.
	Truncated bool `json:"truncated,omitempty"`
}

// Stopped: the step ended the agent's turn.
func (a Action) Stopped() bool { return len(a.Calls) == 0 && !a.Malformed }

func (a Action) names() []string {
	n := make([]string, len(a.Calls))
	for i, c := range a.Calls {
		n[i] = c.Name
	}
	sort.Strings(n)
	return n
}

// SameTools: both stopped, or both called the same multiset of tools. A
// malformed step matches only another malformed step.
func SameTools(a, b Action) bool {
	if a.Malformed || b.Malformed {
		return a.Malformed && b.Malformed
	}
	return slices.Equal(a.names(), b.names())
}

// SameCalls: SameTools with identical arguments (order-insensitive).
func SameCalls(a, b Action) bool {
	if a.Malformed || b.Malformed {
		return a.Malformed && b.Malformed
	}
	key := func(x Action) []string {
		k := make([]string, len(x.Calls))
		for i, c := range x.Calls {
			k[i] = c.Name + "\x00" + c.Input
		}
		sort.Strings(k)
		return k
	}
	return slices.Equal(key(a), key(b))
}

// toolSpec is what a request offered: tool name -> required argument keys
// (nil for freeform/server tools whose input is not a JSON object schema).
type toolSpec map[string][]string

// entry is one conversation turn, normalised across wire protocols.
type entry struct {
	model  bool
	action Action // model turns only
	fp     string // fingerprint, cache markers stripped
}

// conv is one parsed request.
type conv struct {
	entries []entry
	tools   toolSpec
}

// prefixOf: c's history starts with every turn of p's.
func (c conv) prefixOf(p conv) bool {
	if len(c.entries) < len(p.entries) {
		return false
	}
	for i, e := range p.entries {
		if c.entries[i].model != e.model || c.entries[i].fp != e.fp {
			return false
		}
	}
	return true
}

// steps is how many model turns precede the request (0 = first turn).
func (c conv) steps() int {
	n := 0
	for _, e := range c.entries {
		if e.model {
			n++
		}
	}
	return n
}

// canon re-encodes JSON with sorted keys and no cache_control markers (Claude
// Code moves them between turns; they are not content).
func canon(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(bytes.TrimSpace(raw))
	}
	var strip func(any) any
	strip = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			delete(t, "cache_control")
			for k, x := range t {
				t[k] = strip(x)
			}
		case []any:
			for i, x := range t {
				t[i] = strip(x)
			}
		}
		return v
	}
	b, _ := json.Marshal(strip(v))
	return string(b)
}

// argCanon canonicalises tool arguments that may arrive as a JSON string
// (OpenAI function_call.arguments) or an object.
func argCanon(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if json.Valid([]byte(s)) {
			return canon(json.RawMessage(s))
		}
		return s // freeform input (custom tools)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	return canon(raw)
}

// block is the union of the content-block shapes we read: Anthropic
// (type/name/input), Bedrock Converse (toolUse) and Gemini (functionCall).
type block struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Input   json.RawMessage `json:"input"`
	ToolUse *struct {
		Name  string
		Input json.RawMessage
	} `json:"toolUse"`
	FunctionCall *struct {
		Name string
		Args json.RawMessage
	} `json:"functionCall"`
}

func blocksAction(bs []block) Action {
	var a Action
	for _, b := range bs {
		switch {
		case b.Type == "tool_use" || b.Type == "server_tool_use":
			a.Calls = append(a.Calls, Call{Name: b.Name, Input: argCanon(b.Input)})
		case b.ToolUse != nil:
			a.Calls = append(a.Calls, Call{Name: b.ToolUse.Name, Input: argCanon(b.ToolUse.Input)})
		case b.FunctionCall != nil:
			a.Calls = append(a.Calls, Call{Name: b.FunctionCall.Name, Input: argCanon(b.FunctionCall.Args)})
		}
	}
	return a
}

// contentBlocks reads a message content that is a string or a block list.
func contentBlocks(raw json.RawMessage) []block {
	var bs []block
	_ = json.Unmarshal(raw, &bs) // a plain string has no tool calls
	return bs
}

// respItem is one OpenAI Responses input/output item.
type respItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Input     json.RawMessage `json:"input"`
	Action    json.RawMessage `json:"action"`
}

func (it respItem) model() bool {
	switch it.Type {
	case "function_call", "custom_tool_call", "local_shell_call", "reasoning", "web_search_call", "file_search_call", "computer_call", "mcp_call":
		return true
	case "message", "":
		return it.Role == "assistant"
	}
	return false
}

func (it respItem) call() (Call, bool) {
	switch it.Type {
	case "function_call":
		return Call{Name: it.Name, Input: argCanon(it.Arguments)}, true
	case "custom_tool_call":
		return Call{Name: it.Name, Input: argCanon(it.Input)}, true
	case "mcp_call":
		// Remote MCP tools are offered as one {"type":"mcp"} entry; the prefix
		// keeps distinct MCP tools distinct and lets validity match the entry.
		return Call{Name: hostedMCP + it.Name, Input: argCanon(it.Arguments)}, true
	case "local_shell_call", "computer_call", "web_search_call", "file_search_call":
		return Call{Name: strings.TrimSuffix(it.Type, "_call"), Input: argCanon(it.Action)}, true
	}
	return Call{}, false
}

// hostedMCP prefixes calls to remote MCP tools the API runs itself.
const hostedMCP = "mcp:"

// hostedCalls maps a hosted call name to the tool types that offer it
// (versioned types such as web_search_preview_2025_03_11 match by prefix).
var hostedCalls = map[string][]string{
	"web_search":  {"web_search"},
	"file_search": {"file_search"},
	"computer":    {"computer"},
	"local_shell": {"local_shell"},
}

func itemsAction(items []respItem) Action {
	var a Action
	for _, it := range items {
		if c, ok := it.call(); ok {
			a.Calls = append(a.Calls, c)
		}
	}
	return a
}

// parseRequest normalises a request body into turns and offered tools.
func parseRequest(protocol string, body []byte) (conv, bool) {
	var r struct {
		Messages []json.RawMessage `json:"messages"`
		Contents []json.RawMessage `json:"contents"`
		Input    json.RawMessage   `json:"input"`
		Parallel bool              `json:"parallel_tool_calls"`
		Tools    []struct {
			Type        string `json:"type"`
			Name        string `json:"name"`
			InputSchema *struct {
				Required []string `json:"required"`
			} `json:"input_schema"`
			Parameters *struct {
				Required []string `json:"required"`
			} `json:"parameters"`
			FunctionDeclarations []struct {
				Name       string `json:"name"`
				Parameters *struct {
					Required []string `json:"required"`
				} `json:"parameters"`
				ParametersJSONSchema *struct {
					Required []string `json:"required"`
				} `json:"parametersJsonSchema"`
			} `json:"functionDeclarations"`
		} `json:"tools"`
		ToolConfig *struct {
			Tools []struct {
				ToolSpec *struct {
					Name        string `json:"name"`
					InputSchema struct {
						JSON struct {
							Required []string `json:"required"`
						} `json:"json"`
					} `json:"inputSchema"`
				} `json:"toolSpec"`
			} `json:"tools"`
		} `json:"toolConfig"`
	}
	if json.Unmarshal(body, &r) != nil {
		return conv{}, false
	}
	c := conv{tools: toolSpec{}}
	req := func(xs []string) []string {
		if xs == nil {
			return []string{}
		}
		return xs
	}
	for _, t := range r.Tools {
		switch {
		case t.InputSchema != nil:
			c.tools[t.Name] = req(t.InputSchema.Required)
		case t.Parameters != nil:
			c.tools[t.Name] = req(t.Parameters.Required)
		case len(t.FunctionDeclarations) > 0:
			for _, f := range t.FunctionDeclarations {
				switch {
				case f.Parameters != nil:
					c.tools[f.Name] = req(f.Parameters.Required)
				case f.ParametersJSONSchema != nil:
					c.tools[f.Name] = req(f.ParametersJSONSchema.Required)
				default:
					c.tools[f.Name] = []string{}
				}
			}
		case t.Name != "":
			c.tools[t.Name] = nil // freeform or server tool
		case t.Type != "":
			c.tools[t.Type] = nil // built-in (local_shell, web_search...)
		}
	}
	if r.ToolConfig != nil {
		for _, t := range r.ToolConfig.Tools {
			if t.ToolSpec != nil {
				c.tools[t.ToolSpec.Name] = req(t.ToolSpec.InputSchema.JSON.Required)
			}
		}
	}
	switch protocol {
	case gateway.ProtoAnthropic, gateway.ProtoBedrock:
		for _, m := range r.Messages {
			var msg struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			}
			if json.Unmarshal(m, &msg) != nil {
				return conv{}, false
			}
			e := entry{model: msg.Role == "assistant", fp: canon(m)}
			if e.model {
				e.action = blocksAction(contentBlocks(msg.Content))
			}
			c.entries = append(c.entries, e)
		}
	case gateway.ProtoGemini:
		for _, m := range r.Contents {
			var msg struct {
				Role  string  `json:"role"`
				Parts []block `json:"parts"`
			}
			if json.Unmarshal(m, &msg) != nil {
				return conv{}, false
			}
			e := entry{model: msg.Role == "model", fp: canon(m)}
			if e.model {
				e.action = blocksAction(msg.Parts)
			}
			c.entries = append(c.entries, e)
		}
	case gateway.ProtoResponses:
		var s string
		if json.Unmarshal(r.Input, &s) == nil {
			c.entries = []entry{{fp: canon(r.Input)}}
			break
		}
		var raws []json.RawMessage
		if json.Unmarshal(r.Input, &raws) != nil {
			return conv{}, false
		}
		// Consecutive model-produced items are one step. With parallel tool
		// calls, Codex stores each call's output right after it ([fc A, out A,
		// fc B, out B]): an output followed directly by another call (no
		// reasoning or message between, which a new model turn starts with)
		// stays inside the step. ponytail: a non-reasoning model that calls
		// sequentially looks the same; such steps merge (depth undercounts).
		items := make([]respItem, len(raws))
		for i, raw := range raws {
			if json.Unmarshal(raw, &items[i]) != nil {
				return conv{}, false
			}
		}
		var group []respItem
		var fp strings.Builder
		var held []string // outputs inside an open parallel step
		flush := func() {
			if group != nil {
				c.entries = append(c.entries, entry{model: true, action: itemsAction(group), fp: fp.String()})
				group = nil
				fp.Reset()
			}
			for _, h := range held {
				c.entries = append(c.entries, entry{fp: h})
			}
			held = nil
		}
		for i, it := range items {
			if it.model() {
				if group == nil {
					group = []respItem{}
				}
				group = append(group, it)
				fp.WriteString(canon(raws[i]))
				continue
			}
			if r.Parallel && group != nil && strings.HasSuffix(it.Type, "_output") && i+1 < len(items) {
				if _, isCall := items[i+1].call(); isCall {
					held = append(held, canon(raws[i]))
					continue
				}
			}
			flush()
			c.entries = append(c.entries, entry{fp: canon(raws[i])})
		}
		flush()
	default:
		return conv{}, false
	}
	return c, true
}

// parseResponse reads the action a model took from a non-streaming response.
func parseResponse(protocol string, body []byte) (Action, bool) {
	var r struct {
		Content    []block         `json:"content"`
		StopReason string          `json:"stop_reason"` // Anthropic
		Stop       string          `json:"stopReason"`  // Bedrock Converse
		Output     json.RawMessage `json:"output"`
		Status     string          `json:"status"` // Responses
		Incomplete *struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Candidates []struct {
			Content struct {
				Parts []block `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
	}
	if json.Unmarshal(body, &r) != nil {
		return Action{}, false
	}
	switch protocol {
	case gateway.ProtoAnthropic, gateway.ProtoBedrock:
		if r.Content != nil {
			a := blocksAction(r.Content)
			a.Truncated = r.StopReason == "max_tokens"
			return a, true
		}
		var cv struct {
			Message *struct {
				Content []block `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(r.Output, &cv) == nil && cv.Message != nil { // Bedrock Converse
			a := blocksAction(cv.Message.Content)
			a.Truncated = r.Stop == "max_tokens"
			a.Malformed = strings.HasPrefix(r.Stop, "malformed_")
			return a, true
		}
	case gateway.ProtoResponses:
		var items []respItem
		if json.Unmarshal(r.Output, &items) == nil && items != nil {
			a := itemsAction(items)
			a.Truncated = r.Status == "incomplete" && r.Incomplete != nil && r.Incomplete.Reason == "max_output_tokens"
			return a, true
		}
	case gateway.ProtoGemini:
		if len(r.Candidates) > 0 {
			c := r.Candidates[0]
			a := blocksAction(c.Content.Parts)
			a.Truncated = c.FinishReason == "MAX_TOKENS"
			a.Malformed = c.FinishReason == "MALFORMED_FUNCTION_CALL" || c.FinishReason == "UNEXPECTED_TOOL_CALL"
			return a, true
		}
	}
	return Action{}, false
}

// offers reports whether a hosted call (web search, MCP...) was offered.
func (t toolSpec) offers(call string) bool {
	if strings.HasPrefix(call, hostedMCP) {
		_, ok := t["mcp"]
		return ok
	}
	for _, typ := range hostedCalls[call] {
		for k := range t {
			if strings.HasPrefix(k, typ) {
				return true
			}
		}
	}
	return false
}

// validity checks an action against the tools the request offered. A
// malformed step is an invalid call.
func (t toolSpec) validity(a Action) (invalidTool, schemaError bool) {
	schemaError = a.Malformed
	for _, c := range a.Calls {
		req, ok := t[c.Name]
		if !ok {
			if !t.offers(c.Name) {
				invalidTool = true
			}
			continue
		}
		if req == nil {
			continue // freeform/server tool: no object schema to check
		}
		var args map[string]json.RawMessage
		if json.Unmarshal([]byte(c.Input), &args) != nil {
			schemaError = true
			continue
		}
		for _, k := range req {
			if _, ok := args[k]; !ok {
				schemaError = true
			}
		}
	}
	return invalidTool, schemaError
}

// Rate is a proportion with a session-clustered bootstrap CI.
type Rate struct {
	Mean float64 `json:"mean"`
	CILo float64 `json:"ciLo"`
	CIHi float64 `json:"ciHi"`
	N    int     `json:"n"`
}

// AgentArm is one arm's per-step behaviour.
type AgentArm struct {
	// ToolCallRate: share of steps that called at least one tool.
	ToolCallRate float64 `json:"toolCallRate"`
	// InvalidToolRate: steps calling a tool the request did not offer
	// (hallucinated tool names).
	InvalidToolRate float64 `json:"invalidToolRate"`
	// SchemaErrorRate: steps whose arguments miss a required field or are
	// not a JSON object.
	SchemaErrorRate float64 `json:"schemaErrorRate"`
	// InvalidCallRate: steps with either problem (what the exported
	// halo.eval.agent.invalid_call_rate samples per session).
	InvalidCallRate float64 `json:"invalidCallRate"`
	// PrematureStopRate: among referenced steps where production kept
	// working, the share where this arm ended its turn instead.
	PrematureStopRate float64 `json:"prematureStopRate"`
	// Fidelity: agreement (same tools) with the action production actually
	// took. The control's fidelity is the re-sampling noise floor.
	Fidelity Rate `json:"fidelity"`
}

// DepthBucket is tool agreement by conversation depth.
type DepthBucket struct {
	Steps         string  `json:"steps"` // e.g. "0", "1-4"
	N             int     `json:"n"`
	ToolAgreement float64 `json:"toolAgreement"`
}

// AgentResult is the step-level reading of one shadow experiment. Rates are
// step-weighted (every step counts once); the exported analysis samples are
// per session (see StepSample), a different estimand that weights sessions
// equally.
type AgentResult struct {
	Steps    int `json:"steps"`    // pairs whose both actions parsed
	Sessions int `json:"sessions"` // distinct sessions among them
	// MultiTurn: steps past the first turn (turns: all).
	MultiTurn int `json:"multiTurn"`
	// Excluded, not steps: Auxiliary requests that offer no tools (compaction
	// summaries, next-speaker checks: both arms just answer), Truncated steps
	// (an arm hit its output cap), Retries (byte-identical resends of a step).
	Auxiliary int `json:"auxiliary"`
	Truncated int `json:"truncated"`
	Retries   int `json:"retries"`
	// ToolAgreement / ArgAgreement: candidate vs control replay, same prefix.
	ToolAgreement Rate     `json:"toolAgreement"`
	ArgAgreement  Rate     `json:"argAgreement"`
	Control       AgentArm `json:"control"`
	Candidate     AgentArm `json:"candidate"`
	// Referenced: steps whose production action was recovered.
	Referenced int `json:"referenced"`
	// FidelityDelta: candidate - control fidelity, paired by step,
	// session-clustered CI. Below zero beyond the noise floor = regression.
	FidelityDelta MetricDelta `json:"fidelityDelta"`
	// Diverged: share of sessions where the candidate's action differed from
	// the control replay at some step; FirstDivergence is the mean step at
	// which that first happened (among diverged sessions).
	Diverged        float64       `json:"diverged"`
	FirstDivergence float64       `json:"firstDivergence"`
	ByDepth         []DepthBucket `json:"byDepth"`
	// PerStep are the analysis samples the exporter may send, one per step.
	PerStep []StepSample `json:"-"`
}

// StepSample is one step's per-arm reading. It is exported once (tracked by
// pair id in the history) under unit = hashed session, so the per-unit mean
// the analysis takes is a per-session mean over its steps, and a rerun never
// re-weights a session.
type StepSample struct {
	PairID, Session string
	Time            time.Time
	// HasRef: production's action was recovered; the fidelity fields are set
	// only then.
	HasRef                      bool
	ControlFidelity, CandFid    float64
	ControlInvalid, CandInvalid float64 // 1 when the arm's call was invalid
}

type agentStep struct {
	pair      shadow.Pair
	conv      conv
	ctl, cand Action
	ref       *Action
}

func cluster(p shadow.Pair) string {
	if p.SessionID != "" {
		return p.SessionID
	}
	return "pair:" + p.ID
}

// reference finds production's action at p's step: a later step of the same
// session whose history starts with all of p's turns followed by a model turn
// (subagent and compacted conversations share the session id but not the
// prefix, and are skipped).
func reference(p agentStep, session []agentStep) *Action {
	n := len(p.conv.entries)
	if n == 0 {
		return nil
	}
	var best *agentStep
	for i := range session {
		q := &session[i]
		e := q.conv.entries
		if len(e) <= n || !e[n].model || !q.conv.prefixOf(p.conv) {
			continue
		}
		if best == nil || len(e) < len(best.conv.entries) {
			best = q
		}
	}
	if best == nil {
		return nil
	}
	a := best.conv.entries[n].action
	return &a
}

func rate(x []float64, cl []string, seed uint64) Rate {
	if len(x) == 0 {
		return Rate{}
	}
	b, err := stats.ClusterBootstrapMean(x, cl, bootstrapIters, seed, bootstrapAlpha)
	if err != nil {
		return Rate{Mean: mean(x), N: len(x)}
	}
	return Rate{Mean: b.Mean, CILo: b.CILo, CIHi: b.CIHi, N: len(x)}
}

func mean(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range x {
		s += v
	}
	return s / float64(len(x))
}

var depthBuckets = []struct {
	label  string
	lo, hi int
}{{"0", 0, 0}, {"1-4", 1, 4}, {"5-19", 5, 19}, {"20+", 20, 1 << 30}}

// stepSet is the parsed steps of a pair set plus what was excluded.
type stepSet struct {
	steps                         []agentStep // ordered by session, depth, pair id
	auxiliary, retries, truncated int
}

// agentSteps parses every pair whose both sides answered into a step, with
// production's action recovered where it can be. Auxiliary requests (no
// tools offered), byte-identical retries and truncated steps are not steps:
// they are counted and excluded.
func agentSteps(pairs []shadow.Pair) stepSet {
	var r stepSet
	var sources []agentStep // every parsed step: reference candidates
	seen := map[string]bool{}
	for _, p := range pairs {
		if !usable(p.Control) || !usable(p.Candidate) {
			continue
		}
		c, ok := parseRequest(p.Protocol, p.Request)
		if !ok {
			continue
		}
		if len(c.tools) == 0 {
			r.auxiliary++
			continue
		}
		ca, ok1 := parseResponse(p.Protocol, p.Control.Response)
		ta, ok2 := parseResponse(p.Protocol, p.Candidate.Response)
		if !ok1 || !ok2 {
			continue
		}
		h := sha256.Sum256(p.Request)
		if key := cluster(p) + "\x00" + string(h[:]); seen[key] {
			r.retries++
			continue
		} else {
			seen[key] = true
		}
		sources = append(sources, agentStep{pair: p, conv: c, ctl: ca, cand: ta})
	}
	// Deterministic order: session, then depth, then id.
	sort.SliceStable(sources, func(i, j int) bool {
		ci, cj := cluster(sources[i].pair), cluster(sources[j].pair)
		if ci != cj {
			return ci < cj
		}
		if a, b := sources[i].conv.steps(), sources[j].conv.steps(); a != b {
			return a < b
		}
		return sources[i].pair.ID < sources[j].pair.ID
	})
	bySession := map[string][]agentStep{}
	for _, s := range sources {
		bySession[cluster(s.pair)] = append(bySession[cluster(s.pair)], s)
	}
	for _, s := range sources {
		if s.ctl.Truncated || s.cand.Truncated {
			r.truncated++
			continue
		}
		s.ref = reference(s, bySession[cluster(s.pair)])
		r.steps = append(r.steps, s)
	}
	return r
}

// AnalyzeAgent computes the step-level reading over pairs whose both sides
// answered. It returns nil when no pair's actions could be parsed.
func AnalyzeAgent(pairs []shadow.Pair, seed uint64) *AgentResult {
	set := agentSteps(pairs)
	steps := set.steps
	if len(steps) == 0 {
		return nil
	}
	r := &AgentResult{Steps: len(steps), Auxiliary: set.auxiliary, Retries: set.retries, Truncated: set.truncated}
	sessions := map[string]bool{}
	var tool, arg []float64
	var cls []string
	var refCl []string
	var ctlFid, candFid []float64
	// Per arm: [0] steps calling a tool, [1] invalid tool, [2] schema error,
	// [3] premature stops, [5] invalid call (tool or schema); ctlArm[4]
	// counts referenced steps where production kept working.
	var ctlArm, candArm [6]float64
	firstDiv := map[string]int{}
	depth := make([][2]float64, len(depthBuckets))
	for _, s := range steps {
		id := cluster(s.pair)
		sessions[id] = true
		d := s.conv.steps()
		if d > 0 {
			r.MultiTurn++
		}
		agree := SameTools(s.ctl, s.cand)
		tool, arg = append(tool, b2f(agree)), append(arg, b2f(SameCalls(s.ctl, s.cand)))
		cls = append(cls, id)
		if !agree {
			if f, seen := firstDiv[id]; !seen || d < f {
				firstDiv[id] = d
			}
		}
		for i, bk := range depthBuckets {
			if d >= bk.lo && d <= bk.hi {
				depth[i][0]++
				depth[i][1] += b2f(agree)
			}
		}
		ss := StepSample{PairID: s.pair.ID, Session: id, Time: s.pair.Time}
		for i, arm := range []struct {
			a   Action
			acc *[6]float64
		}{{s.ctl, &ctlArm}, {s.cand, &candArm}} {
			inv, sch := s.conv.tools.validity(arm.a)
			if i == 0 {
				ss.ControlInvalid = b2f(inv || sch)
			} else {
				ss.CandInvalid = b2f(inv || sch)
			}
			arm.acc[0] += b2f(len(arm.a.Calls) > 0)
			arm.acc[1] += b2f(inv)
			arm.acc[2] += b2f(sch)
			arm.acc[5] += b2f(inv || sch)
			if s.ref != nil && !s.ref.Stopped() {
				arm.acc[3] += b2f(arm.a.Stopped())
			}
		}
		if s.ref != nil {
			r.Referenced++
			refCl = append(refCl, id)
			cf, tf := b2f(SameTools(s.ctl, *s.ref)), b2f(SameTools(s.cand, *s.ref))
			ctlFid, candFid = append(ctlFid, cf), append(candFid, tf)
			ss.HasRef, ss.ControlFidelity, ss.CandFid = true, cf, tf
			if !s.ref.Stopped() {
				ctlArm[4]++
			}
		}
		r.PerStep = append(r.PerStep, ss)
	}
	r.Sessions = len(sessions)
	r.ToolAgreement, r.ArgAgreement = rate(tool, cls, seed), rate(arg, cls, seed)
	n := float64(len(steps))
	arm := func(a [6]float64, fid []float64) AgentArm {
		x := AgentArm{ToolCallRate: a[0] / n, InvalidToolRate: a[1] / n, SchemaErrorRate: a[2] / n, InvalidCallRate: a[5] / n, Fidelity: rate(fid, refCl, seed)}
		if ctlArm[4] > 0 {
			x.PrematureStopRate = a[3] / ctlArm[4]
		}
		return x
	}
	r.Control, r.Candidate = arm(ctlArm, ctlFid), arm(candArm, candFid)
	if len(ctlFid) > 0 {
		if b, err := stats.PairedClusterBootstrap(ctlFid, candFid, refCl, bootstrapIters, seed, bootstrapAlpha); err == nil {
			r.FidelityDelta = MetricDelta{Mean: b.Mean, CILo: b.CILo, CIHi: b.CIHi, Baseline: mean(ctlFid)}
		}
	}
	if len(firstDiv) > 0 {
		r.Diverged = float64(len(firstDiv)) / float64(len(sessions))
		for _, d := range firstDiv {
			r.FirstDivergence += float64(d) / float64(len(firstDiv))
		}
	}
	for i, bk := range depthBuckets {
		if depth[i][0] > 0 {
			r.ByDepth = append(r.ByDepth, DepthBucket{Steps: bk.label, N: int(depth[i][0]), ToolAgreement: depth[i][1] / depth[i][0]})
		}
	}
	return r
}
