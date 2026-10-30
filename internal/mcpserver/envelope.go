package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The uniform response envelope. Every tool answers with next_steps, success
// or error, and this file is the one place that guarantees it: a receiving
// middleware around tools/call that
//
//   - coerces forgiving argument shapes (a string where an array is expected)
//     and turns argument problems into errors that name the field, its type,
//     an example and the allowed values, before the SDK's bare schema text;
//   - normalizes whatever next_steps / next a handler produced (strings) into
//     ordered {tool|command, why, args} steps and appends the standard flow;
//   - wraps every error with a kind, the message and recovery steps.
//
// Around tools/list it adds examples, defaults and the next_steps property to
// the advertised schemas so the contract is visible without reading docs.

// step is one entry of next_steps: a tool call or a human command, and why.
type step struct {
	Tool    string         `json:"tool,omitempty"`
	Command string         `json:"command,omitempty"`
	Why     string         `json:"why"`
	Args    map[string]any `json:"args,omitempty"`
}

// errInfo is the structured half of an error result.
type errInfo struct {
	Kind     string   `json:"kind"`
	Message  string   `json:"message"`
	Field    string   `json:"field,omitempty"`
	Expected string   `json:"expected,omitempty"`
	Example  any      `json:"example,omitempty"`
	Allowed  []string `json:"allowed,omitempty"`
}

// argProblem is one thing wrong with a call's arguments.
type argProblem struct {
	Field    string
	Problem  string // missing | unknown | type
	Expected string
	Example  any
	Allowed  []string
}

type mwState struct {
	mu      sync.Mutex
	schemas map[string]*mcp.Tool // raw tool as registered, by name
}

func (s *srv) addEnvelope(m *mcp.Server) { m.AddReceivingMiddleware(s.envelope) }

func (s *srv) envelope(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "tools/list":
			res, err := next(ctx, method, req)
			if lr, ok := res.(*mcp.ListToolsResult); ok && err == nil {
				return s.decorateList(lr), nil
			}
			return res, err
		case "tools/call":
			if cr, ok := req.(*mcp.CallToolRequest); ok && cr.Params != nil {
				return s.callTool(ctx, next, method, cr)
			}
		}
		return next(ctx, method, req)
	}
}

func (s *srv) callTool(ctx context.Context, next mcp.MethodHandler, method string, req *mcp.CallToolRequest) (mcp.Result, error) {
	name := req.Params.Name
	args := map[string]any{}
	if len(req.Params.Arguments) > 0 {
		dec := json.NewDecoder(bytes.NewReader(req.Params.Arguments))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			return s.errorResult(name, nil, errInfo{Kind: "invalid_arguments",
				Message: fmt.Sprintf("arguments of %s must be a JSON object, e.g. %s", name, exampleJSON(s.exampleArgs(name, nil)))}), nil
		}
	}
	if args == nil {
		args = map[string]any{} // arguments: null
	}
	tool := s.rawTool(ctx, next, req)
	var sch *jsonschema.Schema
	if tool != nil {
		sch = asSchema(tool.InputSchema)
	}
	if sch != nil {
		if coerce(sch, args) {
			if b, err := json.Marshal(args); err == nil {
				req.Params.Arguments = b
			}
		}
		if ps := s.checkArgs(name, sch, args); len(ps) > 0 {
			return s.errorResult(name, args, s.argError(name, ps)), nil
		}
	}
	res, err := next(ctx, method, req)
	if err != nil {
		return res, err
	}
	cr, ok := res.(*mcp.CallToolResult)
	if !ok || cr == nil {
		return res, err
	}
	if cr.IsError {
		info := classify(name, textOf(cr))
		if strings.HasPrefix(info.Message, "validating ") { // the SDK's own schema text: rewrite it
			info = errInfo{Kind: "invalid_arguments", Message: fmt.Sprintf("invalid arguments for %s: %s. Example: %s",
				name, strings.TrimPrefix(info.Message, "validating \"arguments\": "), exampleJSON(s.exampleArgs(name, sch)))}
		}
		return s.errorResult(name, args, info), nil
	}
	s.decorateSuccess(name, args, cr)
	return cr, nil
}

// rawTool returns the tool as registered, loading the registry through the
// inner tools/list on first use.
func (s *srv) rawTool(ctx context.Context, next mcp.MethodHandler, req *mcp.CallToolRequest) *mcp.Tool {
	s.mw.mu.Lock()
	defer s.mw.mu.Unlock()
	if t, ok := s.mw.schemas[req.Params.Name]; ok {
		return t
	}
	s.mw.schemas = map[string]*mcp.Tool{}
	lr := &mcp.ListToolsRequest{Session: req.Session, Params: &mcp.ListToolsParams{}}
	for {
		res, err := next(ctx, "tools/list", lr)
		l, ok := res.(*mcp.ListToolsResult)
		if err != nil || !ok {
			return nil
		}
		for _, t := range l.Tools {
			s.mw.schemas[t.Name] = t
		}
		if l.NextCursor == "" {
			break
		}
		lr = &mcp.ListToolsRequest{Session: req.Session, Params: &mcp.ListToolsParams{Cursor: l.NextCursor}}
	}
	return s.mw.schemas[req.Params.Name]
}

func asSchema(v any) *jsonschema.Schema {
	switch x := v.(type) {
	case nil:
		return nil
	case *jsonschema.Schema:
		return x
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var sc jsonschema.Schema
	if json.Unmarshal(b, &sc) != nil {
		return nil
	}
	return &sc
}

func cloneSchema(sc *jsonschema.Schema) *jsonschema.Schema {
	b, err := json.Marshal(sc)
	if err != nil {
		return sc
	}
	var c jsonschema.Schema
	if json.Unmarshal(b, &c) != nil {
		return sc
	}
	return &c
}

func textOf(r *mcp.CallToolResult) string {
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			return t.Text
		}
	}
	return ""
}

// ---- arguments ----

// coerce rewrites unambiguous shortcuts in place: "a,b" or "a" for an array,
// ["name@ver", ...] or "name@ver,..." for a string map, "true" for a boolean.
func coerce(sch *jsonschema.Schema, args map[string]any) bool {
	changed := false
	for k, v := range args {
		p := sch.Properties[k]
		if p == nil {
			continue
		}
		switch {
		case schemaIs(p, "array"):
			if str, ok := v.(string); ok {
				args[k], changed = splitList(str), true
			}
		case schemaIs(p, "object") && p.AdditionalProperties != nil && p.AdditionalProperties.Type == "string":
			sep := "@"
			if k == "models" {
				sep = "="
			}
			var items []string
			switch x := v.(type) {
			case string:
				for _, e := range splitList(x) {
					items = append(items, e.(string))
				}
			case []any:
				for _, e := range x {
					if es, ok := e.(string); ok {
						items = append(items, es)
					}
				}
				if len(items) != len(x) {
					continue
				}
			default:
				continue
			}
			mp := map[string]any{}
			for _, it := range items {
				n, ver, _ := strings.Cut(it, sep)
				if n == "" {
					continue
				}
				if ver == "" && k == "tools" {
					ver = fallbackVersion(n)
				}
				mp[n] = ver
			}
			args[k], changed = mp, true
		case schemaIs(p, "boolean"):
			if str, ok := v.(string); ok && (str == "true" || str == "false") {
				args[k], changed = str == "true", true
			}
		}
	}
	return changed
}

func splitList(s string) []any {
	out := []any{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// schemaIs reports whether sc admits the JSON type t (ignoring null).
func schemaIs(sc *jsonschema.Schema, t string) bool {
	if sc.Type == t {
		return true
	}
	for _, x := range sc.Types {
		if x == t {
			return true
		}
	}
	return false
}

func typeName(sc *jsonschema.Schema) string {
	ts := sc.Types
	if sc.Type != "" {
		ts = []string{sc.Type}
	}
	var out []string
	for _, t := range ts {
		if t != "null" {
			out = append(out, t)
		}
	}
	switch {
	case len(out) == 0:
		return "value"
	case out[0] == "array" && sc.Items != nil && sc.Items.Type != "":
		return "array of " + sc.Items.Type
	case out[0] == "object" && sc.AdditionalProperties != nil && sc.AdditionalProperties.Type != "":
		return "object of string to " + sc.AdditionalProperties.Type
	}
	return strings.Join(out, " or ")
}

func typeMatches(sc *jsonschema.Schema, v any) bool {
	if sc.Type == "" && len(sc.Types) == 0 {
		return true
	}
	if v == nil {
		return true // an explicit null is the SDK's call
	}
	switch x := v.(type) {
	case string:
		return schemaIs(sc, "string")
	case bool:
		return schemaIs(sc, "boolean")
	case json.Number:
		if schemaIs(sc, "number") {
			return true
		}
		_, err := x.Int64()
		return schemaIs(sc, "integer") && err == nil
	case []any:
		return schemaIs(sc, "array")
	case map[string]any:
		return schemaIs(sc, "object")
	}
	return true
}

func (s *srv) checkArgs(tool string, sch *jsonschema.Schema, args map[string]any) []argProblem {
	var ps []argProblem
	mk := func(field, problem string, p *jsonschema.Schema) argProblem {
		ap := argProblem{Field: field, Problem: problem, Example: s.fieldExample(tool, field, p), Allowed: s.allowed(tool, field, p)}
		if p != nil {
			ap.Expected = typeName(p)
		}
		return ap
	}
	req := append([]string(nil), sch.Required...)
	for _, r := range extraRequired[tool] {
		if !contains(req, r) {
			req = append(req, r)
		}
	}
	for _, r := range req {
		if v, ok := args[r]; !ok || v == nil {
			ps = append(ps, mk(r, "missing", sch.Properties[r]))
		}
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	closed := sch.AdditionalProperties != nil && sch.AdditionalProperties.Not != nil
	for _, k := range keys {
		p := sch.Properties[k]
		switch {
		case p == nil && closed:
			ap := argProblem{Field: k, Problem: "unknown"}
			ap.Allowed = propNames(sch)
			ps = append(ps, ap)
		case p != nil && !typeMatches(p, args[k]):
			ps = append(ps, mk(k, "type", p))
		}
	}
	return ps
}

func propNames(sch *jsonschema.Schema) []string {
	var n []string
	for k := range sch.Properties {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (s *srv) argError(tool string, ps []argProblem) errInfo {
	var parts []string
	for _, p := range ps {
		switch p.Problem {
		case "missing":
			parts = append(parts, fmt.Sprintf("%q is required%s", p.Field, describeField(p)))
		case "unknown":
			parts = append(parts, fmt.Sprintf("unknown field %q (fields of %s: %s)", p.Field, tool, strings.Join(p.Allowed, ", ")))
		default:
			parts = append(parts, fmt.Sprintf("%q has the wrong type%s", p.Field, describeField(p)))
		}
	}
	first := ps[0]
	info := errInfo{Kind: "invalid_arguments", Field: first.Field, Expected: first.Expected, Example: first.Example}
	if first.Problem != "unknown" {
		info.Allowed = first.Allowed
	}
	info.Message = fmt.Sprintf("invalid arguments for %s: %s", tool, strings.Join(parts, "; "))
	return info
}

func describeField(p argProblem) string {
	var b []string
	if p.Expected != "" {
		b = append(b, "type "+p.Expected)
	}
	if len(p.Allowed) > 0 {
		b = append(b, "one of: "+strings.Join(p.Allowed, ", "))
	}
	if p.Example != nil {
		b = append(b, "example: "+exampleJSON(p.Example))
	}
	if len(b) == 0 {
		return ""
	}
	return " (" + strings.Join(b, "; ") + ")"
}

func exampleJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// ---- results ----

func (s *srv) errorResult(tool string, args map[string]any, info errInfo) *mcp.CallToolResult {
	steps := s.errorSteps(tool, args, info)
	env := map[string]any{"error": info, "next_steps": steps}
	b, _ := json.Marshal(env)
	text := info.Message
	if len(steps) > 0 {
		text += "\nnext_steps: " + stepsText(steps)
	}
	return &mcp.CallToolResult{IsError: true, StructuredContent: json.RawMessage(b),
		Content: []mcp.Content{&mcp.TextContent{Text: text}, &mcp.TextContent{Text: string(b)}}}
}

func stepsText(steps []step) string {
	var parts []string
	for i, st := range steps {
		what := st.Command
		if st.Tool != "" {
			what = st.Tool
			if len(st.Args) > 0 {
				what += " " + exampleJSON(st.Args)
			}
		}
		parts = append(parts, fmt.Sprintf("%d. %s (%s)", i+1, what, st.Why))
	}
	return strings.Join(parts, " ")
}

// classify names the error kind from the handler's message.
func classify(tool, msg string) errInfo {
	k := "error"
	switch {
	case strings.Contains(msg, "writes are disabled on this server"):
		k = "writes_disabled"
	case strings.HasPrefix(msg, "load policy ") || strings.Contains(msg, "policy has validation errors"):
		k = "policy_invalid"
	case strings.HasPrefix(msg, "validating "), strings.Contains(msg, "is required"), strings.Contains(msg, "unknown ring"),
		strings.Contains(msg, "unknown experiment"), strings.Contains(msg, "unknown rollout"):
		k = "invalid_arguments"
	case strings.Contains(msg, "refusing to overwrite"):
		k = "conflict"
	case strings.Contains(msg, "not configured"), strings.Contains(msg, "HALO_SESSION"), strings.Contains(msg, "--server"):
		k = "not_configured"
	}
	return errInfo{Kind: k, Message: msg}
}

func (s *srv) errorSteps(tool string, args map[string]any, info errInfo) []step {
	var out []step
	retry := func(why string) {
		out = append(out, step{Tool: tool, Why: why, Args: s.exampleArgs(tool, nil)})
	}
	switch info.Kind {
	case "invalid_arguments":
		if info.Field == "ring" || strings.Contains(info.Message, "unknown ring") {
			out = append(out, step{Tool: "list_rings", Why: "the ring names this policy defines"})
		}
		if strings.Contains(info.Message, "unknown experiment") || info.Field == "experiment" {
			out = append(out, step{Tool: "list_experiments", Why: "the experiment names this policy defines"})
		}
		retry("call again with the field fixed; args is a complete valid example")
	case "writes_disabled":
		if cmd := backticked(info.Message, "halo "); cmd != "" {
			out = append(out, step{Command: cmd, Why: "a human runs this; this server is read-only"})
		}
		dry := s.exampleArgs(tool, nil)
		dry["dry_run"] = true
		out = append(out, step{Tool: tool, Why: "the dry run needs no write access; show its result to the human", Args: dry})
	case "policy_invalid":
		out = append(out, step{Tool: "validate", Why: "lists every policy issue with its path"},
			step{Tool: "init_policy", Why: "no halos.yaml yet? a dry run shows the one to create", Args: map[string]any{"org": "acme", "dry_run": true}})
	case "conflict":
		out = append(out, step{Tool: "validate", Why: "the policy dir already holds a policy; check it instead of generating over it"},
			step{Command: "halo mcp serve --policy-dir ./new-policy --allow-writes", Why: "a human restarts the server on an empty directory to generate a fresh policy repo"})
	case "not_configured":
		out = append(out, step{Tool: "status", Why: "shows what this server was started with (--server, ClickHouse, --allow-writes)"})
	default:
		retry("retry after fixing the cause named in error.message")
		out = append(out, step{Tool: "doctor", Why: "checks the machine and the policy repo and prints the exact fix for each problem"})
	}
	return out
}

// backticked returns the first `...` span of msg starting with prefix.
func backticked(msg, prefix string) string {
	for {
		i := strings.IndexByte(msg, '`')
		if i < 0 {
			return ""
		}
		j := strings.IndexByte(msg[i+1:], '`')
		if j < 0 {
			return ""
		}
		if span := msg[i+1 : i+1+j]; strings.HasPrefix(span, prefix) {
			return span
		}
		msg = msg[i+1+j+1:]
	}
}

// decorateSuccess folds next_steps / next into one ordered list and appends
// the standard flow for the tool.
func (s *srv) decorateSuccess(tool string, args map[string]any, cr *mcp.CallToolResult) {
	var old []byte
	switch sc := cr.StructuredContent.(type) {
	case json.RawMessage:
		old = sc
	case nil:
	default:
		old, _ = json.Marshal(sc)
	}
	out := map[string]any{}
	if len(old) > 0 {
		dec := json.NewDecoder(bytes.NewReader(old))
		dec.UseNumber()
		if dec.Decode(&out) != nil || out == nil {
			out = map[string]any{}
		}
	}
	var steps []step
	for _, key := range []string{"next_steps", "next"} {
		steps = append(steps, toSteps(out[key])...)
		delete(out, key)
	}
	steps = append(steps, s.flow(tool, args, out)...)
	out["next_steps"] = dedupe(steps)
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	cr.StructuredContent = json.RawMessage(b)
	if len(cr.Content) == 1 {
		if t, ok := cr.Content[0].(*mcp.TextContent); ok && (t.Text == string(old) || len(old) == 0) {
			t.Text = string(b)
			return
		}
	}
	if len(old) == 0 {
		cr.Content = append(cr.Content, &mcp.TextContent{Text: string(b)})
	}
}

func dedupe(in []step) []step {
	seen := map[string]bool{}
	out := []step{}
	for _, st := range in {
		k := st.Tool + "|" + st.Command + "|" + st.Why
		if st.Tool != "" || st.Command != "" {
			k = st.Tool + "|" + st.Command + "|" + exampleJSON(st.Args)
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, st)
		}
	}
	return out
}

// toSteps accepts the shapes handlers produce: []string, []any of strings or
// of step objects.
func toSteps(v any) []step {
	l, ok := v.([]any)
	if !ok {
		if ss, ok2 := v.([]string); ok2 {
			for _, x := range ss {
				l = append(l, x)
			}
		}
	}
	var out []step
	for _, e := range l {
		switch x := e.(type) {
		case string:
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, stringStep(x))
			}
		case map[string]any:
			st := step{}
			st.Tool, _ = x["tool"].(string)
			st.Command, _ = x["command"].(string)
			st.Why, _ = x["why"].(string)
			st.Args, _ = x["args"].(map[string]any)
			if st.Tool != "" || st.Command != "" || st.Why != "" {
				out = append(out, st)
			}
		}
	}
	return out
}

// stringStep lifts a human command out of a free-text next step; the text is
// always kept as why.
func stringStep(s string) step {
	st := step{Why: s}
	if strings.HasPrefix(s, "human gate") {
		if _, cmd, ok := strings.Cut(s, ": "); ok && strings.HasPrefix(cmd, "halo ") {
			st.Command = cmd // a pasteable shell line, possibly `a && b`
			return st
		}
	}
	for _, p := range []string{"halo ", "sudo "} {
		if c := backticked(s, p); c != "" {
			st.Command = c
			return st
		}
		if strings.HasPrefix(s, p) {
			st.Command = s
			return st
		}
	}
	return st
}

// ---- tools/list ----

var stepSchemaJSON = `{"type":"array","description":"Ordered next calls: a tool (with an args example) or a human command, and why.",` +
	`"items":{"type":"object","properties":{"tool":{"type":"string"},"command":{"type":"string"},"why":{"type":"string"},"args":{"type":"object"}},"required":["why"]}}`

func (s *srv) decorateList(lr *mcp.ListToolsResult) *mcp.ListToolsResult {
	var stepsSch jsonschema.Schema
	_ = json.Unmarshal([]byte(stepSchemaJSON), &stepsSch)
	rings, exps := s.names()
	out := *lr
	out.Tools = make([]*mcp.Tool, 0, len(lr.Tools))
	for _, t := range lr.Tools {
		tc := *t
		if in := asSchema(t.InputSchema); in != nil {
			in = cloneSchema(in)
			for _, r := range extraRequired[t.Name] {
				if !contains(in.Required, r) {
					in.Required = append(in.Required, r)
				}
			}
			for name, p := range in.Properties {
				if len(p.Examples) == 0 {
					if ex := s.fieldExampleWith(t.Name, name, p, rings, exps); ex != nil {
						p.Examples = []any{ex}
					}
				}
				if len(p.Default) == 0 {
					if d, ok := fieldDefault(t.Name, name); ok {
						b, _ := json.Marshal(d)
						p.Default = b
					}
				}
			}
			tc.InputSchema = in
		}
		if o := asSchema(t.OutputSchema); o != nil {
			o = cloneSchema(o)
			if o.Properties == nil {
				o.Properties = map[string]*jsonschema.Schema{}
			}
			delete(o.Properties, "next")
			sc := stepsSch
			o.Properties["next_steps"] = &sc
			var req []string
			for _, r := range o.Required {
				if r != "next" && r != "next_steps" {
					req = append(req, r)
				}
			}
			o.Required = append(req, "next_steps")
			tc.OutputSchema = o
		}
		out.Tools = append(out.Tools, &tc)
	}
	return &out
}
