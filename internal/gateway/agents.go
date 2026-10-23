package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/dshakes/halos/internal/policy"
)

// Delegated agents at the gateway (ADR-0024). The subject is the root
// principal, so cohort, ring, budgets and posture are the root's; the agent
// chain is attributed (x-halo-actor, telemetry) and bounded by policy here.

const (
	// HeaderActor carries the verified actor chain ("planner>reviewer") and
	// HeaderActorDepth its length upstream. Gateway-owned like every x-halo-*:
	// a client copy is always discarded.
	HeaderActor      = "x-halo-actor"
	HeaderActorDepth = "x-halo-actor-depth"
)

// admitAgent applies the current policy to a delegated caller's model call:
// every agent of the chain must still be in agents.actors and admit the
// root's groups, the chain must be within agents.maxDepth and the root's
// profile and unit maxDepth, the model within the credential's scope,
// agents.allowedModels and the models of every actor of the chain, and no
// declared tool in agents.deniedTools. When deniedTools is set and the tools
// cannot be read, the call is refused. Every refusal is a 400: a permanent
// error the CLIs show instead of retrying.
func admitAgent(org *policy.Org, sub *policy.Subject, req RequestInfo, path string, body []byte) *Rejection {
	deny := func(format string, a ...any) *Rejection {
		return &Rejection{Status: http.StatusBadRequest, Protocol: req.Protocol, Code: "agent_not_permitted",
			Message: "halos: " + fmt.Sprintf(format, a...)}
	}
	d := sub.Delegation
	if err := org.Agents.AdmitChain(sub.Groups, d); err != nil {
		return deny("%v", err)
	}
	sc, err := agentScope(org, policy.Subject{ID: sub.ID, Groups: sub.Groups, Kind: sub.Kind})
	if err != nil {
		return deny("the agent policy cannot be resolved for this principal")
	}
	if d.Depth() > sc.MaxDepth {
		return deny("delegation depth %d exceeds the maximum %d (agents.maxDepth, profile and unit agents.maxDepth)", d.Depth(), sc.MaxDepth)
	}
	if lim := org.Agents.ChainModelLimit(d); lim != nil && !slices.Contains(lim, req.ModelAlias) {
		return deny("model %q is not permitted for agent chain %s; allowed: %v", req.ModelAlias, d.Chain(), lim)
	}
	if len(org.Agents.DeniedTools) == 0 {
		return nil
	}
	tools, err := ToolNames(req.Protocol, path, body)
	if err != nil {
		return deny("the request's tools cannot be inspected (%v); agents.deniedTools is set, so delegated agents must send tool declarations the gateway can read", err)
	}
	for _, t := range tools {
		if org.Agents.DeniesTool(t.Name, t.Hosted) {
			return deny("tool %q is denied to delegated agents (agents.deniedTools)", t.Name)
		}
	}
	return nil
}

// scopeCache memoises policy.AgentScopeIn per policy snapshot (a reload is a
// new *Org): it depends only on the ring and unit names, and resolving a
// profile merges its chain.
var scopeCache struct {
	mu  sync.Mutex
	org *policy.Org
	m   map[[2]string]policy.AgentScope
}

// agentScope is org.AgentScopeFor(s), memoised by ring and unit.
func agentScope(org *policy.Org, s policy.Subject) (policy.AgentScope, error) {
	var key [2]string
	if r := org.ResolveRing(s); r != nil {
		key[0] = r.Name
	}
	if u := org.ResolveUnit(s); u != nil {
		key[1] = u.Name
	}
	scopeCache.mu.Lock()
	defer scopeCache.mu.Unlock()
	if scopeCache.org != org {
		scopeCache.org, scopeCache.m = org, map[[2]string]policy.AgentScope{}
	}
	if sc, ok := scopeCache.m[key]; ok {
		return sc, nil
	}
	sc, err := org.AgentScopeIn(key[0], key[1])
	if err != nil {
		return policy.AgentScope{}, err
	}
	scopeCache.m[key] = sc
	return sc, nil
}

// agentHeaders stamps the verified chain on the upstream request.
func agentHeaders(h map[string]string, d *policy.DelegationChain) {
	if d.Depth() == 0 {
		return
	}
	h[HeaderActor] = d.Chain()
	h[HeaderActorDepth] = strconv.Itoa(d.Depth())
}

// Tool is one tool a model call declares. Hosted marks a tool the provider
// runs or builds in (web search, code execution, a remote MCP server, a
// versioned Anthropic tool): Name is then its type, its Gemini or Bedrock
// tool key, or mcp:<server>, and policy matches it as a prefix (see
// policy.Agents.DeniesTool).
type Tool struct {
	Name   string
	Hosted bool
}

// ToolNames returns every tool a model call declares, or an error when the
// body or its tool declarations cannot be read: a body nested past
// maxJSONDepth, trailing data, a tools member of the wrong shape, a tool
// without a name, or a (protocol, path) without an extractor. The
// inspectable shapes are an explicit list:
//
//   - Anthropic Messages and count_tokens: tools[].name and tools[].type
//     (hosted unless "custom"), mcp_servers[].name as mcp:<name>.
//   - OpenAI Responses: tools[].name of function and custom tools; any other
//     tools[].type is hosted, mcp as mcp:<server_label>.
//   - Bedrock invoke and converse: the Anthropic shape,
//     toolConfig.tools[].toolSpec.name, toolConfig.tools[].systemTool.name
//     (hosted), any other toolConfig.tools[] member (hosted) and
//     additionalModelRequestFields.tools.
//   - Gemini generateContent, streamGenerateContent and countTokens:
//     tools[].functionDeclarations[].name, every other tools[] member key
//     (codeExecution, googleSearch, urlContext, ...) as hosted, and the same
//     under generateContentRequest.
//
// Keys match ignoring case and underscores (function_declarations is
// functionDeclarations) and duplicate keys all count, so a body cannot show
// the gateway one tool list and the upstream parser another.
func ToolNames(protocol, path string, body []byte) ([]Tool, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	root, err := decodeNode(dec, 0)
	if err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("body: trailing data after the JSON value")
	}
	if root.kind != '{' {
		return nil, errors.New("body is not a JSON object")
	}
	var x toolReader
	switch {
	case protocol == ProtoAnthropic && (path == PathMessages || path == PathCountTokens):
		x.anthropic(root)
	case protocol == ProtoResponses && path == PathResponses:
		x.responses(root)
	case protocol == ProtoBedrock && bedrockPath.MatchString(path):
		x.anthropic(root)
		for _, tc := range root.field("toolConfig") {
			x.converse(tc)
		}
		for _, f := range root.field("additionalModelRequestFields") {
			x.anthropic(f)
		}
	case protocol == ProtoGemini && geminiPath.MatchString(path):
		x.gemini(root)
		for _, g := range root.field("generateContentRequest") {
			x.gemini(g)
		}
	default:
		return nil, fmt.Errorf("no tool extractor for %s %s", protocol, path)
	}
	return x.out, x.err
}

// toolReader collects tools; the first shape error sticks.
type toolReader struct {
	out []Tool
	err error
}

func (x *toolReader) fail(format string, a ...any) {
	if x.err == nil {
		x.err = fmt.Errorf(format, a...)
	}
}

func (x *toolReader) add(name string, hosted bool) { x.out = append(x.out, Tool{name, hosted}) }

// objects returns the objects of every n.key array (null and absent are none).
func (x *toolReader) objects(n jnode, key string) []jnode {
	var out []jnode
	for _, v := range n.field(key) {
		switch {
		case v.kind == 0 && v.scalar == nil: // null
		case v.kind != '[':
			x.fail("%s is not an array", key)
		default:
			for _, e := range v.arr {
				if e.kind != '{' {
					x.fail("a %s entry is not an object", key)
					continue
				}
				out = append(out, e)
			}
		}
	}
	return out
}

// strs returns every n.key string value.
func (x *toolReader) strs(n jnode, key string) []string {
	var out []string
	for _, v := range n.field(key) {
		s, ok := v.scalar.(string)
		if !ok {
			x.fail("tool %s is not a string", key)
			continue
		}
		out = append(out, s)
	}
	return out
}

func (x *toolReader) anthropic(n jnode) {
	if n.kind != '{' {
		return
	}
	for _, t := range x.objects(n, "tools") {
		names, types := x.strs(t, "name"), x.strs(t, "type")
		if len(names)+len(types) == 0 {
			x.fail("a tool has neither name nor type")
		}
		for _, nm := range names {
			x.add(nm, false)
		}
		for _, ty := range types {
			if !strings.EqualFold(ty, "custom") {
				x.add(ty, true)
			}
		}
	}
	for _, m := range x.objects(n, "mcp_servers") {
		names := x.strs(m, "name")
		if len(names) == 0 {
			x.fail("an mcp_servers entry has no name")
		}
		for _, nm := range names {
			x.add("mcp:"+nm, true)
		}
	}
}

func (x *toolReader) responses(n jnode) {
	for _, t := range x.objects(n, "tools") {
		types, names := x.strs(t, "type"), x.strs(t, "name")
		if len(types) == 0 {
			x.fail("a tool has no type")
		}
		for _, ty := range types {
			switch strings.ToLower(ty) {
			case "function", "custom":
				if len(names) == 0 {
					x.fail("a %s tool has no name", ty)
				}
			case "mcp":
				labels := x.strs(t, "server_label")
				if len(labels) == 0 {
					x.fail("an mcp tool has no server_label")
				}
				for _, l := range labels {
					x.add("mcp:"+l, true)
				}
			default:
				x.add(ty, true)
			}
		}
		for _, nm := range names {
			x.add(nm, false)
		}
	}
}

func (x *toolReader) converse(tc jnode) {
	if tc.kind != '{' {
		x.fail("toolConfig is not an object")
		return
	}
	for _, t := range x.objects(tc, "tools") {
		for _, kv := range t.obj {
			switch {
			case keyIs(kv.k, "cachePoint"): // a prompt-cache marker, not a tool
			case keyIs(kv.k, "toolSpec"), keyIs(kv.k, "systemTool"):
				names := x.strs(kv.v, "name")
				if len(names) == 0 {
					x.fail("a %s has no name", kv.k)
				}
				for _, nm := range names {
					x.add(nm, keyIs(kv.k, "systemTool"))
				}
			default:
				x.add(kv.k, true)
			}
		}
	}
}

func (x *toolReader) gemini(n jnode) {
	if n.kind != '{' {
		return
	}
	for _, t := range x.objects(n, "tools") {
		for _, kv := range t.obj {
			if !keyIs(kv.k, "functionDeclarations") {
				x.add(kv.k, true)
				continue
			}
			for _, f := range x.objects(jnode{kind: '{', obj: []jmember{kv}}, kv.k) {
				names := x.strs(f, "name")
				if len(names) == 0 {
					x.fail("a function declaration has no name")
				}
				for _, nm := range names {
					x.add(nm, false)
				}
			}
		}
	}
}

// jnode is a JSON value that keeps every object member, duplicates included.
type jnode struct {
	kind   json.Delim // '{' or '[' for an object or array, 0 for a scalar
	obj    []jmember
	arr    []jnode
	scalar any
}

type jmember struct {
	k string
	v jnode
}

// field returns every member value whose key equals name ignoring case and
// underscores (protobuf JSON parsers accept snake_case and camelCase).
func (n jnode) field(name string) []jnode {
	var out []jnode
	for _, kv := range n.obj {
		if keyIs(kv.k, name) {
			out = append(out, kv.v)
		}
	}
	return out
}

// keyIs reports whether JSON key k names member name, ignoring case
// (Unicode folding, as the most lenient upstream parser) and underscores.
func keyIs(k, name string) bool {
	return strings.EqualFold(strings.ReplaceAll(k, "_", ""), strings.ReplaceAll(name, "_", ""))
}

// maxJSONDepth bounds decodeNode's recursion.
const maxJSONDepth = 64

func decodeNode(dec *json.Decoder, depth int) (jnode, error) {
	if depth > maxJSONDepth {
		return jnode{}, errors.New("gateway: JSON nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return jnode{}, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return jnode{scalar: tok}, nil
	}
	n := jnode{kind: d}
	switch d {
	case '{':
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return jnode{}, err
			}
			k, _ := kt.(string)
			v, err := decodeNode(dec, depth+1)
			if err != nil {
				return jnode{}, err
			}
			n.obj = append(n.obj, jmember{k, v})
		}
	case '[':
		for dec.More() {
			v, err := decodeNode(dec, depth+1)
			if err != nil {
				return jnode{}, err
			}
			n.arr = append(n.arr, v)
		}
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return jnode{}, err
	}
	return n, nil
}
