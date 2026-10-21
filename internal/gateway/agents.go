package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

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
// the agent must still be in agents.actors, the chain within agents.maxDepth,
// the model within the credential's scope, agents.allowedModels and the
// actor's models, and no declared tool in agents.deniedTools. Every refusal
// is a 400: a permanent error the CLIs show instead of retrying.
func admitAgent(org *policy.Org, d *policy.DelegationChain, req RequestInfo, body []byte) *Rejection {
	deny := func(format string, a ...any) *Rejection {
		return &Rejection{Status: http.StatusBadRequest, Protocol: req.Protocol, Code: "agent_not_permitted",
			Message: "halos: " + fmt.Sprintf(format, a...)}
	}
	if org.Agents == nil {
		return deny("delegated agent credentials are not accepted: the policy declares no agents")
	}
	cur := d.Current().Agent
	actor := org.Agents.Actor(cur)
	if actor == nil {
		return deny("agent %q is not in agents.actors", cur)
	}
	if d.Depth() > org.Agents.Depth() {
		return deny("delegation depth %d exceeds agents.maxDepth %d", d.Depth(), org.Agents.Depth())
	}
	if lim := policy.IntersectScope(d.Models, org.Agents.ModelLimit(actor)); lim != nil && !slices.Contains(lim, req.ModelAlias) {
		return deny("model %q is not permitted for agent %q; allowed: %v", req.ModelAlias, cur, lim)
	}
	if t := org.Agents.ToolDenied(ToolNames(req.Protocol, body)); t != "" {
		return deny("tool %q is denied to delegated agents (agents.deniedTools)", t)
	}
	return nil
}

// agentHeaders stamps the verified chain on the upstream request.
func agentHeaders(h map[string]string, d *policy.DelegationChain) {
	if d.Depth() == 0 {
		return
	}
	h[HeaderActor] = d.Chain()
	h[HeaderActorDepth] = strconv.Itoa(d.Depth())
}

// ToolNames returns every tool name a model call declares: Anthropic
// tools[].name (Bedrock carries the same body), OpenAI Responses tools[].name
// and, for built-in tools, tools[].type, Gemini
// tools[].functionDeclarations[].name. Keys match case-insensitively and
// duplicate keys all count, so a body cannot show the gateway one tool list
// and the upstream parser another. Unparseable bodies yield none (the model
// alias check already refuses a body whose model cannot be read).
func ToolNames(protocol string, body []byte) []string {
	root, err := decodeNode(json.NewDecoder(bytes.NewReader(body)), 0)
	if err != nil {
		return nil
	}
	var out []string
	names := func(item jnode, keys ...string) {
		for _, kv := range item.obj {
			if s, ok := kv.v.scalar.(string); ok && slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, kv.k) }) {
				out = append(out, s)
			}
		}
	}
	for _, tools := range root.field("tools") {
		for _, t := range tools.arr {
			if protocol == ProtoGemini {
				for _, fds := range t.field("functionDeclarations") {
					for _, f := range fds.arr {
						names(f, "name")
					}
				}
				continue
			}
			names(t, "name", "type")
		}
	}
	return out
}

// jnode is a JSON value that keeps every object member, duplicates included.
type jnode struct {
	obj    []jmember
	arr    []jnode
	scalar any
}

type jmember struct {
	k string
	v jnode
}

// field returns every member value whose key equals name ignoring case.
func (n jnode) field(name string) []jnode {
	var out []jnode
	for _, kv := range n.obj {
		if strings.EqualFold(kv.k, name) {
			out = append(out, kv.v)
		}
	}
	return out
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
	var n jnode
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
