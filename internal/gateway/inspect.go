// Package gateway holds the traffic-plane logic shared by the halo-kong plugin
// and halo-shadow: request inspection, cohort decision and model rewrite. It is
// pure (no Kong, no network) so the plugin stays a thin adapter.
package gateway

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // UA prefixes come from the adapters
)

// Wire protocols (match policy.Gateway.Protocols values).
const (
	ProtoAnthropic = "anthropic-messages"
	ProtoBedrock   = "bedrock-invoke"
	ProtoResponses = "openai-responses"
)

// Exact model-call paths. Anything else under a model-bearing prefix
// (/v1/messages/*, /v1/responses/*, /model/*) is rejected by Prepare.
const (
	PathMessages    = "/v1/messages"
	PathCountTokens = "/v1/messages/count_tokens" //nolint:gosec // URL path, not a credential
	PathResponses   = "/v1/responses"
	pathBatches     = "/v1/messages/batches"
)

var bedrockPath = regexp.MustCompile(`^/model/([^/]+)/(invoke|invoke-with-response-stream|converse|converse-stream)$`)

// ProtocolForPath classifies a request path by exact match; "" means "not a
// model call". count_tokens is anthropic-messages (it carries a model alias).
func ProtocolForPath(p string) string {
	switch {
	case p == PathMessages, p == PathCountTokens:
		return ProtoAnthropic
	case p == PathResponses:
		return ProtoResponses
	case bedrockPath.MatchString(p):
		return ProtoBedrock
	}
	return ""
}

// modelPrefix returns the protocol whose model-bearing prefix p falls under
// (after unescaping, cleaning and lower-casing, so /v1//Messages/ or
// /v1/%6dessages can't sneak past), or "" when p is not under one.
func modelPrefix(p string) string {
	u, err := url.PathUnescape(p)
	if err != nil {
		return ProtoAnthropic // undecodable: treat as suspicious, never forward
	}
	c := strings.ToLower(path.Clean("/" + u))
	for pre, proto := range map[string]string{PathMessages: ProtoAnthropic, PathResponses: ProtoResponses, "/model": ProtoBedrock} {
		if c == pre || strings.HasPrefix(c, pre+"/") {
			return proto
		}
	}
	return ""
}

// uaPrefixes is built once from the adapters' harness.Meta.
var uaPrefixes = sync.OnceValue(func() [][2]string { // {prefix, harness}
	var out [][2]string
	for _, n := range harness.Names() {
		m, _ := harness.MetaOf(n)
		for _, p := range m.UAPrefixes {
			out = append(out, [2]string{p, n})
		}
	}
	return out
})

// HarnessFromUA maps a User-Agent to a harness adapter name.
func HarnessFromUA(ua string) string {
	l := strings.ToLower(ua)
	for _, p := range uaPrefixes() {
		if strings.HasPrefix(l, p[0]) {
			return p[1]
		}
	}
	return ""
}

// Inspect extracts the requested model alias and whether the request is a
// first turn. Bedrock carries the alias in the path, the others in the body.
// Unparseable bodies yield ("", false): never shadowed, routed by default.
func Inspect(protocol, path string, body []byte) (model string, firstTurn bool) {
	if protocol == ProtoBedrock {
		if m := bedrockPath.FindStringSubmatch(path); m != nil {
			model, _ = url.PathUnescape(m[1])
		}
	}
	var b struct {
		Model          string          `json:"model"`
		Messages       []turn          `json:"messages"`
		Input          json.RawMessage `json:"input"`
		PreviousRespID string          `json:"previous_response_id"`
	}
	if json.Unmarshal(body, &b) != nil {
		return model, false
	}
	if protocol != ProtoBedrock {
		model = b.Model
	}
	switch protocol {
	case ProtoAnthropic, ProtoBedrock:
		return model, firstTurnOf(b.Messages)
	case ProtoResponses:
		if b.PreviousRespID != "" {
			return model, false
		}
		var s string
		if json.Unmarshal(b.Input, &s) == nil && s != "" {
			return model, true
		}
		var items []turn
		if json.Unmarshal(b.Input, &items) != nil {
			return model, false
		}
		return model, firstTurnOf(items)
	}
	return model, false
}

type turn struct {
	Role string `json:"role"`
	Type string `json:"type"`
}

// firstTurnOf: exactly one user message and no assistant/tool traffic.
// ponytail: heuristic; a client that replays history without assistant turns
// would look first-turn. Fine for sampling, not for billing.
func firstTurnOf(ts []turn) bool {
	users := 0
	for _, t := range ts {
		switch {
		case t.Role == "user":
			users++
		case t.Role == "assistant", strings.HasPrefix(t.Type, "function_call"), strings.HasSuffix(t.Type, "_call"), strings.HasSuffix(t.Type, "_output"), t.Type == "reasoning":
			return false
		}
	}
	return users == 1
}

// NewRequestInfo builds RequestInfo from the request alone. UserID/Groups are
// left empty: cohort comes only from a verified identity (PrepareVerified).
func NewRequestInfo(h http.Header, path string, body []byte) RequestInfo {
	proto := ProtocolForPath(path)
	model, first := Inspect(proto, path, body)
	if path == PathCountTokens {
		first = false // never mirror token counting
	}
	return RequestInfo{
		Protocol:   proto,
		ModelAlias: model,
		FirstTurn:  first,
		Harness:    HarnessFromUA(h.Get("User-Agent")),
		SessionID:  SessionID(h),
	}
}

// SessionID is the harness session id: Claude Code's header, then Codex's.
func SessionID(h http.Header) string {
	if v := h.Get("x-claude-code-session-id"); v != "" {
		return v
	}
	return h.Get("session_id")
}
