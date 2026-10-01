package gateway

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/dshakes/halos/internal/policy"
)

// Provider wire constants stamped into translated bodies.
const (
	bedrockAnthropicVersion = "bedrock-2023-05-31"
	vertexAnthropicVersion  = "vertex-2023-10-16"
)

// Outbound is the request an upstream expects, derived from the client's
// request. Path is escaped and relative to the upstream's base URL.
type Outbound struct {
	Path     string
	RawQuery string
	SetQuery bool // replace the client's query string with RawQuery (else keep it)
	Body     []byte
	// SSE: the response is a Bedrock event stream the anthropic-messages client
	// cannot read; convert it with EventStreamToSSE.
	SSE bool
}

// BuildOutbound rewrites the client's request (protocol proto, escaped path,
// body) for upstream up serving model. Same-wire upstreams only get the model
// swapped (RewriteRequest). Translations:
//
//	anthropic-messages -> bedrock   POST /model/{id}/invoke[-with-response-stream], body without model/stream + anthropic_version
//	anthropic-messages -> vertex    POST .../publishers/anthropic/models/{id}:[stream]rawPredict, body without model + anthropic_version
//	openai-responses   -> azure     POST /openai/v1/responses (or /openai/responses?api-version=), model = deployment
//
// Responses stay in the provider's format except Bedrock streams, which are
// converted to SSE (see Outbound.SSE).
func BuildOutbound(proto string, up policy.Upstream, model, path string, body []byte) (Outbound, error) {
	if !policy.KindServes(up.Kind, proto) {
		return Outbound{}, fmt.Errorf("gateway: upstream kind %s cannot serve %s", up.Kind, proto)
	}
	switch {
	case up.Kind == "bedrock" && proto == ProtoAnthropic:
		stream, nb, err := anthropicBody(path, body, bedrockAnthropicVersion, true)
		if err != nil {
			return Outbound{}, err
		}
		op := "invoke"
		if stream {
			op = "invoke-with-response-stream"
		}
		return Outbound{Path: "/model/" + escapeSegment(model) + "/" + op, Body: nb, SetQuery: true, SSE: stream}, nil
	case up.Kind == "vertex":
		if up.Project == "" || up.Region == "" {
			return Outbound{}, fmt.Errorf("gateway: vertex upstream needs project and region")
		}
		stream, nb, err := anthropicBody(path, body, vertexAnthropicVersion, false)
		if err != nil {
			return Outbound{}, err
		}
		op := ":rawPredict"
		if stream {
			op = ":streamRawPredict"
		}
		p := "/v1/projects/" + url.PathEscape(up.Project) + "/locations/" + url.PathEscape(up.Region) +
			"/publishers/anthropic/models/" + url.PathEscape(model) + op
		return Outbound{Path: p, Body: nb, SetQuery: true}, nil
	case up.Kind == "azure-openai":
		nb, err := setJSONField(body, "model", model) // the deployment name
		if err != nil {
			return Outbound{}, err
		}
		if up.APIVersion != "" {
			return Outbound{Path: "/openai/responses", RawQuery: "api-version=" + url.QueryEscape(up.APIVersion), SetQuery: true, Body: nb}, nil
		}
		return Outbound{Path: "/openai/v1/responses", SetQuery: true, Body: nb}, nil
	}
	p, b, err := RewriteRequest(proto, path, body, model)
	return Outbound{Path: p, Body: b}, err
}

// anthropicBody turns an anthropic-messages body into a provider invoke body:
// the model moves to the URL, anthropic_version is set. dropStream removes the
// stream flag (Bedrock chooses by endpoint; Vertex keeps it in the body).
func anthropicBody(path string, body []byte, version string, dropStream bool) (stream bool, out []byte, err error) {
	if path != PathMessages {
		return false, nil, fmt.Errorf("gateway: %q has no provider equivalent (only %s)", path, PathMessages)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false, nil, fmt.Errorf("gateway: translate: body is not a JSON object: %w", err)
	}
	_ = json.Unmarshal(m["stream"], &stream)
	delete(m, "model")
	if dropStream {
		delete(m, "stream")
	}
	if _, ok := m["anthropic_version"]; !ok {
		m["anthropic_version"] = json.RawMessage(strconvQuote(version))
	}
	out, err = json.Marshal(m)
	return stream, out, err
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }
