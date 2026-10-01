package gateway

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// RewriteRequest points a request at upstream model `model`: the JSON "model"
// field for anthropic-messages / openai-responses, the /model/{id}/ path
// segment for bedrock-invoke. Only the request is touched; responses stream
// through untouched. Empty model or unknown protocol is a no-op.
func RewriteRequest(protocol, path string, body []byte, model string) (string, []byte, error) {
	if model == "" {
		return path, body, nil
	}
	switch protocol {
	case ProtoAnthropic, ProtoResponses:
		nb, err := setJSONField(body, "model", model)
		return path, nb, err
	case ProtoBedrock:
		m := bedrockPath.FindStringSubmatch(path)
		if m == nil {
			return path, body, fmt.Errorf("gateway: not a bedrock model path: %q", path)
		}
		return "/model/" + escapeSegment(model) + "/" + m[2], body, nil
	}
	return path, body, nil
}

// ForceNonStreaming makes a request non-streaming (used for shadow copies).
func ForceNonStreaming(protocol, path string, body []byte) (string, []byte, error) {
	switch protocol {
	case ProtoAnthropic, ProtoResponses:
		nb, err := setJSONField(body, "stream", false)
		return path, nb, err
	case ProtoBedrock:
		if strings.HasSuffix(path, "-with-response-stream") {
			return strings.TrimSuffix(path, "-with-response-stream"), body, nil
		}
		if strings.HasSuffix(path, "converse-stream") {
			return strings.TrimSuffix(path, "-stream"), body, nil
		}
	}
	return path, body, nil
}

// setJSONField replaces one top-level field, preserving all other values
// byte-for-byte (key order is normalised).
func setJSONField(body []byte, key string, val any) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body, fmt.Errorf("gateway: rewrite %q: body is not a JSON object: %w", key, err)
	}
	raw, err := json.Marshal(val)
	if err != nil {
		return body, fmt.Errorf("gateway: rewrite %q: %w", key, err)
	}
	m[key] = raw
	out, err := json.Marshal(m)
	if err != nil {
		return body, fmt.Errorf("gateway: rewrite %q: %w", key, err)
	}
	return out, nil
}

// escapeSegment percent-encodes ':' and '/' too (Bedrock ARNs / profile ids).
func escapeSegment(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// Target splits an upstream URL for Kong's balancer.
func Target(raw string) (scheme, host string, port int, pathPrefix string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", 0, "", fmt.Errorf("gateway: bad upstream url %q: %v", raw, err)
	}
	port = 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			return "", "", 0, "", fmt.Errorf("gateway: bad port in %q: %w", raw, err)
		}
	}
	return u.Scheme, u.Hostname(), port, strings.TrimRight(u.Path, "/"), nil
}
