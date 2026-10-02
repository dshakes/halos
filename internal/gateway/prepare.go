package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// Result is everything the Kong plugin must apply to the upstream request.
type Result struct {
	Decision Decision
	Protocol string
	// ClearHeaders are client-supplied x-halo-* names to drop (all of them; the
	// ones Decision sets are then re-set with gateway-owned values).
	ClearHeaders []string
	// Path/Body are the rewritten forms; Rewritten is false when unchanged.
	Path      string
	Body      []byte
	Rewritten bool
	// RewriteErr is non-nil when a rewrite was needed but failed (Reject is
	// then set too: an un-rewritten alias must never reach the upstream).
	RewriteErr error
	// Reject, when non-nil, must be answered by the adapter itself; the
	// request must NOT be forwarded.
	Reject *Rejection
}

// Rejection is a request the gateway answers itself. Fail closed: unknown
// model endpoints (404), unreadable/oversize bodies (413), models that are
// not a configured alias (400: a permanent client error, which the CLIs do
// not retry, unlike 403/5xx/429).
type Rejection struct {
	Status   int
	Protocol string // selects the error body shape
	Message  string
	Code     string // OpenAI Responses error code; "" = derived from Status
}

func (r *Rejection) Error() string { return fmt.Sprintf("gateway: %d %s", r.Status, r.Message) }

// JSON renders the error in the caller's wire format so the CLI shows Message.
func (r *Rejection) JSON() []byte {
	var v any
	switch r.Protocol {
	case ProtoResponses:
		code := map[int]string{400: "model_not_allowed", 401: "invalid_api_key", 403: "model_not_allowed", 404: "unknown_url", 413: "request_too_large"}[r.Status]
		if r.Code != "" {
			code = r.Code
		}
		v = map[string]any{"error": map[string]any{"message": r.Message, "type": "invalid_request_error", "param": nil, "code": code}}
	case ProtoBedrock:
		v = map[string]any{"message": r.Message}
	case ProtoGemini:
		status := map[int]string{400: "INVALID_ARGUMENT", 401: "UNAUTHENTICATED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND", 413: "INVALID_ARGUMENT", 503: "UNAVAILABLE"}[r.Status]
		if status == "" {
			status = "UNKNOWN"
		}
		v = map[string]any{"error": map[string]any{"code": r.Status, "message": r.Message, "status": status}}
	default:
		typ := map[int]string{400: "invalid_request_error", 401: "authentication_error", 403: "permission_error", 404: "not_found_error", 413: "request_too_large", 503: "api_error"}[r.Status]
		if typ == "" {
			typ = "api_error"
		}
		v = map[string]any{"type": "error", "error": map[string]any{"type": typ, "message": r.Message}}
	}
	b, _ := json.Marshal(v) // maps of strings: cannot fail
	return b
}

// RejectTooLarge is the 413 for a model call whose body could not be read
// in full (Kong spooled it to disk, or it exceeds the proxy limit).
func RejectTooLarge(path string) *Rejection {
	return &Rejection{Status: http.StatusRequestEntityTooLarge, Protocol: protocolOrPrefix(path),
		Message: "request body too large for the Halos gateway to inspect"}
}

func protocolOrPrefix(path string) string {
	if p := ProtocolForPath(path); p != "" {
		return p
	}
	return modelPrefix(path)
}

// passthrough reports whether a non-model path may be forwarded unchanged.
// Only model listing is: anything else (other providers' model calls such as
// /v1/chat/completions or Gemini :generateContent, admin APIs) would bypass
// the model allowlist, so it is refused.
// ponytail: exact list; add paths here when a supported CLI needs one.
func passthrough(p string) bool {
	if strings.ContainsAny(p, "%\\") { // no escaped or alternate separators
		return false
	}
	id, ok := strings.CutPrefix(p, "/v1/models/")
	// ":" is excluded: /v1/models/x:generateContent-style calls are model calls, never a model lookup.
	return p == "/v1/models" || (ok && id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/:"))
}

// admit enforces the model allowlist and the non-model passthrough allowlist.
func admit(org *policy.Org, req RequestInfo, d Decision, path string) *Rejection {
	if req.Protocol == "" {
		proto := modelPrefix(path)
		switch {
		case proto == "" && passthrough(path):
			return nil
		case proto == "":
			return &Rejection{Status: http.StatusNotFound, Protocol: ProtoAnthropic, Message: fmt.Sprintf("path %q is not served by the Halos gateway", path)}
		case strings.HasPrefix(strings.ToLower(path), pathBatches):
			// ponytail: batches carry a model per item; strict until someone needs them.
			return &Rejection{Status: http.StatusBadRequest, Protocol: proto, Message: "the message batches API is not permitted by the Halos gateway policy"}
		}
		return &Rejection{Status: http.StatusNotFound, Protocol: proto, Message: fmt.Sprintf("unknown model endpoint %q", path)}
	}
	if org == nil {
		return &Rejection{Status: http.StatusServiceUnavailable, Protocol: req.Protocol, Message: "gateway policy is not loaded"}
	}
	if d.UpstreamName == "" && d.UpstreamModel == "" { // no gateway or variant route for this alias
		var allowed []string
		if org.Gateway != nil {
			for a := range org.Gateway.Models {
				allowed = append(allowed, a)
			}
		}
		sort.Strings(allowed)
		return &Rejection{Status: http.StatusBadRequest, Protocol: req.Protocol,
			Message: fmt.Sprintf("model %q is not permitted by the Halos gateway policy; allowed models: %s", req.ModelAlias, strings.Join(allowed, ", "))}
	}
	return nil
}

// PrepareVerified inspects a request and computes the full set of mutations,
// or a Rejection the adapter must answer instead of forwarding. Cohort comes
// only from sub, verified by internal/identity (JWT, or trusted-proxy
// headers); sub == nil means anonymous: default routing, no experiments.
// Client-supplied headers (x-halo-* or identity) never influence the outcome.
func PrepareVerified(org *policy.Org, sub *policy.Subject, h http.Header, path string, body []byte) Result {
	res := Result{Path: path, Body: body}
	// Always clear the owned names, even if the header list the host gave us
	// was truncated (Kong's GetHeaders caps the count).
	seen := map[string]bool{}
	names := []string{HeaderRing, HeaderRelease, HeaderExperiment, HeaderVariant}
	for name := range h {
		if l := strings.ToLower(name); strings.HasPrefix(l, HaloPrefix) {
			names = append(names, l)
		}
	}
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			res.ClearHeaders = append(res.ClearHeaders, n)
		}
	}
	req := NewRequestInfo(h, path, body)
	if sub != nil {
		req.UserID, req.Groups = sub.ID, sub.Groups
	}
	res.Protocol = req.Protocol
	res.Decision = Decide(org, req)
	if res.Reject = admit(org, req, res.Decision, path); res.Reject != nil {
		return res
	}
	if m := res.Decision.UpstreamModel; m != "" && m != req.ModelAlias {
		p, b, err := RewriteRequest(req.Protocol, path, body, m)
		if err != nil {
			res.RewriteErr = err
			res.Reject = &Rejection{Status: http.StatusBadRequest, Protocol: req.Protocol, Message: "request body could not be rewritten for the upstream model"}
		} else {
			res.Path, res.Body, res.Rewritten = p, b, true
		}
	}
	return res
}

// IdentityHeaderFor picks the configured header, falling back to the org's.
func IdentityHeaderFor(org *policy.Org, override string) string {
	if override != "" {
		return override
	}
	if org != nil && org.Gateway != nil {
		return org.Gateway.Auth.IdentityHeader
	}
	return ""
}
