package gateway

import (
	"net/http"
	"strings"
	"testing"
)

func TestGeminiWire(t *testing.T) {
	for path, want := range map[string]string{
		"/v1beta/models/gemini-default:streamGenerateContent": ProtoGemini,
		"/v1beta/models/gemini-default:generateContent":       ProtoGemini,
		"/v1beta/models/gemini-default:countTokens":           ProtoGemini,
		"/v1/models/gemini-default:generateContent":           ProtoGemini,
		"/v1beta/models/gemini-default%3AgenerateContent":     ProtoGemini,
		"/v1beta/models/gemini-default:embedContent":          "",
		"/v1beta/models/a/b:generateContent":                  "",
		"/v1beta/models":                                      "",
	} {
		if got := ProtocolForPath(path); got != want {
			t.Errorf("ProtocolForPath(%q) = %q, want %q", path, got, want)
		}
	}
	model, first := Inspect(ProtoGemini, "/v1beta/models/gemini-default:streamGenerateContent", []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`))
	if model != "gemini-default" || !first {
		t.Errorf("inspect: %q %v", model, first)
	}
	if _, first = Inspect(ProtoGemini, "/v1beta/models/m:generateContent", []byte(`{"contents":[{"role":"user"},{"role":"model"},{"role":"user"}]}`)); first {
		t.Error("a conversation with a model turn is not a first turn")
	}
	if !IsCountTokens("/v1beta/models/m:countTokens") || IsCountTokens("/v1beta/models/m:generateContent") {
		t.Error("IsCountTokens")
	}
	p, _, err := RewriteRequest(ProtoGemini, "/v1beta/models/gemini-default:streamGenerateContent", []byte(`{}`), "gemini-2.5-pro")
	if err != nil || p != "/v1beta/models/gemini-2.5-pro:streamGenerateContent" {
		t.Errorf("rewrite: %q %v", p, err)
	}
}

// Gemini model calls must never slip through the non-model passthrough, and
// unknown Gemini operations are refused rather than forwarded.
func TestGeminiNotPassthrough(t *testing.T) {
	org := testOrg()
	for _, path := range []string{"/v1/models/x:embedContent", "/v1/models/x:batchEmbedContents", "/v1beta/models/x:embedContent", "/v1beta/models"} {
		res := PrepareVerified(org, nil, http.Header{}, path, []byte(`{}`))
		if res.Reject == nil || res.Reject.Status != http.StatusNotFound && res.Reject.Status != http.StatusBadRequest {
			t.Errorf("%s: want a refusal, got %+v", path, res.Reject)
		}
	}
	res := PrepareVerified(org, nil, http.Header{}, "/v1beta/models/not-an-alias:generateContent", []byte(`{}`))
	if res.Reject == nil || res.Reject.Status != http.StatusBadRequest || !strings.Contains(string(res.Reject.JSON()), "INVALID_ARGUMENT") {
		t.Fatalf("unknown alias: %+v", res.Reject)
	}
}
