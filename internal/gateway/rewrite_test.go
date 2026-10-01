package gateway

import (
	"encoding/json"
	"testing"
)

func TestRewriteRequest(t *testing.T) {
	tests := []struct {
		name, proto, path, body, model string
		wantPath                       string
		wantModel                      string // "" => body untouched
		wantErr                        bool
	}{
		{"anthropic", ProtoAnthropic, "/v1/messages", `{"model":"sonnet","max_tokens":9,"messages":[{"role":"user","content":"x"}]}`, "claude-x", "/v1/messages", "claude-x", false},
		{"responses", ProtoResponses, "/v1/responses", `{"model":"gpt","input":"x"}`, "gpt-5", "/v1/responses", "gpt-5", false},
		{"bedrock invoke", ProtoBedrock, "/model/sonnet/invoke", `{}`, "us.anthropic.claude-sonnet-4-5-v1:0", "/model/us.anthropic.claude-sonnet-4-5-v1%3A0/invoke", "", false},
		{"bedrock stream + arn", ProtoBedrock, "/model/sonnet/invoke-with-response-stream", `{}`, "arn:aws:bedrock:us-east-1:1:inference-profile/p", "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fp/invoke-with-response-stream", "", false},
		{"empty model no-op", ProtoAnthropic, "/v1/messages", `{"model":"a"}`, "", "/v1/messages", "a", false},
		{"bad json", ProtoAnthropic, "/v1/messages", `[`, "m", "/v1/messages", "", true},
		{"bad bedrock path", ProtoBedrock, "/nope", `{}`, "m", "/nope", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, b, err := RewriteRequest(tc.proto, tc.path, []byte(tc.body), tc.model)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
			if p != tc.wantPath {
				t.Fatalf("path %q want %q", p, tc.wantPath)
			}
			if tc.wantModel != "" {
				var m map[string]any
				if err := json.Unmarshal(b, &m); err != nil || m["model"] != tc.wantModel {
					t.Fatalf("body %s err=%v", b, err)
				}
			}
		})
	}
}

func TestRewritePreservesFields(t *testing.T) {
	_, b, err := RewriteRequest(ProtoAnthropic, "/v1/messages", []byte(`{"model":"a","big":12345678901234567890,"messages":[{"role":"user","content":"é"}]}`), "b")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if string(m["big"]) != "12345678901234567890" || string(m["messages"]) != `[{"role":"user","content":"é"}]` {
		t.Fatalf("fields mangled: %s", b)
	}
}

func TestForceNonStreaming(t *testing.T) {
	p, b, _ := ForceNonStreaming(ProtoAnthropic, "/v1/messages", []byte(`{"stream":true,"model":"m"}`))
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if p != "/v1/messages" || m["stream"] != false {
		t.Fatalf("%s %s", p, b)
	}
	if p, _, _ := ForceNonStreaming(ProtoBedrock, "/model/x/invoke-with-response-stream", nil); p != "/model/x/invoke" {
		t.Fatal(p)
	}
}

func TestTarget(t *testing.T) {
	s, h, p, pre, err := Target("https://orch.internal:8443/bedrock/")
	if err != nil || s != "https" || h != "orch.internal" || p != 8443 || pre != "/bedrock" {
		t.Fatal(s, h, p, pre, err)
	}
	if _, _, p, _, _ := Target("http://x"); p != 80 {
		t.Fatal(p)
	}
	if _, _, _, _, err := Target("nohost"); err == nil {
		t.Fatal("want error")
	}
}
