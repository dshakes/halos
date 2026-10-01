package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func jsonField(t *testing.T, body []byte, k string) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	return m[k]
}

func TestBuildOutbound(t *testing.T) {
	msg := []byte(`{"model":"opus","stream":true,"max_tokens":5,"messages":[]}`)
	sync := []byte(`{"model":"opus","max_tokens":5,"messages":[]}`)
	vertex := policy.Upstream{Kind: "vertex", Project: "proj", Region: "us-east5"}

	t.Run("bedrock stream", func(t *testing.T) {
		o, err := BuildOutbound(ProtoAnthropic, policy.Upstream{Kind: "bedrock"}, "us.anthropic.claude-opus-4-1:0", PathMessages, msg)
		if err != nil {
			t.Fatal(err)
		}
		if o.Path != "/model/us.anthropic.claude-opus-4-1%3A0/invoke-with-response-stream" || !o.SSE || !o.SetQuery {
			t.Fatalf("%+v", o)
		}
		if jsonField(t, o.Body, "model") != nil || jsonField(t, o.Body, "stream") != nil || jsonField(t, o.Body, "anthropic_version") != "bedrock-2023-05-31" {
			t.Fatalf("body %s", o.Body)
		}
	})
	t.Run("bedrock sync", func(t *testing.T) {
		o, err := BuildOutbound(ProtoAnthropic, policy.Upstream{Kind: "bedrock"}, "m", PathMessages, sync)
		if err != nil || o.Path != "/model/m/invoke" || o.SSE {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("bedrock client stays bedrock", func(t *testing.T) {
		o, err := BuildOutbound(ProtoBedrock, policy.Upstream{Kind: "bedrock"}, "new", "/model/old/invoke", []byte(`{}`))
		if err != nil || o.Path != "/model/new/invoke" || o.SetQuery {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("vertex stream and sync", func(t *testing.T) {
		const base = "/v1/projects/proj/locations/us-east5/publishers/anthropic/models/claude-opus-4-1@20250805"
		o, err := BuildOutbound(ProtoAnthropic, vertex, "claude-opus-4-1@20250805", PathMessages, msg)
		if err != nil || o.Path != base+":streamRawPredict" {
			t.Fatalf("%+v %v", o, err)
		}
		if jsonField(t, o.Body, "model") != nil || jsonField(t, o.Body, "stream") != true || jsonField(t, o.Body, "anthropic_version") != "vertex-2023-10-16" {
			t.Fatalf("body %s", o.Body)
		}
		if o, err = BuildOutbound(ProtoAnthropic, vertex, "claude-opus-4-1@20250805", PathMessages, sync); err != nil || o.Path != base+":rawPredict" {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("azure", func(t *testing.T) {
		body := []byte(`{"model":"gpt","input":"hi"}`)
		o, err := BuildOutbound(ProtoResponses, policy.Upstream{Kind: "azure-openai"}, "my-deploy", PathResponses, body)
		if err != nil || o.Path != "/openai/v1/responses" || jsonField(t, o.Body, "model") != "my-deploy" {
			t.Fatalf("%+v %v", o, err)
		}
		o, err = BuildOutbound(ProtoResponses, policy.Upstream{Kind: "azure-openai", APIVersion: "2025-04-01-preview"}, "d", PathResponses, body)
		if err != nil || o.Path != "/openai/responses" || o.RawQuery != "api-version=2025-04-01-preview" {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("openai stays responses", func(t *testing.T) {
		o, err := BuildOutbound(ProtoResponses, policy.Upstream{Kind: "openai"}, "gpt-5", PathResponses, []byte(`{"model":"x"}`))
		if err != nil || o.Path != PathResponses || o.SetQuery || jsonField(t, o.Body, "model") != "gpt-5" {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("errors", func(t *testing.T) {
		for name, c := range map[string]struct {
			proto string
			up    policy.Upstream
			path  string
			body  string
		}{
			"vertex for responses client": {ProtoResponses, vertex, PathResponses, `{}`},
			"azure for anthropic client":  {ProtoAnthropic, policy.Upstream{Kind: "azure-openai"}, PathMessages, `{}`},
			"count_tokens to bedrock":     {ProtoAnthropic, policy.Upstream{Kind: "bedrock"}, PathCountTokens, `{}`},
			"bad json to vertex":          {ProtoAnthropic, vertex, PathMessages, `[`},
			"vertex without project":      {ProtoAnthropic, policy.Upstream{Kind: "vertex", Region: "global"}, PathMessages, `{}`},
		} {
			if _, err := BuildOutbound(c.proto, c.up, "m", c.path, []byte(c.body)); err == nil {
				t.Errorf("%s: want error", name)
			}
		}
	})
}

// frame builds one AWS event-stream message with string headers.
func frame(hdrs [][2]string, payload []byte) []byte {
	var h bytes.Buffer
	for _, kv := range hdrs {
		h.WriteByte(byte(len(kv[0])))
		h.WriteString(kv[0])
		h.WriteByte(7)
		_ = binary.Write(&h, binary.BigEndian, uint16(len(kv[1])))
		h.WriteString(kv[1])
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(16+h.Len()+len(payload)))
	_ = binary.Write(&b, binary.BigEndian, uint32(h.Len()))
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(b.Bytes()))
	b.Write(h.Bytes())
	b.Write(payload)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(b.Bytes()))
	return b.Bytes()
}

func chunk(event string) []byte {
	p, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(event))})
	return frame([][2]string{{":event-type", "chunk"}, {":message-type", "event"}}, p)
}

func TestEventStreamToSSE(t *testing.T) {
	in := bytes.Join([][]byte{
		chunk(`{"type":"message_start","message":{"id":"m"}}`),
		chunk(`{"type":"content_block_delta","delta":{"text":"hi"}}`),
		frame([][2]string{{":message-type", "exception"}, {":exception-type", "throttlingException"}}, []byte("slow down")),
	}, nil)
	got, err := io.ReadAll(EventStreamToSSE(io.NopCloser(bytes.NewReader(in))))
	if err != nil {
		t.Fatal(err)
	}
	want := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n"
	if !strings.HasPrefix(string(got), want) || !strings.Contains(string(got), "event: error") || !strings.Contains(string(got), "throttlingException") {
		t.Fatalf("got:\n%s", got)
	}

	// A corrupted frame is an error, never silently passed through.
	bad := chunk(`{"type":"ping"}`)
	bad[len(bad)-1] ^= 0xff
	if _, err := io.ReadAll(EventStreamToSSE(io.NopCloser(bytes.NewReader(bad)))); err == nil {
		t.Fatal("checksum mismatch must error")
	}
}
