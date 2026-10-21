package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/dshakes/halos/internal/budget"
)

// esFrame encodes one AWS event stream frame with a single string header.
func esFrame(eventType string, payload []byte) []byte {
	var h bytes.Buffer
	name := ":event-type"
	h.WriteByte(byte(len(name)))
	h.WriteString(name)
	h.WriteByte(7)
	_ = binary.Write(&h, binary.BigEndian, uint16(len(eventType)))
	h.WriteString(eventType)
	total := 12 + h.Len() + len(payload) + 4
	var f bytes.Buffer
	_ = binary.Write(&f, binary.BigEndian, uint32(total))
	_ = binary.Write(&f, binary.BigEndian, uint32(h.Len()))
	_ = binary.Write(&f, binary.BigEndian, crc32.ChecksumIEEE(f.Bytes()))
	f.Write(h.Bytes())
	f.Write(payload)
	_ = binary.Write(&f, binary.BigEndian, crc32.ChecksumIEEE(f.Bytes()))
	return f.Bytes()
}

func invokeChunk(event string) []byte {
	b, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(event))})
	return esFrame("chunk", b)
}

func TestUsageTap(t *testing.T) {
	long := strings.Repeat("x", 2<<20) // > usageMaxLine and > usageTail
	tests := []struct {
		name, proto, ctype, body string
		want                     budget.Usage
		ok                       bool
	}{
		{"anthropic json", ProtoAnthropic, "application/json",
			`{"id":"m","content":[{"type":"tool_use","input":{"usage":{"input_tokens":999}}}],"usage":{"input_tokens":12,"output_tokens":34,"cache_read_input_tokens":5,"cache_creation_input_tokens":6}}`,
			budget.Usage{Input: 12, Output: 34, CacheRead: 5, CacheWrite: 6}, true},
		{"anthropic sse", ProtoAnthropic, "text/event-stream; charset=utf-8",
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"output_tokens\":1,\"cache_read_input_tokens\":40}}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"\\\"usage\\\": {\\\"output_tokens\\\": 1000000}\"}}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":250}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			budget.Usage{Input: 100, Output: 250, CacheRead: 40}, true},
		{"anthropic sse crlf and huge delta", ProtoAnthropic, "text/event-stream",
			"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":1}}}\r\n\r\n" +
				"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"" + long + "\"}}\r\n\r\n" +
				"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}",
			budget.Usage{Input: 7, Output: 9}, true},
		{"responses sse", ProtoResponses, "text/event-stream",
			"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\n" +
				"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"text\":\"" + long + "\"}],\"usage\":{\"input_tokens\":1000,\"input_tokens_details\":{\"cached_tokens\":800},\"output_tokens\":70,\"output_tokens_details\":{\"reasoning_tokens\":30}},\"user\":null}}\n\n",
			budget.Usage{Input: 200, Output: 70, CacheRead: 800}, true},
		{"responses json", ProtoResponses, "application/json",
			`{"id":"r","output":[],"usage":{"input_tokens":10,"output_tokens":3},"metadata":{}}`,
			budget.Usage{Input: 10, Output: 3}, true},
		{"gemini sse", ProtoGemini, "text/event-stream",
			"data: {\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":50,\"candidatesTokenCount\":5}}\r\n\r\n" +
				"data: {\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":50,\"cachedContentTokenCount\":20,\"candidatesTokenCount\":40,\"thoughtsTokenCount\":15}}\r\n\r\n",
			budget.Usage{Input: 30, Output: 55, CacheRead: 20}, true},
		{"gemini json array stream", ProtoGemini, "application/json",
			`[{"candidates":[],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":1}},{"candidates":[],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":4}}]`,
			budget.Usage{Input: 9, Output: 4}, true},
		{"bedrock invoke json", ProtoBedrock, "application/json",
			`{"content":[],"usage":{"input_tokens":3,"output_tokens":4}}`, budget.Usage{Input: 3, Output: 4}, true},
		{"bedrock converse json", ProtoBedrock, "application/json",
			`{"output":{},"usage":{"inputTokens":11,"outputTokens":22,"cacheReadInputTokens":3,"cacheWriteInputTokens":4,"totalTokens":40}}`,
			budget.Usage{Input: 11, Output: 22, CacheRead: 3, CacheWrite: 4}, true},
		{"bedrock invoke stream", ProtoBedrock, "application/vnd.amazon.eventstream",
			string(invokeChunk(`{"type":"message_start","message":{"usage":{"input_tokens":21,"output_tokens":1}}}`)) +
				string(invokeChunk(`{"type":"message_delta","usage":{"output_tokens":13}}`)) +
				string(invokeChunk(`{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":21,"outputTokenCount":13}}`)),
			budget.Usage{Input: 21, Output: 13}, true},
		{"bedrock converse stream", ProtoBedrock, "application/vnd.amazon.eventstream",
			string(esFrame("contentBlockDelta", []byte(`{"delta":{"text":"hi"}}`))) +
				string(esFrame("metadata", []byte(`{"usage":{"inputTokens":8,"outputTokens":2},"metrics":{"latencyMs":5}}`))),
			budget.Usage{Input: 8, Output: 2}, true},
		{"no usage", ProtoAnthropic, "application/json", `{"type":"error","error":{"type":"overloaded_error"}}`, budget.Usage{}, false},
		{"usage null only", ProtoResponses, "text/event-stream", "data: {\"response\":{\"usage\":null}}\n\n", budget.Usage{}, false},
		{"negative counts clamp", ProtoResponses, "application/json", `{"usage":{"input_tokens":5,"input_tokens_details":{"cached_tokens":9},"output_tokens":-3}}`,
			budget.Usage{Input: 0, Output: 0, CacheRead: 9}, true},
		{"corrupt event stream", ProtoBedrock, "application/vnd.amazon.eventstream", "\x00\x00\x00\x01garbage-frame-bytes", budget.Usage{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, chunked := range []bool{false, true} {
				var src io.Reader = strings.NewReader(tt.body)
				if chunked {
					src = iotest.OneByteReader(src)
				}
				calls := 0
				var got budget.Usage
				var ok bool
				tap := UsageTap(tt.proto, tt.ctype, io.NopCloser(src), func(u budget.Usage, found bool) { calls++; got, ok = u, found })
				out, err := io.ReadAll(tap)
				if err != nil {
					t.Fatal(err)
				}
				_ = tap.Close()
				if string(out) != tt.body {
					t.Fatal("tap changed the body")
				}
				if calls != 1 || ok != tt.ok || got != tt.want {
					t.Fatalf("chunked=%v: calls=%d ok=%v usage=%+v, want ok=%v %+v", chunked, calls, ok, got, tt.ok, tt.want)
				}
			}
		})
	}
}

// A client that goes away mid-stream still charges what was already reported.
func TestUsageTapCloseBeforeEOF(t *testing.T) {
	body := "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":500,\"output_tokens\":1}}}\n\ndata: {\"type\":\"content_block_delta\"}\n\n"
	var got budget.Usage
	var ok bool
	tap := UsageTap(ProtoAnthropic, "text/event-stream", io.NopCloser(strings.NewReader(body)), func(u budget.Usage, found bool) { got, ok = u, found })
	buf := make([]byte, 90)
	if _, err := io.ReadFull(tap, buf); err != nil {
		t.Fatal(err)
	}
	_ = tap.Close()
	_ = tap.Close()
	if !ok || got.Input != 500 {
		t.Fatalf("partial stream: ok=%v %+v", ok, got)
	}

	// An upstream read error ends the body too.
	calls := 0
	tap = UsageTap(ProtoAnthropic, "application/json", io.NopCloser(iotest.ErrReader(errors.New("reset"))), func(budget.Usage, bool) { calls++ })
	if _, err := io.ReadAll(tap); err == nil {
		t.Fatal("want read error")
	}
	_ = tap.Close()
	if calls != 1 {
		t.Fatalf("done called %d times", calls)
	}
}

func TestRejectionQuota(t *testing.T) {
	for _, tc := range []struct{ proto, want string }{
		{ProtoAnthropic, `{"error":{"message":"m","type":"rate_limit_error"},"type":"error"}`},
		{ProtoResponses, `{"error":{"code":"insufficient_quota","message":"m","param":null,"type":"insufficient_quota"}}`},
		{ProtoGemini, `{"error":{"code":429,"message":"m","status":"RESOURCE_EXHAUSTED"}}`},
		{ProtoBedrock, `{"message":"m"}`},
	} {
		r := &Rejection{Status: http.StatusTooManyRequests, Protocol: tc.proto, Message: "m", RetryAfter: 1500 * 1e6}
		if got := string(r.JSON()); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.proto, got, tc.want)
		}
		h := http.Header{}
		r.SetHeaders(h)
		if h.Get("Retry-After") != "2" {
			t.Errorf("%s: Retry-After %q, want 2 (rounded up)", tc.proto, h.Get("Retry-After"))
		}
		if want := map[bool]string{true: "ThrottlingException"}[tc.proto == ProtoBedrock]; h.Get("X-Amzn-ErrorType") != want {
			t.Errorf("%s: x-amzn-ErrorType %q", tc.proto, h.Get("X-Amzn-ErrorType"))
		}
	}
	h := http.Header{}
	(&Rejection{Status: http.StatusForbidden, Protocol: ProtoBedrock}).SetHeaders(h)
	if len(h) != 0 {
		t.Fatalf("a 403 without RetryAfter set headers: %v", h)
	}
}
