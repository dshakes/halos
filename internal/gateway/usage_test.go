package gateway

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
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
				var ok, complete bool
				tap := UsageTap(tt.proto, tt.ctype, "", io.NopCloser(src), func(r UsageResult) { calls++; got, ok, complete = r.Usage, r.Found, r.Complete })
				out, err := io.ReadAll(tap)
				if err != nil {
					t.Fatal(err)
				}
				_ = tap.Close()
				if string(out) != tt.body {
					t.Fatal("tap changed the body")
				}
				// read to EOF: complete exactly when usage was found
				if calls != 1 || ok != tt.ok || complete != tt.ok || got != tt.want {
					t.Fatalf("chunked=%v: calls=%d ok=%v complete=%v usage=%+v, want ok=%v %+v", chunked, calls, ok, complete, got, tt.ok, tt.want)
				}
			}
		})
	}
}

// A client that goes away mid-stream keeps what was already reported, but
// the result is not Complete: the caller must estimate, not trust it.
func TestUsageTapCloseBeforeEOF(t *testing.T) {
	body := "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":500,\"output_tokens\":1}}}\n\ndata: {\"type\":\"content_block_delta\"}\n\n"
	var got UsageResult
	tap := UsageTap(ProtoAnthropic, "text/event-stream", "", io.NopCloser(strings.NewReader(body)), func(r UsageResult) { got = r })
	buf := make([]byte, 90)
	if _, err := io.ReadFull(tap, buf); err != nil {
		t.Fatal(err)
	}
	_ = tap.Close()
	_ = tap.Close()
	if !got.Found || got.Complete || got.Usage.Input != 500 || got.Bytes != 90 {
		t.Fatalf("partial stream: %+v", got)
	}

	// An upstream read error ends the body too, incomplete.
	calls := 0
	tap = UsageTap(ProtoAnthropic, "application/json", "", io.NopCloser(iotest.ErrReader(errors.New("reset"))), func(r UsageResult) { calls++; got = r })
	if _, err := io.ReadAll(tap); err == nil {
		t.Fatal("want read error")
	}
	_ = tap.Close()
	if calls != 1 || got.Complete {
		t.Fatalf("done called %d times, %+v", calls, got)
	}
}

// Every way a metered stream can end without its final usage is incomplete:
// a client hanging up after OpenAI's output_text.done (usage only arrives in
// response.completed), an upstream cut, an Anthropic stream closed after
// message_start.
func TestUsageTapIncomplete(t *testing.T) {
	responses := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"" + strings.Repeat("y", 3000) + "\"}\n\n" +
		"event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\"}\n\n"
	completed := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":900}}}\n\n"
	for _, tc := range []struct {
		name     string
		src      io.Reader
		closeAt  int // bytes read before Close; -1 = read to the end
		found    bool
		complete bool
	}{
		{"responses closed at output_text.done", strings.NewReader(responses + completed), len(responses), false, false},
		{"responses read to the end", strings.NewReader(responses + completed), -1, true, true},
		{"upstream cut", io.MultiReader(strings.NewReader(responses), iotest.ErrReader(io.ErrUnexpectedEOF)), -1, false, false},
		{"clean EOF, no usage", strings.NewReader(responses), -1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got UsageResult
			tap := UsageTap(ProtoResponses, "text/event-stream", "", io.NopCloser(tc.src), func(r UsageResult) { got = r })
			if tc.closeAt >= 0 {
				if _, err := io.ReadFull(tap, make([]byte, tc.closeAt)); err != nil {
					t.Fatal(err)
				}
			} else {
				_, _ = io.ReadAll(tap)
			}
			_ = tap.Close()
			if got.Found != tc.found || got.Complete != tc.complete || got.Bytes < int64(len(responses)) {
				t.Fatalf("%+v", got)
			}
		})
	}
}

// gzip and deflate bodies are decompressed for the scan only; an encoding
// the stdlib cannot decode (br) is never Complete, so it is estimated.
func TestUsageTapContentEncoding(t *testing.T) {
	body := "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":70,\"output_tokens\":1}}}\n\n" +
		"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":30}}\n\n"
	gz := func(b []byte) []byte {
		var w bytes.Buffer
		z := gzip.NewWriter(&w)
		_, _ = z.Write(b)
		_ = z.Close()
		return w.Bytes()
	}
	zl := func(b []byte) []byte {
		var w bytes.Buffer
		z := zlib.NewWriter(&w)
		_, _ = z.Write(b)
		_ = z.Close()
		return w.Bytes()
	}
	full := budget.Usage{Input: 70, Output: 30}
	for _, tc := range []struct {
		name, enc string
		wire      []byte
		closeAt   int // -1 = read to the end
		want      budget.Usage
		complete  bool
	}{
		{"gzip", "gzip", gz([]byte(body)), -1, full, true},
		{"x-gzip upper case", "X-GZIP", gz([]byte(body)), -1, full, true},
		{"deflate", "deflate", zl([]byte(body)), -1, full, true},
		{"gzip closed early", "gzip", gz([]byte(body)), 10, budget.Usage{}, false},
		{"gzip truncated by upstream", "gzip", gz([]byte(body))[:40], -1, budget.Usage{}, false},
		{"not actually gzip", "gzip", []byte(body), -1, budget.Usage{}, false},
		{"br", "br", []byte("\x1b\x00\x00"), -1, budget.Usage{}, false},
		{"identity", "identity", []byte(body), -1, full, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, chunked := range []bool{false, true} {
				var src io.Reader = bytes.NewReader(tc.wire)
				if chunked {
					src = iotest.OneByteReader(src)
				}
				calls := 0
				var got UsageResult
				tap := UsageTap(ProtoAnthropic, "text/event-stream", tc.enc, io.NopCloser(src), func(r UsageResult) { calls++; got = r })
				var out []byte
				if tc.closeAt >= 0 {
					out = make([]byte, tc.closeAt)
					if _, err := io.ReadFull(tap, out); err != nil {
						t.Fatal(err)
					}
				} else {
					out, _ = io.ReadAll(tap)
					if !bytes.Equal(out, tc.wire) {
						t.Fatal("tap changed the body")
					}
				}
				_ = tap.Close()
				if calls != 1 || got.Complete != tc.complete || (tc.complete && got.Usage != tc.want) {
					t.Fatalf("chunked=%v: calls=%d %+v", chunked, calls, got)
				}
			}
		})
	}
}

func TestEstimateUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    UsageResult
		e    Estimate
		want budget.Usage
	}{
		{"nothing seen: request bytes / 3, response bytes / 4", UsageResult{Bytes: 4000}, Estimate{RequestBytes: 900}, budget.Usage{Input: 300, Output: 1000}},
		{"capped at max tokens", UsageResult{Bytes: 4000}, Estimate{RequestBytes: 900, MaxOutput: 64}, budget.Usage{Input: 300, Output: 64}},
		{"message_start input wins over request bytes", UsageResult{Usage: budget.Usage{Input: 500, CacheRead: 40, Output: 1}, Found: true, Bytes: 40}, Estimate{RequestBytes: 900},
			budget.Usage{Input: 500, CacheRead: 40, Output: 10}},
		{"reported output beats the byte guess and the cap", UsageResult{Usage: budget.Usage{Input: 5, Output: 200}, Found: true, Bytes: 30}, Estimate{RequestBytes: 9, MaxOutput: 100},
			budget.Usage{Input: 5, Output: 200}},
		{"never zero", UsageResult{}, Estimate{}, budget.Usage{Input: 1}},
		// A cut stream is charged its decoded output text, not its SSE framing.
		{"stream: delta text / 4", UsageResult{Streamed: true, Bytes: 1 << 20, OutputText: 4000, OutputEvents: 300}, Estimate{RequestBytes: 30}, budget.Usage{Input: 10, Output: 1000}},
		{"stream: at least a token per delta", UsageResult{Streamed: true, Bytes: 1 << 20, OutputText: 400, OutputEvents: 300}, Estimate{RequestBytes: 30}, budget.Usage{Input: 10, Output: 300}},
		{"stream: no deltas yet", UsageResult{Streamed: true, Bytes: 500}, Estimate{RequestBytes: 30}, budget.Usage{Input: 10}},
		// An inflated body without max tokens is capped at the ceiling.
		{"default ceiling", UsageResult{Bytes: 256 << 20}, Estimate{RequestBytes: 30}, budget.Usage{Input: 10, Output: DefaultOutputCeiling}},
		{"configured ceiling", UsageResult{Bytes: 256 << 20}, Estimate{RequestBytes: 30, OutputCeiling: 8000}, budget.Usage{Input: 10, Output: 8000}},
		// Server-side state is charged a worst case, not request bytes / 3.
		{"server state", UsageResult{Bytes: 40}, Estimate{RequestBytes: 300, ServerStateInput: 200_000}, budget.Usage{Input: 200_000, Output: 10}},
		{"server state, input partly reported", UsageResult{Usage: budget.Usage{Input: 50, CacheRead: 150_000}, Found: true}, Estimate{ServerStateInput: 200_000},
			budget.Usage{Input: 50_000, CacheRead: 150_000}},
		{"reported input above the server state charge", UsageResult{Usage: budget.Usage{Input: 300_000}, Found: true}, Estimate{ServerStateInput: 200_000},
			budget.Usage{Input: 300_000}},
	} {
		if got := EstimateUsage(tc.r, tc.e); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestServerStateInput(t *testing.T) {
	for _, tc := range []struct {
		proto, body string
		want        bool
	}{
		{ProtoResponses, `{"model":"m","previous_response_id":"resp_1","input":"hi"}`, true},
		{ProtoResponses, `{"model":"m","conversation":"conv_1","input":"hi"}`, true},
		{ProtoResponses, `{"model":"m","conversation":{"id":"conv_1"},"input":"hi"}`, true},
		{ProtoResponses, `{"model":"m","prompt":{"id":"pmpt_1","version":"2"}}`, true},
		{ProtoResponses, `{"model":"m","input":"hi"}`, false},
		{ProtoResponses, `{"model":"m","previous_response_id":"","conversation":null,"prompt":{}}`, false},
		{ProtoResponses, `not json`, false},
		{ProtoAnthropic, `{"previous_response_id":"resp_1"}`, false},
		// Inputs the provider fetches or stores, billed as input the body never carries.
		{ProtoResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_id":"file-1"}]}]}`, true},
		{ProtoResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_url":"https://x/a.pdf"}]}]}`, true},
		{ProtoResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_data":"data:application/pdf;base64,AA"}]}]}`, false},
		{ProtoResponses, `{"input":[{"role":"user","content":[{"type":"input_image","file_id":"file-2"}]}]}`, true},
		{ProtoResponses, `{"input":[{"role":"user","content":[{"type":"input_image","image_url":"HTTPS://x/a.png"}]}]}`, true},
		{ProtoResponses, `{"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,AA"}]}]}`, false},
		{ProtoResponses, `{"input":[{"type":"item_reference","id":"msg_1"}]}`, true},
		{ProtoResponses, `{"input":"hi","tools":[{"type":"file_search","vector_store_ids":["vs_1"]}]}`, true},
		{ProtoResponses, `{"input":"hi","tools":[{"type":"web_search_preview"}]}`, true},
		{ProtoResponses, `{"input":"hi","tools":[{"type":"mcp","server_url":"https://m"}]}`, true},
		{ProtoResponses, `{"input":"hi","tools":[{"type":"code_interpreter"}]}`, true},
		{ProtoResponses, `{"input":"hi","tools":[{"type":"function","name":"f"}]}`, false},
		{ProtoResponses, `{"input":"hi","background":true}`, true},
		{ProtoAnthropic, `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"web_search_20250305","name":"web_search"}]}`, true},
		{ProtoAnthropic, `{"messages":[],"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}`, true},
		{ProtoBedrock, `{"messages":[],"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}`, true},
		{ProtoAnthropic, `{"messages":[],"tools":[{"name":"get_weather","input_schema":{}}]}`, false},
		{ProtoAnthropic, `{"messages":[],"mcp_servers":[{"type":"url","url":"https://m","name":"m"}]}`, true},
		{ProtoAnthropic, `{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_1"}}]}]}`, true},
		{ProtoAnthropic, `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x/a.png"}}]}]}`, true},
		{ProtoAnthropic, `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA"}}]}]}`, false},
		{ProtoAnthropic, `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"document","source":{"type":"url","url":"https://x"}}]}]}]}`, true},
	} {
		if got := ServerStateInput(tc.proto, []byte(tc.body)); got != tc.want {
			t.Errorf("%s %s: %v, want %v", tc.proto, tc.body, got, tc.want)
		}
	}
}

// A client that hangs up before the final usage event (or a background
// request answered with usage null) is charged what the provider bills but
// the gateway never saw: the server-state input floor for remote inputs and
// server tools, the thinking budget (or the output limit) for hidden
// reasoning, and the output limit for background mode. End to end: cut
// response through the tap, then RequestEstimate and EstimateUsage.
func TestEstimateChargesUnseenTokens(t *testing.T) {
	const floor, ceiling = 150_000, 32_000
	cut := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":20,\"output_tokens\":1}}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi there\"}}\n\n"
	for _, tc := range []struct {
		name, proto, ct, resp, body string
		want                        budget.Usage
	}{
		{"anthropic web_search, cut", ProtoAnthropic, "text/event-stream", cut,
			`{"max_tokens":4000,"messages":[{"role":"user","content":"q"}],"tools":[{"type":"web_search_20250305","name":"web_search"}]}`,
			budget.Usage{Input: floor, Output: 2}},
		{"anthropic thinking budget, cut", ProtoAnthropic, "text/event-stream", cut,
			`{"max_tokens":20000,"thinking":{"type":"enabled","budget_tokens":16000},"messages":[{"role":"user","content":"q"}]}`,
			budget.Usage{Input: 20, Output: 16000}},
		{"anthropic thinking budget over max_tokens is capped", ProtoAnthropic, "text/event-stream", cut,
			`{"max_tokens":2000,"thinking":{"type":"enabled","budget_tokens":16000},"messages":[]}`,
			budget.Usage{Input: 20, Output: 2000}},
		{"anthropic adaptive thinking, no max: ceiling", ProtoAnthropic, "text/event-stream", cut,
			`{"thinking":{"type":"adaptive"},"messages":[]}`,
			budget.Usage{Input: 20, Output: ceiling}},
		{"anthropic effort, cut", ProtoAnthropic, "text/event-stream", cut,
			`{"max_tokens":9000,"output_config":{"effort":"high"},"messages":[]}`,
			budget.Usage{Input: 20, Output: 9000}},
		{"no reasoning, cut: text only", ProtoAnthropic, "text/event-stream", cut,
			`{"max_tokens":9000,"messages":[]}`,
			budget.Usage{Input: 20, Output: 2}},
		{"responses reasoning, cut", ProtoResponses, "text/event-stream",
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
			`{"input":"hi","max_output_tokens":12000,"reasoning":{"effort":"high"}}`,
			budget.Usage{Input: -1, Output: 12000}},
		{"responses reasoning effort none: text only", ProtoResponses, "text/event-stream",
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
			`{"input":"hi","max_output_tokens":12000,"reasoning":{"effort":"none"}}`,
			budget.Usage{Input: -1, Output: 1}},
		{"responses input_file, cut", ProtoResponses, "text/event-stream",
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
			`{"input":[{"role":"user","content":[{"type":"input_file","file_id":"file-1"}]}],"max_output_tokens":500}`,
			budget.Usage{Input: floor, Output: 1}},
		{"responses background, usage null", ProtoResponses, "application/json",
			`{"id":"resp_1","status":"queued","background":true,"usage":null}`,
			`{"input":"hi","background":true}`,
			budget.Usage{Input: floor, Output: ceiling}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r UsageResult
			rc := UsageTap(tc.proto, tc.ct, "", io.NopCloser(strings.NewReader(tc.resp)), func(u UsageResult) { r = u })
			_, _ = io.Copy(io.Discard, io.LimitReader(rc, int64(len(tc.resp))))
			_ = rc.Close()
			if r.Complete {
				t.Fatalf("fixture reports complete usage: %+v", r)
			}
			if tc.want.Input == -1 { // nothing reported: request bytes / 3
				tc.want.Input = int64(len(tc.body)) / 3
			}
			e := RequestEstimate(tc.proto, []byte(tc.body), floor, ceiling)
			if got := EstimateUsage(r, e); got != tc.want {
				t.Fatalf("%+v (estimate %+v), want %+v", got, e, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		proto, body string
		on          bool
		budget      int64
	}{
		{ProtoGemini, `{"generationConfig":{"thinkingConfig":{"thinkingBudget":8192}}}`, true, 8192},
		{ProtoGemini, `{"generationConfig":{"thinkingConfig":{"thinkingBudget":-1}}}`, true, 0},
		{ProtoGemini, `{"generationConfig":{"thinkingConfig":{"thinkingBudget":0}}}`, false, 0},
		{ProtoGemini, `{"generationConfig":{"maxOutputTokens":10}}`, false, 0},
		{ProtoBedrock, `{"additionalModelRequestFields":{"thinking":{"type":"enabled","budget_tokens":4000}}}`, true, 4000},
		{ProtoAnthropic, `{"thinking":{"type":"disabled"}}`, false, 0},
		{ProtoResponses, `{"reasoning":null}`, false, 0},
		{ProtoResponses, `{"reasoning":{}}`, true, 0},
	} {
		if on, b := ReasoningBudget(tc.proto, []byte(tc.body)); on != tc.on || b != tc.budget {
			t.Errorf("ReasoningBudget(%s, %s) = %v %d, want %v %d", tc.proto, tc.body, on, b, tc.on, tc.budget)
		}
	}
}

// The tap measures a stream's generated output from its delta payloads, per
// protocol, so a cut stream is not charged for SSE framing (about 10x the text).
func TestUsageTapOutputText(t *testing.T) {
	text := strings.Repeat("abcd", 25) // 100 bytes per delta
	for _, tc := range []struct {
		proto, ct, event string
	}{
		{ProtoAnthropic, "text/event-stream", `event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + text + `"}}`},
		{ProtoResponses, "text/event-stream", `event: response.output_text.delta` + "\n" + `data: {"type":"response.output_text.delta","item_id":"msg_0123456789abcdef","output_index":0,"content_index":0,"delta":"` + text + `"}`},
		{ProtoGemini, "text/event-stream", `data: {"candidates":[{"content":{"parts":[{"text":"` + text + `"}],"role":"model"},"index":0}],"modelVersion":"gemini-2.5-pro"}`},
	} {
		var body strings.Builder
		for range 50 {
			body.WriteString(tc.event + "\n\n")
		}
		var got UsageResult
		rc := UsageTap(tc.proto, tc.ct, "", io.NopCloser(strings.NewReader(body.String())), func(r UsageResult) { got = r })
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
		if !got.Streamed || got.OutputText != 50*100 || got.OutputEvents != 50 || got.Complete {
			t.Errorf("%s: %+v, want 5000 bytes of output text in 50 events", tc.proto, got)
		}
		if u := EstimateUsage(got, Estimate{RequestBytes: 30}); u.Output != 50*100/4 {
			t.Errorf("%s: output estimate %d, want %d (text / 4, not wire bytes %d / 3)", tc.proto, u.Output, 50*100/4, got.Bytes)
		}
	}
}

func TestMaxOutputTokens(t *testing.T) {
	for body, want := range map[string]int64{
		`{"model":"m","max_tokens":32000,"messages":[]}`:           32000,
		`{"model":"m","max_output_tokens":4096,"input":"x"}`:       4096,
		`{"contents":[],"generationConfig":{"maxOutputTokens":8}}`: 8,
		`{"messages":[],"inferenceConfig":{"maxTokens":512}}`:      512,
		`{"model":"m","input":"x"}`:                                0,
		`{"max_tokens":-5}`:                                        0,
		`not json`:                                                 0,
	} {
		if got := MaxOutputTokens([]byte(body)); got != want {
			t.Errorf("%s: %d, want %d", body, got, want)
		}
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
