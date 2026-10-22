package gateway

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"
	"sync"

	"github.com/dshakes/halos/internal/budget"
)

// Usage scanning bounds: memory per response stays under ~1 MiB however
// large the response or a single event is.
const (
	usageTail     = 64 << 10 // usage objects sit at the end of a body or event
	usageMaxLine  = 1 << 20  // longer SSE lines keep only their tail
	usageMaxFrame = 1 << 20  // larger AWS event stream frames stop the scan
	// usageMaxInflated bounds how much of a compressed body is decompressed for
	// the scan; past it the response is charged by estimate.
	usageMaxInflated = 256 << 20
)

// UsageResult is what a UsageTap saw by the time its body ended.
type UsageResult struct {
	Usage budget.Usage // field-wise maximum over every usage object read
	Found bool         // at least one usage object was read
	// Complete: the upstream body reached its clean end (EOF) and a usage
	// object was read, so Usage is the provider's final count. A client that
	// hangs up early, an upstream cut, a Content-Encoding the tap cannot decode
	// or a body without usage leave it false: charge EstimateUsage instead.
	Complete bool
	Bytes    int64 // response bytes seen (decoded bytes when the tap decoded them)
	// Streamed: the body was an SSE or AWS event stream the tap decoded, so
	// OutputText and OutputEvents measure the generated output.
	Streamed bool
	// OutputText is the UTF-8 bytes of generated output (text, thinking, tool
	// arguments) in the stream's delta events, without framing or JSON
	// escaping; OutputEvents counts those events.
	OutputText, OutputEvents int64
}

// UsageTap wraps a model response body in the caller's wire protocol and
// reports its token usage once the body ends (EOF, read error or Close),
// exactly once. It never changes the bytes the client receives. A body with
// Content-Encoding gzip or deflate is decompressed for the scan only, by a
// goroutine that exits when the body ends (the caller must Close it); any
// other encoding is not scanned and reports Complete false.
//
// The response is scanned as it streams: SSE line by line (Anthropic
// message_start/message_delta, OpenAI response.completed, Gemini chunks), an
// AWS event stream frame by frame (Bedrock invoke/converse streams), or, for
// a plain JSON body, its last 64 KiB. Counts merge by maximum, since every
// wire reports cumulative totals.
func UsageTap(proto, contentType, contentEncoding string, rc io.ReadCloser, done func(UsageResult)) io.ReadCloser {
	mt, _, _ := mime.ParseMediaType(contentType)
	t := &usageTap{src: rc, proto: proto, done: done, key: []byte(`"usage"`)}
	if proto == ProtoGemini {
		t.key = []byte(`"usageMetadata"`)
	}
	switch mt {
	case "text/event-stream":
		t.mode = tapSSE
	case "application/vnd.amazon.eventstream":
		t.mode = tapEventStream
	}
	switch enc := strings.ToLower(strings.TrimSpace(contentEncoding)); enc {
	case "", "identity":
	case "gzip", "x-gzip", "deflate":
		t.inflate(enc)
	default: // br, zstd, stacked encodings: no stdlib decoder
		t.opaque = true
	}
	return t
}

const (
	tapJSON = iota
	tapSSE
	tapEventStream
)

type usageTap struct {
	src   io.ReadCloser
	proto string
	mode  int
	n     int64 // raw bytes read
	eof   bool  // src ended with io.EOF
	// opaque: an encoding the tap cannot decode; nothing is scanned.
	opaque bool
	// pw feeds the decompressing goroutine (gzip/deflate). inflated closes
	// when it exits; only then are the scan state, decoded and inflateOK
	// readable by anyone else.
	pw        *io.PipeWriter
	inflated  chan struct{}
	decoded   int64
	inflateOK bool

	key   []byte
	buf   []byte   // JSON: body tail; SSE: current line; event stream: partial frame
	stop  bool     // event stream framing lost: stop scanning
	raw   rawUsage // field-wise maximum over every usage object seen
	found bool
	cut   bool // SSE: the current line outgrew usageMaxLine and lost its head
	// text and deltas measure generated output in streamed events (outputEvent).
	text, deltas int64
	once         sync.Once
	done         func(UsageResult)
}

var errTapDone = errors.New("usage tap: body ended")

// inflate scans the body through a decompressor in its own goroutine. Read
// hands it each chunk through a pipe (Write returns once it is consumed), so
// the scan state is only touched by that goroutine until finish waits for it.
func (t *usageTap) inflate(enc string) {
	pr, pw := io.Pipe()
	t.pw, t.inflated = pw, make(chan struct{})
	go func() {
		defer close(t.inflated)
		var zr io.Reader
		var err error
		if enc == "deflate" {
			zr, err = zlib.NewReader(pr)
		} else {
			zr, err = gzip.NewReader(pr)
		}
		if err == nil {
			buf := make([]byte, 32<<10)
			for {
				n, rerr := zr.Read(buf)
				if n > 0 {
					t.feed(buf[:n])
					if t.decoded += int64(n); t.decoded > usageMaxInflated {
						rerr = errors.New("usage tap: decompressed body too large")
					}
				}
				if rerr != nil {
					if rerr != io.EOF {
						err = rerr
					}
					break
				}
			}
		}
		t.inflateOK = err == nil
		pr.CloseWithError(errTapDone) // later writes fail fast instead of blocking
	}()
}

func (t *usageTap) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n > 0 {
		t.n += int64(n)
		switch {
		case t.pw != nil:
			_, _ = t.pw.Write(p[:n]) // fails only once the decompressor has stopped
		case !t.opaque:
			t.feed(p[:n])
		}
	}
	if err != nil {
		t.eof = err == io.EOF
		t.finish()
	}
	return n, err
}

func (t *usageTap) Close() error {
	t.finish()
	return t.src.Close()
}

func (t *usageTap) finish() {
	t.once.Do(func() {
		decodedOK := !t.opaque
		if t.pw != nil {
			if t.eof {
				_ = t.pw.Close()
			} else {
				_ = t.pw.CloseWithError(io.ErrUnexpectedEOF)
			}
			<-t.inflated
			decodedOK = t.inflateOK
		}
		if t.mode == tapJSON || t.mode == tapSSE { // a final SSE line may lack its newline
			t.scan(t.buf)
		}
		t.buf = nil
		t.done(UsageResult{Usage: t.raw.normalise(t.proto), Found: t.found, Complete: t.eof && t.found && decodedOK, Bytes: max(t.n, t.decoded),
			Streamed: decodedOK && t.mode != tapJSON, OutputText: t.text, OutputEvents: t.deltas})
	})
}

// Estimate defaults.
const (
	// DefaultOutputCeiling caps the output estimate of a request that sets no
	// maximum output tokens: no supported model generates more in one call.
	DefaultOutputCeiling = 128_000
	// DefaultServerStateInputTokens is the input charged, when final usage is
	// missing, for a request that names server-side state (ServerStateInput):
	// a full long-context window, since its real size is invisible here.
	DefaultServerStateInputTokens = 200_000
)

// Estimate is what EstimateUsage knows about the request (RequestEstimate).
type Estimate struct {
	RequestBytes int
	// MaxOutput is the request's maximum output tokens (MaxOutputTokens); 0 = none.
	MaxOutput int64
	// OutputCeiling caps the output estimate when MaxOutput is 0 (0 = DefaultOutputCeiling).
	OutputCeiling int64
	// ServerStateInput is the input to charge when the request makes the
	// provider bill input its bytes do not show (ServerStateInput true); 0 = it does not.
	ServerStateInput int64
	// Reasoning: the request enables hidden reasoning (ReasoningBudget), so
	// the output estimate is at least ThinkingBudget, or the output limit when
	// ThinkingBudget is 0: reasoning tokens are billed as output but never
	// streamed, so a stream cut before the final usage event shows none of them.
	Reasoning      bool
	ThinkingBudget int64
	// Background: an OpenAI Responses background request; its response is
	// queued (usage null), so the output is charged at the limit.
	Background bool
}

// RequestEstimate is the Estimate for a metered request body: maximum output,
// server-side state (charged serverStateInput, else
// DefaultServerStateInputTokens), reasoning and background mode.
func RequestEstimate(proto string, body []byte, serverStateInput, outputCeiling int64) Estimate {
	e := Estimate{RequestBytes: len(body), MaxOutput: MaxOutputTokens(body), OutputCeiling: outputCeiling, Background: Background(proto, body)}
	if ServerStateInput(proto, body) {
		e.ServerStateInput = cmp.Or(serverStateInput, DefaultServerStateInputTokens)
	}
	e.Reasoning, e.ThinkingBudget = ReasoningBudget(proto, body)
	return e
}

// EstimateUsage is the pessimistic charge for a metered 2xx response whose
// final usage was not read (r.Complete false), so hanging up before the last
// event never makes a call free:
//
//   - input as reported so far (Anthropic's message_start), else request
//     bytes / 3; at least e.ServerStateInput when the request names
//     server-side state, whose size the request bytes do not show;
//   - output the larger of the output reported so far and a measure of what
//     was generated: for a decoded stream the delta payload text / 4 (at least
//     one token per delta event), so SSE framing and JSON escaping are not
//     charged; otherwise response bytes / 4. With reasoning on, at least the
//     thinking budget (else the limit); in background mode the limit. Capped
//     at the request's maximum output tokens, else e.OutputCeiling;
//   - never zero.
func EstimateUsage(r UsageResult, e Estimate) budget.Usage {
	u := r.Usage
	if u.Input+u.CacheRead+u.CacheWrite == 0 {
		u.Input = int64(e.RequestBytes) / 3
	}
	if in := u.Input + u.CacheRead + u.CacheWrite; e.ServerStateInput > in {
		u.Input += e.ServerStateInput - in
	}
	gen := r.Bytes / 4
	if r.Streamed {
		gen = max(r.OutputText/4, r.OutputEvents)
	}
	limit := e.MaxOutput
	if limit <= 0 {
		limit = e.OutputCeiling
	}
	if limit <= 0 {
		limit = DefaultOutputCeiling
	}
	switch {
	case e.Background:
		gen = limit
	case e.Reasoning && e.ThinkingBudget > 0:
		gen = max(gen, e.ThinkingBudget)
	case e.Reasoning:
		gen = limit
	}
	u.Output = max(min(gen, limit), u.Output)
	if u.Tokens() == 0 {
		u.Input = 1
	}
	return u
}

// ServerStateInput reports whether a request makes the provider bill input
// tokens the request body does not carry, so request bytes underestimate it:
//
//   - OpenAI Responses: previous_response_id, conversation, a stored prompt
//     id, background mode, input_file by file_id or file_url, input_image by
//     file_id or an http(s) URL, item_reference, and the file_search,
//     web_search*, mcp and code_interpreter tools;
//   - Anthropic Messages (and Bedrock invoke): server tools (web_search,
//     web_fetch, code_execution, tool_search), MCP servers, container
//     uploads, and document or image blocks whose source is a file or a URL.
func ServerStateInput(proto string, body []byte) bool {
	switch proto {
	case ProtoResponses:
		return responsesServerState(body)
	case ProtoAnthropic, ProtoBedrock:
		return anthropicServerState(body)
	}
	return false
}

// setJSON reports whether a raw JSON value is present and not empty.
func setJSON(m json.RawMessage) bool {
	s := string(bytes.TrimSpace(m))
	return s != "" && s != "null" && s != `""` && s != "{}" && s != "[]"
}

type typed struct {
	Type string `json:"type"`
}

func responsesServerState(body []byte) bool {
	var r struct {
		Previous     string          `json:"previous_response_id"`
		Conversation json.RawMessage `json:"conversation"`
		Prompt       json.RawMessage `json:"prompt"`
		Background   bool            `json:"background"`
		Input        json.RawMessage `json:"input"`
		Tools        []typed         `json:"tools"`
	}
	if json.Unmarshal(body, &r) != nil {
		return false
	}
	if r.Previous != "" || setJSON(r.Conversation) || r.Background {
		return true
	}
	var p struct {
		ID string `json:"id"`
	}
	if setJSON(r.Prompt) && json.Unmarshal(r.Prompt, &p) == nil && p.ID != "" {
		return true
	}
	for _, t := range r.Tools {
		if t.Type == "file_search" || t.Type == "mcp" || t.Type == "code_interpreter" || strings.HasPrefix(t.Type, "web_search") {
			return true
		}
	}
	return anyObject(r.Input, func(o map[string]any) bool {
		str := func(k string) string { s, _ := o[k].(string); return s }
		switch str("type") {
		case "input_file":
			return str("file_id") != "" || str("file_url") != ""
		case "input_image":
			u := strings.ToLower(str("image_url"))
			return str("file_id") != "" || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
		case "item_reference":
			return true
		}
		return false
	})
}

func anthropicServerState(body []byte) bool {
	var r struct {
		Tools      []typed         `json:"tools"`
		MCPServers json.RawMessage `json:"mcp_servers"`
		Messages   json.RawMessage `json:"messages"`
		System     json.RawMessage `json:"system"`
	}
	if json.Unmarshal(body, &r) != nil {
		return false
	}
	if setJSON(r.MCPServers) {
		return true
	}
	for _, t := range r.Tools {
		for _, p := range []string{"web_search", "web_fetch", "code_execution", "tool_search"} {
			if strings.HasPrefix(t.Type, p) {
				return true
			}
		}
	}
	remote := func(o map[string]any) bool {
		if t, _ := o["type"].(string); t == "container_upload" {
			return true
		}
		src, _ := o["source"].(map[string]any)
		st, _ := src["type"].(string)
		return st == "file" || st == "url"
	}
	return anyObject(r.Messages, remote) || anyObject(r.System, remote)
}

// anyObject reports whether fn holds for any JSON object within raw.
func anyObject(raw json.RawMessage, fn func(map[string]any) bool) bool {
	if !setJSON(raw) {
		return false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			if fn(x) {
				return true
			}
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		case []any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

// Background reports an OpenAI Responses background request.
func Background(proto string, body []byte) bool {
	if proto != ProtoResponses {
		return false
	}
	var r struct {
		Background bool `json:"background"`
	}
	return json.Unmarshal(body, &r) == nil && r.Background
}

// ReasoningBudget reports whether a request enables hidden reasoning, and the
// token budget it sets (0 = none): OpenAI Responses reasoning (unless effort
// "none"); Anthropic thinking enabled or adaptive (budget_tokens) or an
// output_config effort, also under Bedrock Converse
// additionalModelRequestFields; Gemini generationConfig.thinkingConfig.
func ReasoningBudget(proto string, body []byte) (bool, int64) {
	type thinking struct {
		Type   string `json:"type"`
		Budget int64  `json:"budget_tokens"`
	}
	type effort struct {
		Effort string `json:"effort"`
	}
	var r struct {
		Reasoning json.RawMessage `json:"reasoning"` // Responses
		Thinking  thinking        `json:"thinking"`  // Anthropic, Bedrock invoke
		Output    effort          `json:"output_config"`
		Extra     struct {
			Thinking thinking `json:"thinking"`
			Output   effort   `json:"output_config"`
		} `json:"additionalModelRequestFields"` // Bedrock Converse
		Generation struct {
			Thinking *struct {
				Budget  *int64 `json:"thinkingBudget"`
				Include bool   `json:"includeThoughts"`
				Level   string `json:"thinkingLevel"`
			} `json:"thinkingConfig"`
		} `json:"generationConfig"` // Gemini
	}
	if json.Unmarshal(body, &r) != nil {
		return false, 0
	}
	switch proto {
	case ProtoResponses:
		if s := string(bytes.TrimSpace(r.Reasoning)); s == "" || s == "null" {
			return false, 0
		}
		var e effort
		_ = json.Unmarshal(r.Reasoning, &e) // a non-object reasoning value: on, no effort
		return e.Effort != "none", 0
	case ProtoGemini:
		tc := r.Generation.Thinking
		switch {
		case tc == nil:
			return false, 0
		case tc.Budget != nil && *tc.Budget > 0:
			return true, *tc.Budget
		case tc.Budget != nil && *tc.Budget == 0 && !tc.Include && tc.Level == "":
			return false, 0
		}
		return true, 0 // dynamic (-1), includeThoughts or a thinkingLevel
	}
	for _, c := range []struct {
		t thinking
		e effort
	}{{r.Thinking, r.Output}, {r.Extra.Thinking, r.Extra.Output}} {
		if c.t.Type == "enabled" || c.t.Type == "adaptive" {
			return true, max(c.t.Budget, 0)
		}
		if c.e.Effort != "" && c.e.Effort != "none" {
			return true, 0
		}
	}
	return false, 0
}

// MaxOutputTokens is a model request's output token limit on any supported
// wire; 0 when it sets none or does not parse.
func MaxOutputTokens(body []byte) int64 {
	var r struct {
		MaxTokens       int64 `json:"max_tokens"`        // Anthropic Messages, Bedrock invoke
		MaxOutputTokens int64 `json:"max_output_tokens"` // OpenAI Responses
		Generation      struct {
			MaxOutputTokens int64 `json:"maxOutputTokens"`
		} `json:"generationConfig"` // Gemini
		Inference struct {
			MaxTokens int64 `json:"maxTokens"`
		} `json:"inferenceConfig"` // Bedrock Converse
	}
	if json.Unmarshal(body, &r) != nil {
		return 0
	}
	return max(r.MaxTokens, r.MaxOutputTokens, r.Generation.MaxOutputTokens, r.Inference.MaxTokens, 0)
}

func (t *usageTap) feed(b []byte) {
	switch t.mode {
	case tapSSE:
		for len(b) > 0 {
			i := bytes.IndexByte(b, '\n')
			if i < 0 {
				t.appendLine(b)
				return
			}
			t.appendLine(b[:i])
			t.line(t.buf)
			t.buf, t.cut, b = t.buf[:0], false, b[i+1:]
		}
	case tapEventStream:
		if t.stop {
			return
		}
		t.buf = append(t.buf, b...)
		t.frames()
	default:
		t.buf = keepTail(append(t.buf, b...), 2*usageTail)
	}
}

// keepTail bounds b to max bytes by keeping its last usageTail bytes.
func keepTail(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	n := copy(b, b[len(b)-usageTail:])
	return b[:n]
}

// appendLine grows the current SSE line, keeping only its tail past usageMaxLine.
func (t *usageTap) appendLine(b []byte) {
	t.buf = append(t.buf, b...)
	if len(t.buf) > usageMaxLine {
		t.buf, t.cut = keepTail(t.buf, usageMaxLine), true
	}
}

func (t *usageTap) line(l []byte) {
	if t.cut { // the "data:" prefix was dropped with the head; usage sits at the end
		t.scan(l)
	} else if d, ok := bytes.CutPrefix(bytes.TrimRight(l, "\r"), []byte("data:")); ok {
		t.scan(d)
		t.output(d)
	}
}

// outputEvent is the part of a streamed event that carries generated output:
// delta (Anthropic content_block_delta and Bedrock Converse contentBlockDelta:
// an object; OpenAI Responses *.delta events: a string) and Gemini's
// candidates[].content.parts.
type outputEvent struct {
	Delta      json.RawMessage `json:"delta"`
	Candidates []struct {
		Content struct {
			Parts []json.RawMessage `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// output adds the generated output in one streamed event (a JSON document)
// to t.text and t.deltas.
func (t *usageTap) output(b []byte) {
	if !bytes.Contains(b, []byte(`"delta"`)) && !bytes.Contains(b, []byte(`"candidates"`)) {
		return // message_start, pings, usage-only events: skip the decode
	}
	var ev outputEvent
	if json.Unmarshal(b, &ev) != nil {
		return
	}
	n := textBytes(ev.Delta)
	for _, c := range ev.Candidates {
		for _, p := range c.Content.Parts {
			n += textBytes(p)
		}
	}
	if n > 0 {
		t.text += n
		t.deltas++
	}
}

// textBytes sums the decoded length of every string in a JSON value except
// type tags and signatures (opaque, not generated tokens).
func textBytes(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return 0
	}
	var walk func(any) int64
	walk = func(v any) int64 {
		var n int64
		switch x := v.(type) {
		case string:
			n = int64(len(x))
		case []any:
			for _, e := range x {
				n += walk(e)
			}
		case map[string]any:
			for k, e := range x {
				if k != "type" && k != "signature" && k != "thoughtSignature" {
					n += walk(e)
				}
			}
		}
		return n
	}
	return walk(v)
}

// frames scans every complete AWS event stream frame in t.buf. Framing is
// total u32 | headers u32 | prelude crc | headers | payload | crc; the client
// verifies checksums, the tap only needs the payload.
func (t *usageTap) frames() {
	for len(t.buf) >= 12 {
		total, hlen := binary.BigEndian.Uint32(t.buf[0:4]), binary.BigEndian.Uint32(t.buf[4:8])
		if total < 16 || total > usageMaxFrame || hlen > total-16 {
			t.stop, t.buf = true, nil
			return
		}
		if len(t.buf) < int(total) {
			return
		}
		payload := t.buf[12+hlen : total-4]
		var chunk struct {
			Bytes []byte `json:"bytes"` // invoke-with-response-stream: base64 of the model's event
		}
		if json.Unmarshal(payload, &chunk) == nil && len(chunk.Bytes) > 0 {
			t.scan(chunk.Bytes)
			t.output(chunk.Bytes)
		} else {
			t.scan(payload) // converse-stream: the event itself (metadata carries usage)
			t.output(payload)
		}
		t.buf = t.buf[:copy(t.buf, t.buf[total:])]
	}
}

// scan merges the last usage object in b. Only an unescaped `"usage"` followed
// by ':' and '{' is a key: inside a JSON string every quote is escaped, so
// model output cannot forge one.
func (t *usageTap) scan(b []byte) {
	for end := len(b); end > 0; {
		i := bytes.LastIndex(b[:end], t.key)
		if i < 0 {
			return
		}
		end = i
		rest := bytes.TrimLeft(b[i+len(t.key):], " \t\r\n")
		if len(rest) == 0 || rest[0] != ':' {
			continue
		}
		if rest = bytes.TrimLeft(rest[1:], " \t\r\n"); len(rest) == 0 || rest[0] != '{' {
			continue // "usage": null before the response completes
		}
		var raw rawUsage
		if json.NewDecoder(bytes.NewReader(rest)).Decode(&raw) != nil {
			continue
		}
		t.raw.merge(raw)
		t.found = true
		return
	}
}

// merge keeps each field's maximum. Fields merge before normalising: a
// cumulative event may move tokens between prompt and cache counts.
func (r *rawUsage) merge(o rawUsage) {
	r.InputTokens, r.OutputTokens = max(r.InputTokens, o.InputTokens), max(r.OutputTokens, o.OutputTokens)
	r.CacheRead, r.CacheWrite = max(r.CacheRead, o.CacheRead), max(r.CacheWrite, o.CacheWrite)
	r.InputDetails.Cached = max(r.InputDetails.Cached, o.InputDetails.Cached)
	r.ConverseIn, r.ConverseOut = max(r.ConverseIn, o.ConverseIn), max(r.ConverseOut, o.ConverseOut)
	r.ConverseCacheRead, r.ConverseCacheWrite = max(r.ConverseCacheRead, o.ConverseCacheRead), max(r.ConverseCacheWrite, o.ConverseCacheWrite)
	r.Prompt, r.ToolPrompt = max(r.Prompt, o.Prompt), max(r.ToolPrompt, o.ToolPrompt)
	r.Candidates, r.Thoughts, r.Cached = max(r.Candidates, o.Candidates), max(r.Thoughts, o.Thoughts), max(r.Cached, o.Cached)
}

// rawUsage is the union of every wire's usage fields. No two spellings collide
// under encoding/json's case-insensitive matching.
type rawUsage struct {
	// Anthropic Messages (also Bedrock invoke and Vertex), OpenAI Responses.
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	CacheRead    int64 `json:"cache_read_input_tokens"`
	CacheWrite   int64 `json:"cache_creation_input_tokens"`
	InputDetails struct {
		Cached int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	// Bedrock Converse.
	ConverseIn         int64 `json:"inputTokens"`
	ConverseOut        int64 `json:"outputTokens"`
	ConverseCacheRead  int64 `json:"cacheReadInputTokens"`
	ConverseCacheWrite int64 `json:"cacheWriteInputTokens"`
	// Gemini usageMetadata.
	Prompt     int64 `json:"promptTokenCount"`
	ToolPrompt int64 `json:"toolUsePromptTokenCount"`
	Candidates int64 `json:"candidatesTokenCount"`
	Thoughts   int64 `json:"thoughtsTokenCount"`
	Cached     int64 `json:"cachedContentTokenCount"`
}

// normalise maps raw onto non-overlapping counts. OpenAI and Gemini count
// cached tokens inside the input total; Anthropic and Bedrock do not.
func (r rawUsage) normalise(proto string) budget.Usage {
	var u budget.Usage
	switch {
	case proto == ProtoResponses:
		u = budget.Usage{Input: r.InputTokens - r.InputDetails.Cached, Output: r.OutputTokens, CacheRead: r.InputDetails.Cached}
	case proto == ProtoGemini:
		u = budget.Usage{Input: r.Prompt + r.ToolPrompt - r.Cached, Output: r.Candidates + r.Thoughts, CacheRead: r.Cached}
	case r.ConverseIn|r.ConverseOut|r.ConverseCacheRead|r.ConverseCacheWrite != 0:
		u = budget.Usage{Input: r.ConverseIn, Output: r.ConverseOut, CacheRead: r.ConverseCacheRead, CacheWrite: r.ConverseCacheWrite}
	default:
		u = budget.Usage{Input: r.InputTokens, Output: r.OutputTokens, CacheRead: r.CacheRead, CacheWrite: r.CacheWrite}
	}
	return budget.Usage{Input: max(u.Input, 0), Output: max(u.Output, 0), CacheRead: max(u.CacheRead, 0), CacheWrite: max(u.CacheWrite, 0)}
}
