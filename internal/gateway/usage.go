package gateway

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"mime"
	"sync"

	"github.com/dshakes/halos/internal/budget"
)

// Usage scanning bounds: memory per response stays under ~1 MiB however
// large the response or a single event is.
const (
	usageTail     = 64 << 10 // usage objects sit at the end of a body or event
	usageMaxLine  = 1 << 20  // longer SSE lines keep only their tail
	usageMaxFrame = 1 << 20  // larger AWS event stream frames stop the scan
)

// UsageTap wraps a model response body in the caller's wire protocol and
// reports its token usage once the body ends (EOF, read error or Close),
// exactly once. It never changes the bytes the client receives. ok is false
// when no usage object was seen (a cut stream, an unknown shape): the caller
// counts that rather than guessing.
//
// The response is scanned as it streams: SSE line by line (Anthropic
// message_start/message_delta, OpenAI response.completed, Gemini chunks), an
// AWS event stream frame by frame (Bedrock invoke/converse streams), or, for
// a plain JSON body, its last 64 KiB. Counts merge by maximum, since every
// wire reports cumulative totals.
func UsageTap(proto, contentType string, rc io.ReadCloser, done func(u budget.Usage, ok bool)) io.ReadCloser {
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
	key   []byte
	buf   []byte   // JSON: body tail; SSE: current line; event stream: partial frame
	stop  bool     // event stream framing lost: stop scanning
	raw   rawUsage // field-wise maximum over every usage object seen
	found bool
	cut   bool // SSE: the current line outgrew usageMaxLine and lost its head
	once  sync.Once
	done  func(budget.Usage, bool)
}

func (t *usageTap) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n > 0 {
		t.feed(p[:n])
	}
	if err != nil {
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
		if t.mode == tapJSON || t.mode == tapSSE { // a final SSE line may lack its newline
			t.scan(t.buf)
		}
		t.buf = nil
		t.done(t.raw.normalise(t.proto), t.found)
	})
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
	}
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
		} else {
			t.scan(payload) // converse-stream: the event itself (metadata carries usage)
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
