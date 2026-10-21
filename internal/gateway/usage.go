package gateway

import (
	"bytes"
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
	once  sync.Once
	done  func(UsageResult)
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
		t.done(UsageResult{Usage: t.raw.normalise(t.proto), Found: t.found, Complete: t.eof && t.found && decodedOK, Bytes: max(t.n, t.decoded)})
	})
}

// EstimateUsage is the pessimistic charge for a metered 2xx response whose
// final usage was not read (r.Complete false), so hanging up before the last
// event never makes a call free: input as reported so far (Anthropic's
// message_start), else request bytes / 3; output the larger of response bytes
// / 3 and the output reported so far, capped at the request's maximum output
// tokens (0 = no cap). Never zero.
func EstimateUsage(r UsageResult, requestBytes int, maxOutput int64) budget.Usage {
	u := r.Usage
	if u.Input+u.CacheRead+u.CacheWrite == 0 {
		u.Input = int64(requestBytes) / 3
	}
	out := max(r.Bytes/3, u.Output)
	if maxOutput > 0 && out > maxOutput {
		out = max(maxOutput, u.Output)
	}
	u.Output = out
	if u.Tokens() == 0 {
		u.Input = 1
	}
	return u
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
