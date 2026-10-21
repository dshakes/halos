package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/telemetry/gwmetrics"
)

// Semantic-convention mapping for the GenAI signals (see internal/telemetry/gwmetrics).

// genaiOperation is gen_ai.operation.name for a model-call wire protocol.
func genaiOperation(proto string) string {
	if proto == gateway.ProtoGemini {
		return "generate_content"
	}
	return "chat"
}

// genaiProvider is gen_ai.provider.name: the routed upstream kind when there is
// one, else what the wire protocol implies.
func genaiProvider(proto, kind string) string {
	if p := kindProvider(kind); p != "" {
		return p
	}
	switch proto {
	case gateway.ProtoGemini:
		return "gcp.gemini"
	case gateway.ProtoBedrock:
		return "aws.bedrock"
	case gateway.ProtoResponses:
		return "openai"
	}
	return "anthropic"
}

// kindProvider maps a policy upstream kind to its registered provider name;
// "" for kinds with none (orchestrator).
func kindProvider(kind string) string {
	switch kind {
	case "anthropic", "openai":
		return kind
	case "bedrock":
		return "aws.bedrock"
	case "vertex":
		return "gcp.vertex_ai"
	case "gemini":
		return "gcp.gemini"
	case "azure-openai":
		return "azure.ai.openai"
	}
	return ""
}

// finishGenAI completes gw.GenAI from the route taken and what the usage tap saw.
func (p *Proxy) finishGenAI(gw *gwmetrics.Request, rc *routeCtx) {
	g := gw.GenAI
	if a := rc.served; a != nil {
		if prov := kindProvider(a.kind); prov != "" {
			g.Provider = prov
		}
	}
	if rc.tap == nil {
		return
	}
	in, out, model, ok := rc.tap.result()
	g.ResponseModel = model
	if ok {
		g.InputTokens, g.OutputTokens = in, out
	}
	g.TTFT = rc.tap.ttft()
}

const (
	tapMaxLine = 1 << 20 // longest SSE data line scanned for usage; longer ones are skipped
	tapHead    = 4 << 10 // response prefix searched for the model name
	tapTail    = 64 << 10
)

// usageTap observes a response body as it streams to the client and extracts
// token usage and the response model. It never buffers the whole body, never
// delays or alters a byte, and keeps no content: only a bounded line / tail
// window that is discarded with the request. It is read by the goroutine that
// runs the reverse proxy copy, so no locking is needed once the copy returns.
type usageTap struct {
	r      io.ReadCloser
	stream bool // text/event-stream: scan data lines; else keep a tail for the JSON body
	start  time.Time

	first        time.Time // first body byte
	head         []byte
	line         []byte // partial SSE line
	skip         bool   // current SSE line exceeded tapMaxLine
	tail         []byte
	in, out      int64
	seen         bool
	model        string
	scannedModel bool
}

func newUsageTap(r io.ReadCloser, stream bool, start time.Time) *usageTap {
	return &usageTap{r: r, stream: stream, start: start}
}

func (t *usageTap) Close() error { return t.r.Close() }

func (t *usageTap) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.feed(p[:n])
	}
	return n, err
}

func (t *usageTap) feed(b []byte) {
	if t.first.IsZero() {
		t.first = time.Now()
	}
	if room := tapHead - len(t.head); room > 0 {
		t.head = append(t.head, b[:min(room, len(b))]...)
	}
	if !t.stream {
		t.tail = append(t.tail, b...)
		if len(t.tail) > 2*tapTail { // amortised trim to the last tapTail bytes
			t.tail = append(t.tail[:0], t.tail[len(t.tail)-tapTail:]...)
		}
		return
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			if !t.skip {
				if len(t.line)+len(b) > tapMaxLine {
					t.skip, t.line = true, t.line[:0]
				} else {
					t.line = append(t.line, b...)
				}
			}
			return
		}
		if !t.skip {
			if len(t.line) == 0 {
				t.scanLine(b[:i])
			} else if len(t.line)+i <= tapMaxLine {
				t.line = append(t.line, b[:i]...)
				t.scanLine(t.line)
			}
		}
		t.line, t.skip = t.line[:0], false
		b = b[i+1:]
	}
}

func (t *usageTap) scanLine(l []byte) {
	l = bytes.TrimRight(l, "\r")
	if bytes.HasPrefix(l, []byte("data:")) && bytes.Contains(l, []byte("sage")) { // usage | usageMetadata
		t.scanUsage(l)
	}
}

// usageDoc covers the usage objects of the supported wires: OpenAI chat
// (prompt/completion), OpenAI Responses and Anthropic (input/output + cache),
// Gemini (usageMetadata *TokenCount).
type usageDoc struct {
	PromptTokens         int64 `json:"prompt_tokens"`
	CompletionTokens     int64 `json:"completion_tokens"`
	InputTokens          int64 `json:"input_tokens"`
	OutputTokens         int64 `json:"output_tokens"`
	CacheRead            int64 `json:"cache_read_input_tokens"`
	CacheCreate          int64 `json:"cache_creation_input_tokens"`
	PromptTokenCount     int64 `json:"promptTokenCount"`
	CandidatesTokenCount int64 `json:"candidatesTokenCount"`
	ThoughtsTokenCount   int64 `json:"thoughtsTokenCount"`
}

// scanUsage decodes the usage object following every `"usage":` or
// `"usageMetadata":` key in b and keeps the largest counts seen (Anthropic
// reports input in message_start and the final output in message_delta).
func (t *usageTap) scanUsage(b []byte) {
	for _, key := range [][]byte{[]byte(`"usage"`), []byte(`"usageMetadata"`)} {
		for rest := b; ; {
			i := bytes.Index(rest, key)
			if i < 0 {
				break
			}
			rest = rest[i+len(key):]
			j := bytes.IndexFunc(rest, func(r rune) bool { return r != ' ' && r != ':' && r != '\t' })
			if j < 0 || rest[j] != '{' || bytes.IndexByte(rest[:j], ':') < 0 {
				continue
			}
			var u usageDoc
			if json.NewDecoder(bytes.NewReader(rest[j:])).Decode(&u) != nil {
				continue
			}
			in := max(u.PromptTokens, u.PromptTokenCount, u.InputTokens+u.CacheRead+u.CacheCreate)
			out := max(u.CompletionTokens, u.OutputTokens, u.CandidatesTokenCount+u.ThoughtsTokenCount)
			if in > 0 || out > 0 {
				t.seen = true
				t.in, t.out = max(t.in, in), max(t.out, out)
			}
		}
	}
}

// result finishes a non-stream body (usage and model live at the end of the
// JSON) and reports what was observed. Call after the response was copied.
func (t *usageTap) result() (in, out int64, model string, ok bool) {
	if !t.stream && len(t.tail) > 0 {
		t.scanUsage(t.tail)
	}
	if !t.scannedModel {
		t.scannedModel = true
		t.model = jsonModel(t.head)
		if t.model == "" && !t.stream {
			t.model = jsonModel(t.tail)
		}
	}
	return t.in, t.out, t.model, t.seen
}

// ttft is the time from request receipt to the first body byte of a stream; -1
// when the response was not a stream or no byte arrived. SSE producers send
// the first event when the first token (or its message_start frame) is ready,
// so this is a close proxy, not an exact first-token timestamp.
func (t *usageTap) ttft() time.Duration {
	if !t.stream || t.first.IsZero() {
		return -1
	}
	return t.first.Sub(t.start)
}

// jsonModel returns the first "model" (or Gemini "modelVersion") string value
// in b when it looks like a model id; "" otherwise. Values outside a strict
// id alphabet are dropped: the field is untrusted upstream output and becomes
// a metric attribute.
func jsonModel(b []byte) string {
	for _, key := range []string{`"model"`, `"modelVersion"`} {
		rest := b
		for {
			i := bytes.Index(rest, []byte(key))
			if i < 0 {
				break
			}
			rest = rest[i+len(key):]
			r := bytes.TrimLeft(rest, " :")
			if len(r) == len(rest) || len(rest)-len(r) > 4 || len(r) == 0 || r[0] != '"' {
				continue
			}
			r = r[1:]
			end := bytes.IndexByte(r, '"')
			if end <= 0 || end > 128 {
				continue
			}
			if v := string(r[:end]); validModelID(v) {
				return v
			}
		}
	}
	return ""
}

func validModelID(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("._:/@-", r)
	}) < 0
}
