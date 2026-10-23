package main

import (
	"bytes"
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
	tapHead = 4 << 10 // response prefix searched for the model name
	tapTail = 64 << 10
)

// genaiTap observes a response body as it streams to the client for the
// response model and time to first byte; token usage comes from the one
// usage parser, gateway.UsageTap, through usage. It never buffers the whole
// body, never delays or alters a byte, and keeps no content: only a bounded
// head / tail window that is discarded with the request. It is read, and its
// usage set, by the goroutine that runs the reverse proxy copy, so no
// locking is needed once the copy returns.
type genaiTap struct {
	r      io.ReadCloser
	stream bool // SSE or AWS event stream; else keep a tail for the JSON body
	plain  bool // no Content-Encoding: the bytes can be searched for the model
	start  time.Time

	first        time.Time // first body byte
	head         []byte
	tail         []byte
	in, out      int64
	seen         bool
	model        string
	scannedModel bool
}

func newGenAITap(r io.ReadCloser, stream, plain bool, start time.Time) *genaiTap {
	return &genaiTap{r: r, stream: stream, plain: plain, start: start}
}

func (t *genaiTap) Close() error { return t.r.Close() }

func (t *genaiTap) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.feed(p[:n])
	}
	return n, err
}

func (t *genaiTap) feed(b []byte) {
	if t.first.IsZero() {
		t.first = time.Now()
	}
	if !t.plain {
		return
	}
	if room := tapHead - len(t.head); room > 0 {
		t.head = append(t.head, b[:min(room, len(b))]...)
	}
	if !t.stream {
		t.tail = append(t.tail, b...)
		if len(t.tail) > 2*tapTail { // amortised trim to the last tapTail bytes
			t.tail = append(t.tail[:0], t.tail[len(t.tail)-tapTail:]...)
		}
	}
}

// usage records what gateway.UsageTap read: GenAI input counts every input
// token, cached or not.
func (t *genaiTap) usage(r gateway.UsageResult) {
	if r.Found {
		t.seen = true
		t.in, t.out = r.Usage.Input+r.Usage.CacheRead+r.Usage.CacheWrite, r.Usage.Output
	}
}

// result reports what was observed. Call after the response was copied.
func (t *genaiTap) result() (in, out int64, model string, ok bool) {
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
func (t *genaiTap) ttft() time.Duration {
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
