//go:build uat

// Command uatmock is the upstream side of the real-CLI UAT (test/uat): one
// process serving, on a TLS port and a plain-HTTP port,
//
//   - a mock OIDC issuer (internal/identity/identitytest) + /_uat/mint,
//   - Anthropic Messages      POST /v1/messages[/count_tokens] (JSON + SSE),
//   - OpenAI Responses        POST /v1/responses (SSE),
//   - Gemini                  POST /v1beta/models/{m}:generateContent|streamGenerateContent,
//   - an OTLP/HTTP sink       POST /v1/{logs,metrics,traces} (protobuf or JSON),
//   - static files            GET  /files/... (halod for the Dev Container Feature),
//   - inspection              GET  /_uat/requests, /_uat/otlp; POST /_uat/reset.
//
// Replies are scripted by markers in the latest user turn so the real CLIs
// can be driven through a tool loop: UAT-TASK-PASS writes answer.txt, UAT-READ
// asks to read a file, anything else gets a plain answer naming the protocol.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	resv1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Answer is the text every plain reply starts with; the tests grep the CLIs' stdout for it.
const Answer = "UAT-MOCK-ANSWER"

type record struct {
	Time    time.Time           `json:"time"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query,omitempty"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type otlpRecord struct {
	Signal string            `json:"signal"`
	Attrs  map[string]string `json:"attrs"`
}

type state struct {
	mu     sync.Mutex
	reqs   []record
	otlp   []otlpRecord
	mcpSrv map[string]http.Handler
}

func main() {
	tlsAddr := flag.String("tls-listen", ":8443", "TLS listen address")
	httpAddr := flag.String("http-listen", ":8080", "plain HTTP listen address")
	cert := flag.String("cert", "", "TLS certificate (PEM)")
	key := flag.String("key", "", "TLS key (PEM)")
	issuer := flag.String("issuer", "https://mock:8443", "public issuer URL")
	files := flag.String("files", "", "directory served under /files/")
	flag.Parse()

	iss, err := identitytest.NewIssuer("uat")
	if err != nil {
		log.Fatal(err)
	}
	iss.URL = *issuer
	st := &state{reqs: []record{}, otlp: []otlpRecord{}}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", iss.Handler())
	mux.Handle("/jwks", iss.Handler())
	mux.HandleFunc("GET /_uat/mint", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		claims := map[string]any{"sub": q.Get("email"), "email": q.Get("email"), "aud": q.Get("aud")}
		if g := q.Get("groups"); g != "" {
			claims["groups"] = strings.Split(g, ",")
		}
		tok, err := iss.Mint(claims)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprint(w, tok)
	})
	if *files != "" {
		mux.Handle("GET /files/", http.StripPrefix("/files/", http.FileServer(http.Dir(*files))))
	}
	mux.HandleFunc("GET /_uat/requests", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		_ = json.NewEncoder(w).Encode(st.reqs)
	})
	mux.HandleFunc("GET /_uat/otlp", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		_ = json.NewEncoder(w).Encode(st.otlp)
	})
	mux.HandleFunc("POST /_uat/reset", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		st.reqs, st.otlp = []record{}, []otlpRecord{}
		st.mu.Unlock()
		flakyMu.Lock()
		flakyN = map[string]int{}
		flakyMu.Unlock()
	})
	mux.HandleFunc("POST /v1/logs", st.otlpHandler("logs"))
	mux.HandleFunc("POST /v1/metrics", st.otlpHandler("metrics"))
	mux.HandleFunc("POST /v1/traces", st.otlpHandler("traces"))
	mux.HandleFunc("POST /{$}", st.otlpHandler("root"))
	mux.HandleFunc("/mcp/{name}", st.mcp)
	mux.HandleFunc("/", st.model)

	go func() { log.Fatal(http.ListenAndServe(*httpAddr, mux)) }()                                          //nolint:gosec // test mock
	srv := &http.Server{Addr: *tlsAddr, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}} //nolint:gosec // test mock
	log.Printf("uatmock: tls %s http %s issuer %s", *tlsAddr, *httpAddr, *issuer)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

func (s *state) otlpHandler(signal string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		js := strings.Contains(r.Header.Get("Content-Type"), "json")
		attrs, err := resourceAttrs(b, js)
		if err != nil {
			log.Printf("otlp %s: decode: %v", signal, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		for _, a := range attrs {
			s.otlp = append(s.otlp, otlpRecord{Signal: signal, Attrs: a})
		}
		s.mu.Unlock()
		if js {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "{}")
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
	}
}

// resourceAttrs returns the resource attributes of an OTLP export request of
// any signal: logs, metrics and traces all nest `Resource resource = 1` in
// their repeated field 1, so the walk does not need to know the signal (an
// exporter that posts every signal to one URL is still decoded).
func resourceAttrs(b []byte, js bool) ([]map[string]string, error) {
	var out []map[string]string
	if js {
		var doc map[string][]struct {
			Resource struct {
				Attributes []struct {
					Key   string `json:"key"`
					Value struct {
						StringValue string `json:"stringValue"`
					} `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, err
		}
		for _, rs := range doc {
			for _, r := range rs {
				a := map[string]string{}
				for _, kv := range r.Resource.Attributes {
					a[kv.Key] = kv.Value.StringValue
				}
				out = append(out, a)
			}
		}
		return out, nil
	}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num != 1 || typ != protowire.BytesType {
			if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
				return nil, protowire.ParseError(n)
			}
			b = b[n:]
			continue
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		// v is a ResourceLogs|ResourceMetrics|ResourceSpans; field 1 is the Resource.
		a := map[string]string{}
		for len(v) > 0 {
			fnum, ftyp, m := protowire.ConsumeTag(v)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			v = v[m:]
			if fnum == 1 && ftyp == protowire.BytesType {
				rb, m := protowire.ConsumeBytes(v)
				if m < 0 {
					return nil, protowire.ParseError(m)
				}
				res := &resv1.Resource{}
				if err := proto.Unmarshal(rb, res); err != nil {
					return nil, err
				}
				for _, kv := range res.GetAttributes() {
					a[kv.Key] = kv.GetValue().GetStringValue()
				}
				v = v[m:]
				continue
			}
			if m = protowire.ConsumeFieldValue(fnum, ftyp, v); m < 0 {
				return nil, protowire.ParseError(m)
			}
			v = v[m:]
		}
		out = append(out, a)
	}
	return out, nil
}

var geminiPath = regexp.MustCompile(`^/v1(beta|alpha)?/models/([^/:]+):(generateContent|streamGenerateContent|countTokens)$`)

// model records every non-OTLP request and answers the model protocols.
func (s *state) model(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	s.mu.Lock()
	s.reqs = append(s.reqs, record{Time: time.Now(), Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Headers: r.Header.Clone(), Body: string(b)})
	s.mu.Unlock()
	log.Printf("%q %q %q", r.Method, r.URL.Path, r.URL.RawQuery)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	switch p := r.URL.Path; {
	case p == "/v1/messages/count_tokens":
		writeJSON(w, map[string]any{"input_tokens": 12})
	case p == "/v1/messages":
		anthropic(w, body)
	case p == "/v1/responses":
		responses(w, body)
	case p == "/v1/chat/completions":
		chat(w, body)
	case geminiPath.MatchString(p):
		m := geminiPath.FindStringSubmatch(p)
		gemini(w, r, body, m[2], m[3])
	case strings.HasSuffix(p, "/models") || strings.Contains(p, "/models/"):
		writeJSON(w, map[string]any{"data": []any{}, "models": []any{}})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// sse writes one server-sent event and flushes.
func sse(w http.ResponseWriter, event string, data any) {
	b, _ := json.Marshal(data)
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func sseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
}

// step is what the script wants next: a tool call, or text.
type step struct {
	tool  string         // tool name; "" means text
	input map[string]any // tool arguments
	text  string
}

var readMarker = regexp.MustCompile(`UAT-READ path=(\S+)`)

var (
	flakyMu sync.Mutex
	flakyN  = map[string]int{}
)

// flakyTurn alternates true, false, true, ... per model, so each eval arm
// (one model each) is flaky on its own regardless of trial interleaving.
func flakyTurn(model string) bool {
	flakyMu.Lock()
	defer flakyMu.Unlock()
	flakyN[model]++
	return flakyN[model]%2 == 1
}

// decide maps the latest user text (+ whether a tool result already came back)
// to the next step. hasTool reports whether the request offers that tool.
func decide(proto, model, userText string, toolDone bool, hasTool func(string) bool) step {
	plain := step{text: fmt.Sprintf("%s via %s (model=%s)", Answer, proto, model)}
	if toolDone {
		return step{text: Answer + " tool step done"}
	}
	switch {
	case strings.Contains(userText, "UAT-TASK-PASS"):
		if proto == "anthropic" && hasTool("Write") {
			return step{tool: "Write", input: map[string]any{"file_path": "/work/answer.txt", "content": "42\n"}}
		}
		if proto == "openai" && hasTool("exec_command") { // codex >= ~0.9x
			return step{tool: "exec_command", input: map[string]any{"cmd": "echo 42 > answer.txt"}}
		}
		if proto == "openai" && hasTool("shell") {
			return step{tool: "shell", input: map[string]any{"command": []string{"bash", "-lc", "echo 42 > answer.txt"}}}
		}
	case readMarker.MatchString(userText) && proto == "anthropic" && hasTool("Read"):
		return step{tool: "Read", input: map[string]any{"file_path": readMarker.FindStringSubmatch(userText)[1]}}
	case strings.Contains(userText, "UAT-TASK-FAIL"):
		// Codex never solves it; Claude solves every other attempt, so the
		// control arm of the UAT eval is flaky on this task by construction.
		if proto == "anthropic" && hasTool("Write") && flakyTurn(model) {
			return step{tool: "Write", input: map[string]any{"file_path": "/work/answer.txt", "content": "42\n"}}
		}
		return step{text: Answer + " I will not change anything"}
	}
	return plain
}

// textOf flattens string-or-blocks content.
func textOf(c any) string {
	switch v := c.(type) {
	case string:
		return v
	case []any:
		var sb strings.Builder
		for _, x := range v {
			if m, ok := x.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					sb.WriteString(t + "\n")
				}
			}
		}
		return sb.String()
	}
	return ""
}

func anthropic(w http.ResponseWriter, body map[string]any) {
	model, _ := body["model"].(string)
	msgs, _ := body["messages"].([]any)
	var user string
	toolDone := false
	if n := len(msgs); n > 0 {
		last, _ := msgs[n-1].(map[string]any)
		user = textOf(last["content"])
		// One tool call per conversation: any earlier tool_result ends the script
		// (the CLI may append text turns after a denied tool).
		for _, mv := range msgs {
			m, _ := mv.(map[string]any)
			if blocks, ok := m["content"].([]any); ok {
				for _, x := range blocks {
					if b, ok := x.(map[string]any); ok && b["type"] == "tool_result" {
						toolDone = true
					}
				}
			}
		}
		// The task marker lives in the first user turn; later turns are tool results.
		if first, ok := msgs[0].(map[string]any); ok {
			user += "\n" + textOf(first["content"])
		}
	}
	tools, _ := body["tools"].([]any)
	has := func(name string) bool {
		for _, t := range tools {
			if m, ok := t.(map[string]any); ok && m["name"] == name {
				return true
			}
		}
		return false
	}
	st := decide("anthropic", model, user, toolDone, has)
	stop := "end_turn"
	var block map[string]any
	if st.tool != "" {
		stop = "tool_use"
		block = map[string]any{"type": "tool_use", "id": fmt.Sprintf("toolu_uat%d", time.Now().UnixNano()), "name": st.tool, "input": st.input}
	} else {
		block = map[string]any{"type": "text", "text": st.text}
	}
	usage := map[string]any{"input_tokens": 12, "output_tokens": 7, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
	msg := map[string]any{"id": "msg_uat", "type": "message", "role": "assistant", "model": model,
		"stop_reason": stop, "stop_sequence": nil, "usage": usage}
	if stream, _ := body["stream"].(bool); !stream {
		msg["content"] = []any{block}
		writeJSON(w, msg)
		return
	}
	sseHeaders(w)
	start := map[string]any{}
	for k, v := range msg {
		start[k] = v
	}
	start["content"], start["stop_reason"] = []any{}, nil
	sse(w, "message_start", map[string]any{"type": "message_start", "message": start})
	if st.tool != "" {
		in, _ := json.Marshal(st.input)
		sse(w, "content_block_start", map[string]any{"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "tool_use", "id": block["id"], "name": st.tool, "input": map[string]any{}}})
		sse(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": string(in)}})
	} else {
		sse(w, "content_block_start", map[string]any{"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "text", "text": ""}})
		sse(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "text_delta", "text": st.text}})
	}
	sse(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	sse(w, "message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": 7}})
	sse(w, "message_stop", map[string]any{"type": "message_stop"})
}

func responses(w http.ResponseWriter, body map[string]any) {
	model, _ := body["model"].(string)
	var user string
	toolDone := false
	input, _ := body["input"].([]any)
	for _, x := range input {
		m, _ := x.(map[string]any)
		switch m["type"] {
		case "function_call_output", "custom_tool_call_output":
			toolDone = true
		case "message", nil:
			if m["role"] == "user" {
				user += textOf(m["content"]) + "\n"
			}
		}
	}
	if s, ok := body["input"].(string); ok {
		user = s
	}
	tools, _ := body["tools"].([]any)
	has := func(name string) bool {
		for _, t := range tools {
			if m, ok := t.(map[string]any); ok && (m["name"] == name || m["type"] == name) {
				return true
			}
		}
		return false
	}
	st := decide("openai", model, user, toolDone, has)
	sseHeaders(w)
	id := fmt.Sprintf("resp_uat%d", time.Now().UnixNano())
	sse(w, "response.created", map[string]any{"type": "response.created", "response": map[string]any{"id": id, "model": model, "status": "in_progress"}})
	var item map[string]any
	if st.tool != "" {
		args, _ := json.Marshal(st.input)
		item = map[string]any{"type": "function_call", "id": "fc_uat", "call_id": "call_uat", "name": st.tool, "arguments": string(args), "status": "completed"}
	} else {
		sse(w, "response.output_item.added", map[string]any{"type": "response.output_item.added", "output_index": 0,
			"item": map[string]any{"type": "message", "id": "msg_uat", "role": "assistant", "status": "in_progress", "content": []any{}}})
		sse(w, "response.output_text.delta", map[string]any{"type": "response.output_text.delta", "item_id": "msg_uat", "output_index": 0, "content_index": 0, "delta": st.text})
		item = map[string]any{"type": "message", "id": "msg_uat", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": st.text, "annotations": []any{}}}}
	}
	sse(w, "response.output_item.done", map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
	sse(w, "response.completed", map[string]any{"type": "response.completed", "response": map[string]any{"id": id, "model": model, "status": "completed",
		"output": []any{item},
		"usage": map[string]any{"input_tokens": 12, "input_tokens_details": map[string]any{"cached_tokens": 0}, "output_tokens": 7,
			"output_tokens_details": map[string]any{"reasoning_tokens": 0}, "total_tokens": 19}}})
}

func gemini(w http.ResponseWriter, r *http.Request, body map[string]any, model, method string) {
	if method == "countTokens" {
		writeJSON(w, map[string]any{"totalTokens": 12})
		return
	}
	var user string
	contents, _ := body["contents"].([]any)
	for _, c := range contents {
		if m, ok := c.(map[string]any); ok && m["role"] == "user" {
			if parts, ok := m["parts"].([]any); ok {
				user += textOf(parts)
			}
		}
	}
	text := decide("gemini", model, user, false, func(string) bool { return false }).text
	// Internal JSON-mode calls (e.g. next-speaker checks) need a JSON reply.
	if gc, ok := body["generationConfig"].(map[string]any); ok && gc["responseMimeType"] == "application/json" {
		text = `{"reasoning":"uat","next_speaker":"user","model_choice":"pro"}`
	}
	resp := map[string]any{
		"candidates":    []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": text}}}, "finishReason": "STOP", "index": 0}},
		"usageMetadata": map[string]any{"promptTokenCount": 12, "candidatesTokenCount": 7, "totalTokenCount": 19},
		"modelVersion":  model,
	}
	if method == "generateContent" {
		writeJSON(w, resp)
		return
	}
	if r.URL.Query().Get("alt") == "sse" {
		sseHeaders(w)
		sse(w, "", resp)
		return
	}
	var buf bytes.Buffer // non-SSE stream: a JSON array
	_ = json.NewEncoder(&buf).Encode([]any{resp})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}

// chat answers OpenAI Chat Completions (Copilot CLI BYOK's default wire API).
func chat(w http.ResponseWriter, body map[string]any) {
	model, _ := body["model"].(string)
	var user string
	msgs, _ := body["messages"].([]any)
	for _, x := range msgs {
		if m, ok := x.(map[string]any); ok && m["role"] == "user" {
			user += textOf(m["content"]) + "\n"
		}
	}
	text := decide("openai-chat", model, user, false, func(string) bool { return false }).text
	usage := map[string]any{"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}
	if stream, _ := body["stream"].(bool); !stream {
		writeJSON(w, map[string]any{"id": "chatcmpl-uat", "object": "chat.completion", "created": time.Now().Unix(), "model": model,
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}},
			"usage":   usage})
		return
	}
	sseHeaders(w)
	chunk := func(delta map[string]any, finish any, u any) map[string]any {
		c := map[string]any{"id": "chatcmpl-uat", "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
		if u != nil {
			c["usage"] = u
		}
		return c
	}
	sse(w, "", chunk(map[string]any{"role": "assistant", "content": text}, nil, nil))
	sse(w, "", chunk(map[string]any{}, "stop", usage))
	fmt.Fprint(w, "data: [DONE]\n\n")
}

// mcp serves a one-tool streamable-HTTP MCP server per path (/mcp/<name>) and
// records the hit, so the tests can see which servers a CLI actually reached.
func (s *state) mcp(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	s.reqs = append(s.reqs, record{Time: time.Now(), Method: r.Method, Path: r.URL.Path, Headers: r.Header.Clone()})
	if s.mcpSrv == nil {
		s.mcpSrv = map[string]http.Handler{}
	}
	h, ok := s.mcpSrv[name]
	if !ok {
		srv := mcp.NewServer(&mcp.Implementation{Name: "uat-" + name, Version: "1.0.0"}, nil)
		mcp.AddTool(srv, &mcp.Tool{Name: "uat_echo", Description: "returns the server name"},
			func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "uat-" + name}}}, nil, nil
			})
		h = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
		s.mcpSrv[name] = h
	}
	s.mu.Unlock()
	h.ServeHTTP(w, r)
}
