// Command mockllm is a tiny fake model upstream for the compose demo. It
// answers Anthropic /v1/messages (JSON + SSE), /v1/responses and Bedrock
// /model/{id}/invoke, and echoes which model and x-halo-* headers it received.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var name = os.Getenv("MOCK_NAME")

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", handle("anthropic"))
	mux.HandleFunc("/v1/messages/count_tokens", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("X-Mock-Served-By", name)
		w.Header().Set("X-Mock-Model", body.Model)
		_, _ = w.Write([]byte(`{"input_tokens":7}`))
	})
	mux.HandleFunc("/v1/responses", handle("responses"))
	mux.HandleFunc("/model/", handle("bedrock"))
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"mock","type":"model"}]}`))
	})
	addr := os.Getenv("LISTEN") // e2e runs it on a random loopback port
	if addr == "" {
		addr = ":9000"
	}
	log.Printf("mockllm %q listening %s", name, addr) //nolint:gosec // dev mock logging its own env config
	log.Fatal((&http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

func handle(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		model, _ := body["model"].(string)
		if kind == "bedrock" {
			if p := strings.Split(r.URL.EscapedPath(), "/"); len(p) > 2 {
				model = p[2]
			}
		}
		seen := map[string]string{}
		for k, v := range r.Header {
			l := strings.ToLower(k)
			if strings.HasPrefix(l, "x-halo-") || strings.HasPrefix(l, "anthropic-") || strings.HasPrefix(l, "x-acme-") {
				seen[l] = strings.Join(v, ",")
			}
		}
		text := fmt.Sprintf("served-by=%s model=%s path=%s headers=%v", name, model, r.URL.Path, seen)
		w.Header().Set("X-Mock-Served-By", name)
		w.Header().Set("X-Mock-Model", model)
		for k, v := range seen {
			if strings.HasPrefix(k, "x-halo-") {
				w.Header().Set("X-Seen-"+k, v)
			}
		}
		streaming, _ := body["stream"].(bool)
		if streaming || strings.HasSuffix(r.URL.Path, "-with-response-stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			fl, _ := w.(http.Flusher)
			ev := func(e string, d any) {
				b, _ := json.Marshal(d)
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e, b)
				fl.Flush()
			}
			ev("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_mock", "role": "assistant", "model": model, "usage": map[string]int{"input_tokens": 12, "output_tokens": 0}}})
			for _, part := range strings.Fields(text) {
				ev("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": part + " "}})
				time.Sleep(50 * time.Millisecond) // visible incremental streaming
			}
			ev("message_stop", map[string]any{"type": "message_stop"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		usage := map[string]int{"input_tokens": 12, "output_tokens": 34}
		if kind == "responses" {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "resp_mock", "model": model, "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]string{"type": "output_text", "text": text}}}}, "usage": usage})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": []any{map[string]string{"type": "text", "text": text}}, "usage": usage})
	}
}
