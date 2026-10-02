//go:build providers

// Package providers is the nightly provider smoke: a real halo-proxy in front
// of a REAL model provider. It never runs under plain `go test ./...` (build
// tag `providers`) and skips every provider whose credentials are not in the
// environment. Keys are read from env only and handed to halo-proxy the way the
// product documents (policy upstream credential.env, upstreamHeaders ${ENV},
// the AWS / Google default credential chains); they are never logged or written
// to disk.
//
//	go test -tags providers -run 'TestProviderSmoke/anthropic' -v ./test/providers/...
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// provider describes one path. Wire is the client protocol the smoke speaks to
// halo-proxy; Kind is the policy upstream kind (also the metrics provider label).
type provider struct {
	name, kind, harness, wire string
	needs                     func() (missing string)   // "" = enabled
	upstream                  func(t *testing.T) string // YAML body of the upstream
	model                     string                    // upstream model id
	headers                   string                    // halo-proxy upstreamHeaders YAML for this upstream, if any
}

// envOr returns $name, or def when unset. The *_MODEL vars are the documented overrides.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func needAll(names ...string) func() string {
	return func() string {
		for _, n := range names {
			if os.Getenv(n) == "" {
				return n
			}
		}
		return ""
	}
}

func providers() []provider {
	return []provider{
		{
			name: "anthropic", kind: "anthropic", harness: "claude-code", wire: "anthropic-messages",
			needs:    needAll("ANTHROPIC_API_KEY"),
			upstream: func(*testing.T) string { return "{kind: anthropic, url: https://api.anthropic.com}" },
			model:    envOr("HALO_SMOKE_ANTHROPIC_MODEL", "claude-haiku-4-5"),
			headers:  `{x-api-key: "${ANTHROPIC_API_KEY}", anthropic-version: "2023-06-01"}`,
		},
		{
			name: "openai", kind: "openai", harness: "codex", wire: "openai-responses",
			needs: needAll("OPENAI_API_KEY"),
			upstream: func(*testing.T) string {
				return "{kind: openai, url: https://api.openai.com, credential: {env: OPENAI_API_KEY}}"
			},
			model: envOr("HALO_SMOKE_OPENAI_MODEL", "gpt-4.1-nano"),
		},
		{
			name: "gemini", kind: "gemini", harness: "gemini-cli", wire: "gemini",
			needs: needAll("GEMINI_API_KEY"),
			upstream: func(*testing.T) string {
				return "{kind: gemini, url: https://generativelanguage.googleapis.com, credential: {env: GEMINI_API_KEY}}"
			},
			model: envOr("HALO_SMOKE_GEMINI_MODEL", "gemini-2.5-flash-lite"),
		},
		{
			// AZURE_OPENAI_ENDPOINT must be https://<resource>.openai.azure.com;
			// the model is the deployment name.
			name: "azure-openai", kind: "azure-openai", harness: "codex", wire: "openai-responses",
			needs: needAll("AZURE_OPENAI_KEY", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT"),
			upstream: func(*testing.T) string {
				return fmt.Sprintf("{kind: azure-openai, url: %q, credential: {env: AZURE_OPENAI_KEY}}", os.Getenv("AZURE_OPENAI_ENDPOINT"))
			},
			model: os.Getenv("AZURE_OPENAI_DEPLOYMENT"),
		},
		{
			// SigV4 by halo-proxy through the AWS default chain (env keys here).
			name: "bedrock", kind: "bedrock", harness: "claude-code", wire: "anthropic-messages",
			needs: needAll("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"),
			upstream: func(*testing.T) string {
				r := os.Getenv("AWS_REGION")
				return fmt.Sprintf("{kind: bedrock, url: https://bedrock-runtime.%s.amazonaws.com, region: %s}", r, r)
			},
			model: envOr("HALO_SMOKE_BEDROCK_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0"),
		},
		{
			// ADC via the service-account key file in GOOGLE_APPLICATION_CREDENTIALS.
			name: "vertex", kind: "vertex", harness: "claude-code", wire: "anthropic-messages",
			needs: needAll("GOOGLE_APPLICATION_CREDENTIALS"),
			upstream: func(t *testing.T) string {
				return fmt.Sprintf("{kind: vertex, project: %q, region: %q}", vertexProject(t), envOr("HALO_SMOKE_VERTEX_REGION", "us-east5"))
			},
			model: envOr("HALO_SMOKE_VERTEX_MODEL", "claude-haiku-4-5@20251001"),
		},
	}
}

// vertexProject is HALO_SMOKE_VERTEX_PROJECT, else project_id of the key file.
func vertexProject(t *testing.T) string {
	if p := os.Getenv("HALO_SMOKE_VERTEX_PROJECT"); p != "" {
		return p
	}
	b, err := os.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if err != nil {
		t.Fatalf("read GOOGLE_APPLICATION_CREDENTIALS file: %v", err)
	}
	var k struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(b, &k); err != nil || k.ProjectID == "" {
		t.Fatalf("GOOGLE_APPLICATION_CREDENTIALS has no project_id (set HALO_SMOKE_VERTEX_PROJECT); parse err: %v", err)
	}
	return k.ProjectID
}

func TestProviderSmoke(t *testing.T) {
	for _, p := range providers() {
		t.Run(p.name, func(t *testing.T) {
			if missing := p.needs(); missing != "" {
				t.Skipf("%s not set; skipping %s", missing, p.name)
			}
			smoke(t, buildBins(t), p) // built only for enabled providers; the go build cache keeps it cheap
		})
	}
}

// buildBins compiles halo and halo-proxy into a temp dir removed with t.
func buildBins(t *testing.T) map[string]string {
	t.Helper()
	dir, err := os.MkdirTemp("", "halo-smoke-bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	out := map[string]string{}
	for _, b := range []string{"halo", "halo-proxy"} {
		out[b] = filepath.Join(dir, b)
		cmd := exec.Command("go", "build", "-o", out[b], "./cmd/"+b)
		cmd.Dir = filepath.Join("..", "..")
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b, err, o)
		}
	}
	return out
}

func run(t *testing.T, bin string, args ...string) {
	t.Helper()
	if o, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, o)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startProxy compiles a one-upstream policy and runs halo-proxy on it. Returns
// the public and admin base URLs.
func startProxy(t *testing.T, bins map[string]string, p provider) (base, admin string) {
	t.Helper()
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	run(t, bins["halo"], "init", pol, "--org", "smoke", "--full")
	// The init profile pins claude-code on alias "sonnet", so keep that alias on
	// its (never called) anthropic upstream and add "smoke" for the provider under test.
	protocols := "  claude-code: anthropic-messages\n"
	if p.harness != "claude-code" {
		protocols += fmt.Sprintf("  %s: %s\n", p.harness, p.wire)
	}
	write(t, filepath.Join(pol, "gateway.yaml"), fmt.Sprintf(`apiVersion: halos.dev/v1alpha1
kind: Gateway
name: smoke-gateway
baseURL: https://ai.smoke.example
protocols:
%sauth:
  helperCommand: /usr/local/bin/smoke-token
  ttlSeconds: 3300
upstreams:
  anthropic-direct: {kind: anthropic, url: https://api.anthropic.com}
  smoke: %s
models:
  sonnet: {upstream: anthropic-direct, model: claude-sonnet-4-5}
  smoke: {upstream: smoke, model: %q}
`, protocols, p.upstream(t), p.model))
	snap := filepath.Join(dir, "policy.json")
	run(t, bins["halo"], "gateway", "compile", pol, "-o", snap)

	addr, adm := freeAddr(t), freeAddr(t)
	cfg := "identity: {mode: none}\n" // ${ENV} placeholders stay literal on disk; halo-proxy expands them in memory
	if p.headers != "" {
		cfg += "upstreamHeaders:\n  smoke: " + p.headers + "\n"
	}
	cfgPath := filepath.Join(dir, "halo-proxy.yaml")
	write(t, cfgPath, cfg)

	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bins["halo-proxy"], "--config", cfgPath, "--policy", snap, "--listen", addr, "--admin-listen", adm)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("halo-proxy log (no bodies, no headers):\n%s", logs.String())
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get("http://" + adm + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return "http://" + addr, "http://" + adm
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("halo-proxy not healthy in 30s; log:\n%s", logs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// call posts body to path and returns the status and full body (SSE read to EOF).
func call(t *testing.T, base, path string, hdr map[string]string, body string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, string(b)
}

func trunc(s string) string {
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
}

func smoke(t *testing.T, bins map[string]string, p provider) {
	base, admin := startProxy(t, bins, p)

	var path, streamPath, body, streamBody string
	hdr := map[string]string{}
	switch p.wire {
	case "anthropic-messages":
		path = "/v1/messages"
		streamPath = path
		hdr["anthropic-version"] = "2023-06-01"
		body = `{"model":"smoke","max_tokens":16,"messages":[{"role":"user","content":"Say hi."}]}`
		streamBody = `{"model":"smoke","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"Say hi."}]}`
	case "openai-responses":
		path = "/v1/responses"
		streamPath = path
		body = `{"model":"smoke","max_output_tokens":16,"input":"Say hi."}`
		streamBody = `{"model":"smoke","max_output_tokens":16,"stream":true,"input":"Say hi."}`
	case "gemini":
		path = "/v1beta/models/smoke:generateContent"
		streamPath = "/v1beta/models/smoke:streamGenerateContent?alt=sse"
		body = `{"contents":[{"role":"user","parts":[{"text":"Say hi."}]}],"generationConfig":{"maxOutputTokens":16}}`
		streamBody = body
	}

	t.Run("nonstream", func(t *testing.T) {
		code, out := call(t, base, path, hdr, body)
		if code != 200 {
			t.Fatalf("status %d: %s", code, trunc(out))
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("not JSON: %v: %s", err, trunc(out))
		}
		checkShape(t, p.wire, m)
	})

	t.Run("stream", func(t *testing.T) {
		code, out := call(t, base, streamPath, hdr, streamBody)
		if code != 200 {
			t.Fatalf("status %d: %s", code, trunc(out))
		}
		for _, want := range streamMarkers[p.wire] {
			if !strings.Contains(out, want) {
				t.Errorf("SSE stream missing %q: %s", want, trunc(out))
			}
		}
	})

	// Gateway metrics: both calls counted as 200 and as an ok attempt on this provider kind.
	t.Run("metrics", func(t *testing.T) {
		attempts := fmt.Sprintf(`halo_proxy_upstream_attempts_total{provider=%q,outcome="ok"}`, p.kind)
		var text string
		for i := 0; i < 20; i++ { // the stream is counted when it finishes
			resp, err := http.Get(admin + "/metrics")
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			text = string(b)
			if metricAtLeast(text, attempts, 2) && metricAtLeast(text, `halo_proxy_requests_total{`, 2) && strings.Contains(text, `status="200"`) {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("metrics: want %s >= 2 and requests_total status=200 >= 2; got:\n%s", attempts, grepLines(text, "halo_proxy_requests_total", "halo_proxy_upstream_attempts_total"))
	})
}

// streamMarkers are substrings every successful SSE stream of a wire contains.
var streamMarkers = map[string][]string{
	"anthropic-messages": {"event: message_start", "event: message_stop"},
	"openai-responses":   {"event: response.created", "response.output_text.delta"},
	"gemini":             {"data: ", `"candidates"`},
}

func checkShape(t *testing.T, wire string, m map[string]any) {
	t.Helper()
	switch wire {
	case "anthropic-messages":
		if m["type"] != "message" || m["role"] != "assistant" {
			t.Errorf("want type=message role=assistant, got %v/%v", m["type"], m["role"])
		}
		if c, _ := m["content"].([]any); len(c) == 0 {
			t.Error("content is empty")
		}
		if u, _ := m["usage"].(map[string]any); u == nil || u["output_tokens"] == nil {
			t.Error("usage.output_tokens missing")
		}
	case "openai-responses":
		if m["object"] != "response" {
			t.Errorf("want object=response, got %v", m["object"])
		}
		if s := m["status"]; s != "completed" && s != "incomplete" { // incomplete = hit max_output_tokens
			t.Errorf("status %v", s)
		}
		if _, ok := m["output"].([]any); !ok {
			t.Error("output array missing")
		}
		if u, _ := m["usage"].(map[string]any); u == nil || u["output_tokens"] == nil {
			t.Error("usage.output_tokens missing")
		}
	case "gemini":
		if c, _ := m["candidates"].([]any); len(c) == 0 {
			t.Error("candidates is empty")
		}
		if u, _ := m["usageMetadata"].(map[string]any); u == nil {
			t.Error("usageMetadata missing")
		}
	}
}

// metricAtLeast: some line starting with prefix has a trailing integer value >= n.
func metricAtLeast(text, prefix string, n int) bool {
	for _, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, prefix) {
			continue
		}
		var v int
		if i := strings.LastIndexByte(l, ' '); i > 0 {
			if _, err := fmt.Sscanf(l[i+1:], "%d", &v); err == nil && v >= n {
				return true
			}
		}
	}
	return false
}

func grepLines(text string, subs ...string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		for _, s := range subs {
			if strings.HasPrefix(l, s) {
				out = append(out, l)
			}
		}
	}
	return strings.Join(out, "\n")
}
