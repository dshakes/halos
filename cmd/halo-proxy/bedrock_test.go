package main

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/dshakes/halos/internal/policy"
)

const arnModel = "arn:aws:bedrock:us-east-1:1:inference-profile/us.anthropic.x"

// bedrockEnv routes alias "sonnet" to a kind: bedrock upstream (region set,
// since httptest listens on 127.0.0.1) and gives halo-proxy static creds.
func bedrockEnv(t *testing.T, up *httptest.Server, akid string) *env {
	t.Helper()
	e := testEnv(t, up, func(_ *Config, o *policy.Org) {
		o.Gateway.Upstreams["up"] = policy.Upstream{URL: up.URL, Kind: "bedrock", Region: "us-west-2"}
		o.Gateway.Models["sonnet"] = policy.ModelRoute{Upstream: "up", Model: arnModel}
	})
	e.p.sigv4.Credentials = credentials.NewStaticCredentialsProvider(akid, "SECRET", "")
	e.p.cfg.SignHosts = []string{"127.0.0.1"} // httptest listener
	return e
}

func TestBedrockNonAWSHostRefused(t *testing.T) {
	up, s := recordingServer(t)
	e := bedrockEnv(t, up, "AKIDTEST")
	e.p.cfg.SignHosts = nil
	resp := e.post(t, "/model/sonnet/invoke", e.token(t, "bob@acme.com"), `{"messages":[]}`, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatal("request reached a non-AWS host")
	}
}

func TestBedrockClientAmzHeadersStripped(t *testing.T) {
	up, s := recordingServer(t)
	e := bedrockEnv(t, up, "AKIDTEST")
	e.p.cfg.UpstreamHeaders = map[string]map[string]string{"up": {"X-Amzn-Bedrock-GuardrailIdentifier": "gr-1"}}
	resp := e.post(t, "/model/sonnet/invoke", e.token(t, "bob@acme.com"), `{"messages":[]}`,
		map[string]string{"X-Amz-Meta-Evil": "1", "X-Amzn-Trace-Id": "evil", "X-Amz-Target": "evil"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, h, _, _ := s.get()
	for _, k := range []string{"X-Amz-Meta-Evil", "X-Amzn-Trace-Id", "X-Amz-Target"} {
		if h.Get(k) != "" {
			t.Errorf("client header %s reached upstream", k)
		}
	}
	if h.Get("X-Amzn-Bedrock-GuardrailIdentifier") != "gr-1" || !strings.Contains(h.Get("Authorization"), "x-amzn-bedrock-guardrailidentifier") {
		t.Errorf("gateway header missing or unsigned: %v", h)
	}
}

func TestBedrockDirectSigned(t *testing.T) {
	up, s := recordingServer(t)
	e := bedrockEnv(t, up, "AKIDTEST")
	tok := e.token(t, "bob@acme.com")
	for _, op := range []string{"invoke", "converse"} {
		resp := e.post(t, "/model/sonnet/"+op, tok, `{"messages":[]}`, map[string]string{"x-api-key": "client-key", "Content-Type": "application/json"})
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", op, resp.StatusCode)
		}
		_, h, _, raw := s.get()
		if want := "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fus.anthropic.x/" + op; raw != want {
			t.Fatalf("path %q want %q", raw, want)
		}
		a := h.Get("Authorization")
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") || !strings.Contains(a, "/us-west-2/bedrock/aws4_request") {
			t.Fatalf("%s: Authorization %q (client bearer must be replaced by SigV4)", op, a)
		}
		if h.Get("x-api-key") != "" || h.Get("X-Amz-Date") == "" {
			t.Fatalf("%s: headers %v", op, h)
		}
	}
}

func TestBedrockMissingCredentials502(t *testing.T) {
	up, s := recordingServer(t)
	e := bedrockEnv(t, up, "")
	resp := e.post(t, "/model/sonnet/invoke", e.token(t, "bob@acme.com"), `{"messages":[]}`, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(b), "no AWS credentials") {
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatal("unsigned request reached Bedrock")
	}
}

// A kind: bedrock upstream on a non-AWS host without region is an
// orchestrator/sidecar that signs itself: forwarded unsigned, as before.
func TestBedrockSidecarNotSigned(t *testing.T) {
	up, s := recordingServer(t)
	e := testEnv(t, up, func(_ *Config, o *policy.Org) {
		o.Gateway.Upstreams["up"] = policy.Upstream{URL: up.URL, Kind: "bedrock"}
	})
	e.p.sigv4.Credentials = credentials.NewStaticCredentialsProvider("", "", "") // would 502 if used
	if resp := e.post(t, "/model/sonnet/invoke", e.token(t, "bob@acme.com"), `{"messages":[]}`, nil); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, h, _, _ := s.get(); h.Get("Authorization") != "" {
		t.Fatalf("sidecar upstream got Authorization %q", h.Get("Authorization"))
	}
}

func TestBedrockEventStreamFlushedIncrementally(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = io.WriteString(w, "frame-1\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "frame-2\n")
	}))
	t.Cleanup(up.Close)
	e := bedrockEnv(t, up, "AKIDTEST")
	resp := e.post(t, "/model/sonnet/invoke-with-response-stream", e.token(t, "bob@acme.com"), `{"messages":[]}`, nil)
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != 200 || ct != "application/vnd.amazon.eventstream" {
		t.Fatalf("status %d content-type %q", resp.StatusCode, ct)
	}
	br := bufio.NewReader(resp.Body)
	line := make(chan string, 1)
	go func() { l, _ := br.ReadString('\n'); line <- l }()
	select {
	case l := <-line:
		if l != "frame-1\n" {
			t.Fatalf("first frame %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first eventstream frame not delivered before upstream finished: response is buffered")
	}
	once.Do(func() { close(release) })
	if rest, _ := io.ReadAll(br); string(rest) != "frame-2\n" {
		t.Fatalf("rest %q", rest)
	}
}
