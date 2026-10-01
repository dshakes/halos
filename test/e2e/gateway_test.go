//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/identity/identitytest"
	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/shadow"
)

const audience = "halos-gateway"

// gatewayPolicy extends newPolicy with an OIDC identity, the kiosk, two mock
// upstreams and a running 100%-sampled shadow experiment on both rings.
func gatewayPolicy(t *testing.T, dir, issuer, primary, candidate string) *policy.Org {
	t.Helper()
	newPolicy(t, dir)
	sw := filepath.Join(dir, "halos.yaml")
	writeFile(t, sw, readFile(t, sw)+`identity:
  issuer: `+issuer+`
  clientID: halos-portal
  audience: `+audience+`
  adminGroups: [ai-platform]
selfService:
  enabled: true
  launchers: [laptop]
  enrollmentTTLSeconds: 900
`)
	writeFile(t, filepath.Join(dir, "gateway.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Gateway
name: acme-gateway
baseURL: https://ai.acme.example
protocols:
  claude-code: anthropic-messages
auth:
  helperCommand: /usr/local/bin/acme-token
  ttlSeconds: 3300
upstreams:
  primary: {url: "`+primary+`", kind: anthropic}
  candidate: {url: "`+candidate+`", kind: anthropic}
models:
  sonnet: {upstream: primary, model: claude-sonnet-4-5}
`)
	writeFile(t, filepath.Join(dir, "experiments/shadow.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Experiment
name: sonnet-next-shadow
type: shadow
axis: traffic
status: running
rings: [ring0-canary, ring1-ga]
sampleRate: 1
variants:
  - {name: primary, weight: 1, control: true}
  - name: sonnet-next
    weight: 1
    routes:
      sonnet: {upstream: candidate, model: claude-sonnet-next}
metrics:
  primary: {metric: halo.task.success, direction: increase}
stopping: {method: msprt, alpha: 0.05, minSamples: 10, maxDays: 14, maxSpendUSD: 5}
`)
	if r := run(t, nil, "", "halo", "validate", dir); r.code != 0 {
		t.Fatalf("gateway policy invalid: %s", r)
	}
	org, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return org
}

// usersByRing finds one user id per ring via the same ResolveRing the gateway uses.
func usersByRing(t *testing.T, org *policy.Org) map[string]string {
	t.Helper()
	out := map[string]string{}
	for i := 0; i < 1000 && len(out) < len(org.Rings); i++ {
		u := fmt.Sprintf("dev%d@acme.com", i)
		if r := org.ResolveRing(policy.Subject{ID: u}); r != nil && out[r.Name] == "" {
			out[r.Name] = u
		}
	}
	if len(out) != len(org.Rings) {
		t.Fatalf("could not find a user for every ring: %v", out)
	}
	return out
}

func mint(t *testing.T, iss *identitytest.Issuer, user string, groups ...string) string {
	t.Helper()
	if groups == nil {
		groups = []string{}
	}
	tok, err := iss.Mint(map[string]any{"aud": audience, "email": user, "groups": groups})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestGatewayTrafficPlane: halo gateway compile -> halo-proxy + halo-shadow + mock
// upstreams, JWTs from a mock OIDC issuer.
func TestGatewayTrafficPlane(t *testing.T) {
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()

	primary, candidate := freeAddr(t), freeAddr(t)
	start(t, []string{"MOCK_NAME=primary", "LISTEN=" + primary}, "mockllm")
	start(t, []string{"MOCK_NAME=candidate", "LISTEN=" + candidate}, "mockllm")

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	org := gatewayPolicy(t, pol, iss.URL, "http://"+primary, "http://"+candidate)
	snap := filepath.Join(dir, "policy.json")
	must(t, nil, "halo", "gateway", "compile", pol, "-o", snap)

	shadowAddr, proxyAddr, adminAddr := freeAddr(t), freeAddr(t), freeAddr(t)
	pairs := filepath.Join(dir, "pairs.jsonl")
	start(t, []string{"HALO_SHADOW_TOKEN=e2e-shadow-token"}, "halo-shadow", "-listen", shadowAddr, "-policy", snap, "-out", pairs, "-budget-usd", "5")
	start(t, []string{"HALO_PROXY_HALO_SHADOW_TOKEN=e2e-shadow-token"}, "halo-proxy", "--listen", proxyAddr, "--admin-listen", adminAddr, "--policy", snap,
		"--halo-shadow-url", "http://"+shadowAddr+"/mirror")
	waitUp(t, "http://"+primary+"/v1/models", 200)
	waitUp(t, "http://"+candidate+"/v1/models", 200)
	waitUp(t, "http://"+shadowAddr+"/healthz", 200)
	waitUp(t, "http://"+adminAddr+"/healthz", 200) // 503 until the policy snapshot loads

	base := "http://" + proxyAddr
	send := func(path, body string, hdr map[string]string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	msg := func(model string, stream bool) string {
		return fmt.Sprintf(`{"model":%q,"max_tokens":5,"stream":%v,"messages":[{"role":"user","content":"hi"}]}`, model, stream)
	}
	users := usersByRing(t, org)

	for ring, user := range users {
		t.Run("ring "+ring, func(t *testing.T) {
			spoof := "ring0-canary"
			if ring == spoof {
				spoof = "ring1-ga"
			}
			resp, body := send("/v1/messages", msg("sonnet", false), map[string]string{
				"Authorization": "Bearer " + mint(t, iss, user), "x-halo-ring": spoof, "x-halo-variant": "sonnet-next",
				"x-claude-code-session-id": "sess-" + user,
			})
			if resp.StatusCode != 200 {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			if got := resp.Header.Get("X-Seen-X-Halo-Ring"); got != ring {
				t.Fatalf("upstream saw x-halo-ring %q, want %q (client spoofed %q)", got, ring, spoof)
			}
			if got := resp.Header.Get("X-Seen-X-Halo-Variant"); got == "sonnet-next" {
				t.Fatalf("spoofed x-halo-variant reached the upstream")
			}
			if resp.Header.Get("X-Mock-Served-By") != "primary" || resp.Header.Get("X-Mock-Model") != "claude-sonnet-4-5" {
				t.Fatalf("alias not rewritten/routed: served-by=%q model=%q", resp.Header.Get("X-Mock-Served-By"), resp.Header.Get("X-Mock-Model"))
			}
		})
	}
	ga := users["ring1-ga"]
	auth := map[string]string{"Authorization": "Bearer " + mint(t, iss, ga)}

	t.Run("unknown model 403", func(t *testing.T) {
		resp, body := send("/v1/messages", msg("gpt-4o", false), auth)
		if resp.StatusCode != 403 || !strings.Contains(body, "permission_error") || resp.Header.Get("X-Mock-Served-By") != "" {
			t.Fatalf("status %d served-by %q: %s", resp.StatusCode, resp.Header.Get("X-Mock-Served-By"), body)
		}
	})

	t.Run("forged identity 401", func(t *testing.T) {
		// identity headers without a token
		resp, body := send("/v1/messages", msg("sonnet", false), map[string]string{"x-acme-user": ga, "x-halo-user": ga, "x-halo-ring": "ring0-canary"})
		if resp.StatusCode != 401 {
			t.Fatalf("headers-only identity: status %d: %s", resp.StatusCode, body)
		}
		// a well-formed JWT for the right issuer/audience, signed by someone else's key
		forger, err := identitytest.NewIssuer("e2e") // same kid, different key
		if err != nil {
			t.Fatal(err)
		}
		forger.URL = iss.URL
		resp, body = send("/v1/messages", msg("sonnet", false), map[string]string{"Authorization": "Bearer " + mint(t, forger, ga)})
		if resp.StatusCode != 401 {
			t.Fatalf("forged JWT: status %d: %s", resp.StatusCode, body)
		}
		// right key, wrong audience
		tok, _ := iss.Mint(map[string]any{"aud": "someone-else", "email": ga})
		if resp, body = send("/v1/messages", msg("sonnet", false), map[string]string{"Authorization": "Bearer " + tok}); resp.StatusCode != 401 {
			t.Fatalf("wrong audience: status %d: %s", resp.StatusCode, body)
		}
	})

	t.Run("SSE streams incrementally", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, base+"/v1/messages", strings.NewReader(msg("sonnet", true)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth["Authorization"])
		t0 := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
			t.Fatalf("content-type %q", ct)
		}
		sc := bufio.NewScanner(resp.Body)
		var first time.Duration
		var events []string
		for sc.Scan() {
			if e, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				if first == 0 {
					first = time.Since(t0)
				}
				events = append(events, e)
			}
		}
		total := time.Since(t0)
		if len(events) < 3 || events[0] != "message_start" || events[len(events)-1] != "message_stop" {
			t.Fatalf("events: %v", events)
		}
		// mockllm sleeps 50ms between deltas: a buffering proxy delivers everything at the end.
		if total-first < 100*time.Millisecond {
			t.Fatalf("stream was buffered: first event at %s, done at %s", first, total)
		}
	})

	t.Run("count_tokens routed", func(t *testing.T) {
		resp, body := send("/v1/messages/count_tokens", `{"model":"sonnet","messages":[{"role":"user","content":"hi"}]}`, auth)
		if resp.StatusCode != 200 || !strings.Contains(body, `"input_tokens":7`) || resp.Header.Get("X-Mock-Model") != "claude-sonnet-4-5" {
			t.Fatalf("status %d model %q: %s", resp.StatusCode, resp.Header.Get("X-Mock-Model"), body)
		}
	})

	t.Run("shadow pair recorded", func(t *testing.T) {
		deadline := time.Now().Add(15 * time.Second)
		for {
			b, _ := os.ReadFile(pairs)
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				var p shadow.Pair
				if json.Unmarshal([]byte(line), &p) != nil || p.Experiment != "sonnet-next-shadow" {
					continue
				}
				if p.Control.Status == 200 && p.Candidate.Status == 200 &&
					strings.Contains(string(p.Candidate.Response), "served-by=candidate model=claude-sonnet-next") &&
					strings.Contains(string(p.Control.Response), "served-by=primary model=claude-sonnet-4-5") {
					return
				}
				t.Logf("pair not matching yet: %s", line)
			}
			if time.Now().After(deadline) {
				t.Fatalf("no complete shadow pair in %s:\n%s", pairs, b)
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
}
