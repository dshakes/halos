package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// fakeSlackToken is assembled at runtime: no literal secret in the repo.
func fakeSlackToken() string {
	return "xo" + "xb-" + strings.Repeat("7", 11) + "-" + strings.Repeat("4", 12) + "-" + "q8Zr2LmN5vXc1BwT9yKd3HfJ"
}

func dlpPolicy(t *testing.T, d *policy.DLP) string {
	t.Helper()
	org := &policy.Org{
		Name: "acme",
		Gateway: &policy.Gateway{
			Models:    map[string]policy.ModelRoute{"sonnet": {Upstream: "up", Model: "claude-sonnet"}},
			Upstreams: map[string]policy.Upstream{"up": {URL: "https://api.anthropic.com", Kind: "anthropic"}},
			DLP:       d,
		},
		Rings: []*policy.Ring{{Meta: policy.Meta{Name: "ga"}, Order: 0, Membership: policy.Membership{Default: true}}},
	}
	b, err := policy.Compile(org)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccessDLP(t *testing.T) {
	secret := fakeSlackToken()
	body := `{"model":"sonnet","messages":[{"role":"user","content":"token ` + secret + `"}]}`
	hdrs := map[string][]string{"x-acme-user": {"alice"}}

	// redact: the upstream body carries the marker, never the secret.
	k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(body), hdrs: hdrs}
	trustedCfg(dlpPolicy(t, &policy.DLP{Secrets: policy.DLPSecrets{Action: policy.DLPRedact}})).access(k)
	marker := gateway.RedactionMarker("slack-token", gateway.SecretHash(secret))
	if k.exitStatus != 0 || strings.Contains(k.newBody, secret) || !strings.Contains(k.newBody, marker) || !json.Valid([]byte(k.newBody)) {
		t.Fatalf("redact: exit %d body %s", k.exitStatus, k.newBody)
	}
	logs := strings.Join(k.logs, "\n")
	if !strings.Contains(logs, "dlp secret slack-token redact") || strings.Contains(logs, secret) {
		t.Fatalf("logs %q", logs)
	}

	// block: refused in the caller's wire format, nothing forwarded.
	k = &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(body), hdrs: hdrs}
	trustedCfg(dlpPolicy(t, &policy.DLP{Secrets: policy.DLPSecrets{Action: policy.DLPBlock}})).access(k)
	if k.exitStatus != http.StatusBadRequest || !strings.Contains(string(k.exitBody), "slack-token") || strings.Contains(string(k.exitBody), secret) || k.newBody != "" {
		t.Fatalf("block: exit %d %s", k.exitStatus, k.exitBody)
	}
	var b strings.Builder
	kmetrics.write(&b)
	if !strings.Contains(b.String(), `halo_kong_dlp_findings_total{kind="secret",detector="slack-token",action="block"}`) {
		t.Fatalf("metrics %s", b.String())
	}
}
