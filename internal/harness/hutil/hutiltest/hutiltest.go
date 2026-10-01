// Package hutiltest provides a shared rich fixture and golden-file helper for adapter tests.
package hutiltest

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/halos-dev/halos/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Fixture returns a profile exercising every field, plus a gateway.
func Fixture() (*policy.Profile, *policy.Gateway) {
	p := &policy.Profile{
		Meta: policy.Meta{APIVersion: policy.APIVersion, Kind: policy.KindProfile, Name: "rich"},
		Harnesses: map[string]policy.HarnessSpec{
			"claude-code": {Version: "2.1.280"},
		},
		Models:      policy.Models{Default: "halo-sonnet", Allowed: []string{"halo-sonnet", "halo-haiku"}, Enforce: true},
		Permissions: policy.Permissions{Mode: "acceptEdits", Allow: []string{"Bash(go test:*)"}, Deny: []string{"Read(./.env)"}, Ask: []string{"Bash(git push:*)"}, DisableBypass: true, Sandbox: "off"},
		MCP: policy.MCP{
			ManagedOnly: true,
			Servers: []policy.MCPServer{
				{Name: "docs", URL: "https://mcp.example.com/docs", Headers: map[string]string{"X-Org": "acme"}},
				{Name: "lint", Command: []string{"npx", "-y", "lint-mcp"}},
			},
			Denied: []string{"filesystem"},
		},
		Hooks: policy.Hooks{ManagedOnly: true, Hooks: []policy.Hook{
			{Event: "PreToolUse", Matcher: "Bash", Command: "/opt/halo/audit.sh"},
			{Event: "SessionStart", Command: "/opt/halo/start.sh"},
		}},
		Telemetry: policy.Telemetry{Enabled: true, OTLPEndpoint: "https://otel.example.com:4317", Protocol: "grpc", LogPrompts: true,
			Attributes: map[string]string{"team": "platform eng", "cost-center": "a/b"}},
		Egress:       policy.Egress{AllowedDomains: []string{"example.com", "github.com"}},
		Instructions: "Be careful.\n",
		Env:          map[string]string{"FOO": "bar"},
	}
	g := &policy.Gateway{
		BaseURL: "https://gw.example.com",
		Protocols: map[string]string{
			"claude-code": "anthropic-messages", "codex": "openai-responses", "gemini-cli": "gemini",
		},
		Auth: policy.GatewayAuth{HelperCommand: "/opt/halo/token.sh", TTLSeconds: 300},
	}
	return p, g
}

// Golden compares got to testdata/name, rewriting it under -update.
func Golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if string(want) != string(got) {
		t.Errorf("golden %s mismatch (run with -update)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}
