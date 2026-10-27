// Package hutiltest provides a shared rich fixture and golden-file helper for adapter tests.
package hutiltest

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
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
				{Name: "docs", URL: "https://mcp.example.com/docs", Headers: map[string]string{"X-Org": "acme"},
					Tools: policy.MCPTools{Allow: []string{"search", "fetch"}, Deny: []string{"delete_page"}}, Auth: policy.MCPAuth{Mode: policy.MCPAuthHalos}},
				{Name: "lint", Command: []string{"npx", "-y", "lint-mcp"}},
				{Name: "tickets", URL: "https://mcp.example.com/tickets",
					Auth: policy.MCPAuth{Mode: policy.MCPAuthOAuth, ClientID: "halos-cli", Issuer: "https://auth.example.com", Scopes: []string{"tickets:read"}}},
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
		Extensions: policy.Extensions{
			Marketplaces: []policy.Marketplace{
				{Source: policy.MarketplaceGitHub, Repo: "acme/plugins", Ref: "v1"},
				{Source: policy.MarketplaceHostPattern, HostPattern: `^git\.example\.com$`},
			},
			BlockedMarketplaces: []policy.Marketplace{{Source: policy.MarketplaceGitHub, Repo: "untrusted/plugins"}},
			Plugins:             policy.Plugins{Enabled: []string{"audit@acme-plugins"}, Blocked: []string{"risky@acme-plugins"}},
			Skills:              policy.ExtensionSet{Deny: []string{"deploy"}, PluginOnly: true},
			Subagents:           policy.ExtensionSet{Deny: []string{"Explore"}},
			OutputStyle:         "Explanatory",
			StatusLine:          policy.StatusLine{Command: "/opt/halo/statusline.sh", Padding: 1},
		},
		Login: policy.LoginAPI,
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

// ZeroField zeroes the field at a dotted json path ("extensions.statusLine").
// mcp.tools.allow, mcp.tools.deny and mcp.auth are per-server fields
// (hutil.Populated reports them once): they are zeroed on every server.
func ZeroField(p *policy.Profile, path string) bool {
	for i := range p.MCP.Servers {
		sv := &p.MCP.Servers[i]
		switch path {
		case "mcp.tools.allow":
			sv.Tools.Allow = nil
		case "mcp.tools.deny":
			sv.Tools.Deny = nil
		case "mcp.auth":
			sv.Auth = policy.MCPAuth{}
		}
	}
	switch path {
	case "mcp.tools.allow", "mcp.tools.deny", "mcp.auth":
		return true
	}
	v := reflect.ValueOf(p).Elem()
	for _, part := range strings.Split(path, ".") {
		found := false
		for i := 0; i < v.NumField(); i++ {
			if tag := strings.Split(v.Type().Field(i).Tag.Get("json"), ",")[0]; tag == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return false
		}
	}
	v.Set(reflect.Zero(v.Type()))
	return true
}
