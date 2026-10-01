package server

import (
	"testing"

	"github.com/halos-dev/halos/internal/policy"
)

func TestRedact(t *testing.T) {
	p := &policy.Profile{
		Env: map[string]string{"API_KEY": "plain-value"},
		Harnesses: map[string]policy.HarnessSpec{"claude": {Version: "1", Overrides: map[string]any{
			"model":  "opus",
			"nested": map[string]any{"auth": "Bearer abc123", "list": []any{"ok", "sk-" + "abcdefghijklmnopqrstuvwxyz0123456789"}},
		}}},
	}
	p.MCP.Servers = []policy.MCPServer{{Name: "j", Headers: map[string]string{"Authorization": "x"}}}
	r := redact(p)
	if r.Env["API_KEY"] != "***" || r.MCP.Servers[0].Headers["Authorization"] != "***" {
		t.Errorf("env/headers not masked: %+v", r)
	}
	o := r.Harnesses["claude"].Overrides
	n := o["nested"].(map[string]any)
	if o["model"] != "opus" || n["auth"] != "***" || n["list"].([]any)[0] != "ok" || n["list"].([]any)[1] != "***" {
		t.Errorf("overrides: %+v", o)
	}
	if p.Env["API_KEY"] != "plain-value" || p.Harnesses["claude"].Overrides["nested"].(map[string]any)["auth"] != "Bearer abc123" || p.MCP.Servers[0].Headers["Authorization"] != "x" {
		t.Error("redact mutated the source profile")
	}
}
