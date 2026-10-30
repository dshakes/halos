package codex

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// TestEgressNetworkShape pins the forms the real CLIs accept (test/uat, codex
// 0.99.0 and 0.166.0): the allowed_domains/denied_domains lists, never the
// `domains` table 0.99.0 ignores, and no managed network_access = false under
// an allowlist, which would outrank the user's opt-in for good.
func TestEgressNetworkShape(t *testing.T) {
	for _, tc := range []struct {
		name      string
		egress    policy.Egress
		wantNet   map[string]any
		wantNA    any // network_access in managed_config.toml; nil = not rendered
		wantWarn  string
		forbidden string
	}{
		{
			name:     "allowlist, default deny",
			egress:   policy.Egress{AllowedDomains: []string{"Example.com", "github.com"}, DeniedDomains: []string{"pastebin.com"}},
			wantNet:  map[string]any{"enabled": true, "managed_allowed_domains_only": true, "allowed_domains": []any{"example.com", "github.com"}, "denied_domains": []any{"pastebin.com"}},
			wantNA:   nil,
			wantWarn: "leaves network_access unset",
		},
		{
			name:    "default deny, nothing allowed",
			egress:  policy.Egress{Default: policy.EgressDeny},
			wantNet: map[string]any{"enabled": true, "managed_allowed_domains_only": true},
			wantNA:  false,
		},
		{
			name:      "default allow, deny list only",
			egress:    policy.Egress{Default: policy.EgressAllow, DeniedDomains: []string{"transfer.sh"}},
			wantNet:   map[string]any{"enabled": true, "managed_allowed_domains_only": false, "denied_domains": []any{"transfer.sh"}},
			wantNA:    true,
			forbidden: "leaves network_access unset",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) {
				p.Permissions.Sandbox = "workspace-write"
				p.Egress = tc.egress
				p.Sandbox.ProtectedPaths = nil
			}, harness.Linux)
			if err != nil {
				t.Fatal(err)
			}
			net, _ := decode(t, files, requirementsPath)["experimental_network"].(map[string]any)
			if !reflect.DeepEqual(net, tc.wantNet) {
				t.Errorf("experimental_network = %#v, want %#v", net, tc.wantNet)
			}
			sw, _ := decode(t, files, managedConfigPath)["sandbox_workspace_write"].(map[string]any)
			if got := sw["network_access"]; got != tc.wantNA {
				t.Errorf("network_access = %#v, want %#v", got, tc.wantNA)
			}
			all := strings.Join(warns, "\n")
			if tc.wantWarn != "" && !strings.Contains(all, tc.wantWarn) {
				t.Errorf("missing warning %q in\n%s", tc.wantWarn, all)
			}
			if tc.forbidden != "" && strings.Contains(all, tc.forbidden) {
				t.Errorf("unexpected warning %q in\n%s", tc.forbidden, all)
			}
		})
	}
}

// TestProtectedPathsDenyRead: only absolute and ~ paths render; a relative one
// has no form Codex applies to the workspace (0.166.0 resolves it against
// /etc/codex and its bubblewrap refuses /**/ globs), so it warns instead.
func TestProtectedPathsDenyRead(t *testing.T) {
	for _, tc := range []struct {
		name      string
		paths     []string
		version   string
		wantDeny  []any // nil = no [permissions]
		wantWarns []string
		noWarns   []string
	}{
		{name: "absolute and home", paths: []string{"/etc/secrets", "~/.ssh", "~"}, version: "0.166.0",
			wantDeny: []any{"/etc/secrets", "~/.ssh", "~"}, wantWarns: []string{"rendered as deny_read"}, noWarns: []string{"are relative", "ignores requirements.toml"}},
		{name: "relative dropped", paths: []string{"~/.aws", ".env*", "./secrets/**", "**/id_rsa"}, version: "0.166.0",
			wantDeny: []any{"~/.aws"}, wantWarns: []string{"[.env* ./secrets/** **/id_rsa] are relative"}},
		{name: "only relative: no permissions table", paths: []string{".env*"}, version: "0.166.0",
			wantWarns: []string{"are relative"}, noWarns: []string{"rendered as deny_read"}},
		{name: "pin before 0.122 ignores deny_read", paths: []string{"~/.ssh"}, version: "0.99.0",
			wantDeny: []any{"~/.ssh"}, wantWarns: []string{"0.99.0 ignores requirements.toml [permissions.filesystem] deny_read"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, warns, err := render(func(p *policy.Profile, _ *policy.Gateway) {
				p.Sandbox.ProtectedPaths = tc.paths
				p.Harnesses[name] = policy.HarnessSpec{Version: tc.version}
			}, harness.Linux)
			if err != nil {
				t.Fatal(err)
			}
			req := decode(t, files, requirementsPath)
			var deny []any
			if perm, ok := req["permissions"].(map[string]any); ok {
				deny, _ = perm["filesystem"].(map[string]any)["deny_read"].([]any)
			}
			if !reflect.DeepEqual(deny, tc.wantDeny) {
				t.Errorf("deny_read = %#v, want %#v", deny, tc.wantDeny)
			}
			for _, d := range deny {
				if strings.HasPrefix(d.(string), "/**") {
					t.Errorf("deny_read %q has no non-root prefix (codex 0.166.0 refuses every sandboxed command)", d)
				}
			}
			all := strings.Join(warns, "\n")
			for _, w := range tc.wantWarns {
				if !strings.Contains(all, w) {
					t.Errorf("missing warning %q in\n%s", w, all)
				}
			}
			for _, w := range tc.noWarns {
				if strings.Contains(all, w) {
					t.Errorf("unexpected warning %q in\n%s", w, all)
				}
			}
		})
	}
}
