package vendoradmin

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func cloudPlans(t *testing.T, mutate func(*policy.CloudAgents)) map[string]*Plan {
	t.Helper()
	org := exampleOrg(t)
	mutate(org.CloudAgents)
	rep, err := Render(org)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*Plan{}
	for _, p := range rep.Vendors {
		out[p.Vendor] = p
	}
	return out
}

func TestCloudAgentConsoleSteps(t *testing.T) {
	plans := cloudPlans(t, func(c *policy.CloudAgents) {
		c.Codex = &policy.CloudAgent{Enabled: true, Network: &policy.CloudNetwork{Mode: policy.NetworkAllowlist, Recommended: true, Allow: []string{"pkg.acme.example"}}}
		c.Claude.Network = &policy.CloudNetwork{Mode: policy.NetworkNone}
	})
	tests := []struct{ vendor, want string }{
		{"claude", "turn remote (cloud) sessions on"},
		{"claude", "network access None"},
		{"codex", "Common dependencies plus pkg.acme.example"},
		{"cursor", "turn cloud agents on"},
		{"copilot", "Repository access to Selected repositories: acme-corp/*"},
	}
	for _, tc := range tests {
		if !strings.Contains(strings.Join(plans[tc.vendor].Manual, "\n"), tc.want) {
			t.Errorf("%s manual steps miss %q:\n%s", tc.vendor, tc.want, strings.Join(plans[tc.vendor].Manual, "\n"))
		}
	}
	if !strings.Contains(strings.Join(plans["codex"].Warnings, "\n"), "no task API") {
		t.Error("codex: inventory gap not warned")
	}
	for name, n := range map[string]*policy.CloudNetwork{
		"Trusted": {Mode: policy.NetworkAllowlist, Recommended: true},
		"Full":    {Mode: policy.NetworkFull},
		"only":    {Mode: policy.NetworkAllowlist, Allow: []string{"a.example"}},
	} {
		if got := claudeNetwork(n); !strings.Contains(got, name) {
			t.Errorf("claudeNetwork %+v = %q, want %q", n, got, name)
		}
	}
	if got := codexNetwork(&policy.CloudNetwork{Mode: policy.NetworkNone}); got != "Off" {
		t.Errorf("codexNetwork none = %q", got)
	}
	off := cloudPlans(t, func(c *policy.CloudAgents) { c.Copilot.Enabled = false })
	if !strings.Contains(strings.Join(off["copilot"].Manual, "\n"), "No repositories") {
		t.Error("disabled copilot cloud agent must say no repositories")
	}
}

// The Copilot cloud agent firewall is read per explicit repository and
// diffed, never written: apply still writes content exclusion only.
func TestCopilotCloudAgentFirewallRead(t *testing.T) {
	plans := cloudPlans(t, func(c *policy.CloudAgents) { c.Copilot.Repos = []string{"acme-corp/web", "acme-corp/*"} })
	p := plans["copilot"]
	for _, k := range []string{"cloud_agent.acme-corp/web.is_firewall_enabled", "cloud_agent.acme-corp/web.custom_allowlist"} {
		if s, ok := setting(p, k); !ok || s.Access != AccessRead {
			t.Fatalf("%s: %+v %v", k, s, ok)
		}
	}
	routes := copilotRoutes(`["/.env","/.env.*","/secrets/**"]`)
	routes["GET /repos/acme-corp/web/copilot/cloud-agent/configuration"] = ok(`{"mcp_configuration":null,"is_firewall_enabled":false,"is_firewall_recommended_allowlist_enabled":true,"custom_allowlist":["evil.example"]}`)
	srv, got := fake(t, routes)
	c := NewClient("copilot", srv.URL, "ghp_secret", policy.VendorTarget{Org: "acme"})
	readDiff(t, c, p)
	var keys []string
	for _, ch := range p.Changes {
		keys = append(keys, ch.Key)
		// The live firewall is off and allows evil.example: policy is tighter,
		// so neither change loosens.
		if strings.HasPrefix(ch.Key, cloudKeyPrefix) && (ch.Loosens || ch.Access != AccessRead) {
			t.Fatalf("change %+v", ch)
		}
	}
	for _, k := range []string{"cloud_agent.acme-corp/web.is_firewall_enabled", "cloud_agent.acme-corp/web.custom_allowlist"} {
		if !slices.Contains(keys, k) {
			t.Fatalf("drift on %s not found in %v", k, keys)
		}
	}
	res, err := c.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if strings.HasPrefix(r.Change.Key, cloudKeyPrefix) {
			t.Fatalf("apply wrote a read-only cloud agent setting: %+v", r)
		}
	}
	for _, r := range *got {
		if r.method != "GET" && strings.Contains(r.path, "cloud-agent") {
			t.Fatalf("write to the cloud agent API: %+v", r)
		}
	}
}
