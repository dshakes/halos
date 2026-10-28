package policy

import (
	"strings"
	"testing"
)

func TestCloudAgentsValidate(t *testing.T) {
	gh := &Workloads{Audience: "halos", Issuers: []WorkloadIssuer{{Name: "github", URL: "https://token.actions.githubusercontent.com"}}}
	tests := []struct {
		name string
		ca   *CloudAgents
		wl   *Workloads
		want string // substring of a cloudAgents issue; "" = none
		sev  Severity
	}{
		{"ok", &CloudAgents{
			Identities: []CloudIdentity{{User: "alice@acme.com", GitHub: "alice-gh"}},
			Claude:     &CloudAgent{Enabled: true, Repos: []string{"acme/app", "acme/*"}, Models: []string{"claude-sonnet-5"}, Network: &CloudNetwork{Mode: NetworkAllowlist, Recommended: true}},
			Cursor:     &CloudAgent{Enabled: true, Budgets: []Budget{{Name: "daily", Scope: ScopeUser, Window: WindowDay, LimitTokens: 1000}}},
		}, nil, "", ""},
		{"bad repo", &CloudAgents{Claude: &CloudAgent{Enabled: true, Repos: []string{"acme"}}}, nil, "not owner/repo", SeverityError},
		{"repo traversal", &CloudAgents{Claude: &CloudAgent{Enabled: true, Repos: []string{"acme/../x/y"}}}, nil, "not owner/repo", SeverityError},
		{"bad model", &CloudAgents{Claude: &CloudAgent{Enabled: true, Models: []string{"a b"}}}, nil, "not a model id", SeverityError},
		{"models unsupported warn", &CloudAgents{Copilot: &CloudAgent{Enabled: true, Models: []string{"gpt-5"}}}, nil, "takes no model", SeverityWarning},
		{"duplicate login", &CloudAgents{Identities: []CloudIdentity{{User: "a", GitHub: "X"}, {User: "b", GitHub: "x"}}}, nil, "mapped twice", SeverityError},
		{"identity without login", &CloudAgents{Identities: []CloudIdentity{{User: "a"}}}, nil, "at least one vendor login", SeverityError},
		{"login injection", &CloudAgents{Identities: []CloudIdentity{{User: "a", GitHub: "a\x1b[2J"}}}, nil, "not a GitHub login", SeverityError},
		{"perGroup needs groups", &CloudAgents{Codex: &CloudAgent{Enabled: true, MaxConcurrent: CloudConcurrency{PerGroup: 2}}}, nil, "perGroup needs", SeverityError},
		{"negative limit", &CloudAgents{Codex: &CloudAgent{Enabled: true, MaxConcurrent: CloudConcurrency{PerUser: -1}}}, nil, ">= 0", SeverityError},
		{"budget enforce", &CloudAgents{Cursor: &CloudAgent{Enabled: true, Budgets: []Budget{{Name: "b", Scope: ScopeUser, Window: WindowDay, LimitTokens: 1, Action: BudgetEnforce}}}}, nil, "onOverLimit: pause", SeverityError},
		{"budget reuse checks", &CloudAgents{Cursor: &CloudAgent{Enabled: true, Budgets: []Budget{{Name: "b", Scope: "team", Window: WindowDay, LimitTokens: 1}}}}, nil, "scope", SeverityError},
		{"budget usd on cursor warns", &CloudAgents{Cursor: &CloudAgent{Enabled: true, Budgets: []Budget{{Name: "b", Scope: ScopeOrg, Window: WindowDay, LimitUSD: 5}}}}, nil, "only limitTokens", SeverityWarning},
		{"budget unread vendor warns", &CloudAgents{Codex: &CloudAgent{Enabled: true, Budgets: []Budget{{Name: "b", Scope: ScopeOrg, Window: WindowDay, LimitTokens: 5}}}}, nil, "count nothing", SeverityWarning},
		{"network bad mode", &CloudAgents{Claude: &CloudAgent{Enabled: true, Network: &CloudNetwork{Mode: "open"}}}, nil, "mode", SeverityError},
		{"network full warns", &CloudAgents{Claude: &CloudAgent{Enabled: true, Network: &CloudNetwork{Mode: NetworkFull}}}, nil, "exfiltrate", SeverityWarning},
		{"network empty allowlist", &CloudAgents{Claude: &CloudAgent{Enabled: true, Network: &CloudNetwork{Mode: NetworkAllowlist}}}, nil, "mode none", SeverityError},
		{"network allow on none", &CloudAgents{Claude: &CloudAgent{Enabled: true, Network: &CloudNetwork{Mode: NetworkNone, Allow: []string{"a.com"}}}}, nil, "allowlist only", SeverityError},
		{"network bad domain", &CloudAgents{Codex: &CloudAgent{Enabled: true, Network: &CloudNetwork{Mode: NetworkAllowlist, Allow: []string{"https://a.com/x"}}}}, nil, "not a lowercase domain", SeverityError},
		{"network unsupported warns", &CloudAgents{Gemini: &CloudAgent{Enabled: true, Network: &CloudNetwork{Mode: NetworkNone}}}, nil, "no egress setting", SeverityWarning},
		{"workload on codex", &CloudAgents{Codex: &CloudAgent{Enabled: true, Identity: CloudIdentityWorkload}}, gh, "applies to claude and gemini", SeverityError},
		{"workload needs issuer", &CloudAgents{Server: "https://halo.acme.example", HaloVersion: "v0.3.0", Claude: &CloudAgent{Enabled: true, Identity: CloudIdentityWorkload}}, nil, "workloads issuer", SeverityError},
		{"workload needs https server", &CloudAgents{Server: "http://halo.acme.example", HaloVersion: "v0.3.0", Claude: &CloudAgent{Enabled: true, Identity: CloudIdentityWorkload}}, gh, "cloudAgents.server", SeverityError},
		{"workload needs tag", &CloudAgents{Server: "https://halo.acme.example", HaloVersion: "main", Claude: &CloudAgent{Enabled: true, Identity: CloudIdentityWorkload}}, gh, "haloVersion", SeverityError},
		{"workload ok", &CloudAgents{Server: "https://halo.acme.example", HaloVersion: "v0.3.0", Gemini: &CloudAgent{Enabled: true, Identity: CloudIdentityWorkload}}, gh, "", ""},
		{"bad identity", &CloudAgents{Claude: &CloudAgent{Enabled: true, Identity: "oauth"}}, nil, "identity", SeverityError},
		{"bad onOverLimit", &CloudAgents{Claude: &CloudAgent{Enabled: true, OnOverLimit: "resume"}}, nil, "onOverLimit", SeverityError},
		{"copilot timeout", &CloudAgents{Copilot: &CloudAgent{Enabled: true, TimeoutMinutes: 60}}, nil, "at most 59", SeverityError},
		{"bad version", &CloudAgents{Gemini: &CloudAgent{Enabled: true, Version: "latest"}}, nil, "semantic version", SeverityError},
		{"disabled with repos warns", &CloudAgents{Cursor: &CloudAgent{Repos: []string{"acme/app"}}}, nil, "disabled", SeverityWarning},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := mustLoad(t)
			o.CloudAgents, o.Workloads = tc.ca, tc.wl
			var hit *Issue
			for _, i := range o.Validate() {
				if !strings.HasPrefix(i.Path, "cloudAgents") {
					continue
				}
				if tc.want == "" {
					t.Fatalf("unexpected issue %v", i)
				}
				if strings.Contains(i.String(), tc.want) && (hit == nil || i.Severity == tc.sev) {
					hit = &i
				}
			}
			if tc.want != "" && (hit == nil || hit.Severity != tc.sev) {
				t.Fatalf("want %s %q, got %v", tc.sev, tc.want, hit)
			}
		})
	}
}

func TestCloudAgentMatchers(t *testing.T) {
	a := &CloudAgent{Repos: []string{"Acme/app", "tools/*"}, Models: []string{"m1"}}
	for repo, want := range map[string]bool{"acme/app": true, "acme/other": false, "tools/x": true, "toolsx/y": false, "": false} {
		if got := a.RepoAllowed(repo); got != want {
			t.Errorf("RepoAllowed(%q) = %v, want %v", repo, got, want)
		}
	}
	if !(&CloudAgent{}).RepoAllowed("any/repo") || (*CloudAgent)(nil).RepoAllowed("a/b") {
		t.Error("no patterns allows every repo; an ungoverned vendor allows none")
	}
	if !a.ModelAllowed("m1") || a.ModelAllowed("m2") || !a.ModelAllowed("") {
		t.Error("ModelAllowed")
	}
	c := &CloudAgents{Identities: []CloudIdentity{{User: "alice", GitHub: "Alice-GH"}}}
	if u, ok := c.UserForGitHub("alice-gh"); !ok || u != "alice" {
		t.Errorf("UserForGitHub = %q %v", u, ok)
	}
	if _, ok := c.UserForGitHub("mallory"); ok {
		t.Error("unknown login resolved")
	}
}
