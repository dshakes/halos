package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestExtensionsValidation(t *testing.T) {
	gh := Marketplace{Source: MarketplaceGitHub, Repo: "acme/plugins", Ref: "v1"}
	tests := []struct {
		name    string
		mut     func(*Profile)
		wantErr string // substring every error must contain; empty = valid
	}{
		{"valid full", func(p *Profile) {
			p.Login = LoginAPI
			p.Extensions = Extensions{
				Marketplaces:        []Marketplace{gh, {Source: MarketplaceGit, URL: "https://git.example.com/p.git", Ref: "main"}, {Source: MarketplaceURL, URL: "https://x.example.com/m.json"}, {Source: MarketplaceHostPattern, HostPattern: `^git\.example\.com$`}},
				BlockedMarketplaces: []Marketplace{{Source: MarketplaceGitHub, Repo: "bad/plugins"}},
				Plugins:             Plugins{Enabled: []string{"a@m"}, Blocked: []string{"b@m"}},
				Skills:              ExtensionSet{Deny: []string{"deploy"}, PluginOnly: true},
				Subagents:           ExtensionSet{Deny: []string{"Explore"}},
				OutputStyle:         "Explanatory",
				StatusLine:          StatusLine{Command: "/opt/sl.sh", Padding: 2},
			}
		}, ""},
		{"bad login", func(p *Profile) { p.Login = "sso" }, `login "sso" invalid`},
		{"unknown source", func(p *Profile) { p.Extensions.Marketplaces = []Marketplace{{Source: "npm"}} }, `source "npm" invalid`},
		{"github needs OWNER/REPO", func(p *Profile) {
			p.Extensions.Marketplaces = []Marketplace{{Source: MarketplaceGitHub, Repo: "acme/*"}}
		}, "must be OWNER/REPO"},
		{"github rejects url", func(p *Profile) {
			p.Extensions.Marketplaces = []Marketplace{{Source: MarketplaceGitHub, Repo: "a/b", URL: "https://x.example.com"}}
		}, "not valid for source"},
		{"url rejects ref", func(p *Profile) {
			p.Extensions.Marketplaces = []Marketplace{{Source: MarketplaceURL, URL: "https://x.example.com/m.json", Ref: "v1"}}
		}, "not valid for source"},
		{"git needs absolute url", func(p *Profile) {
			p.Extensions.BlockedMarketplaces = []Marketplace{{Source: MarketplaceGit, URL: "nope"}}
		}, "must be an absolute URL"},
		{"hostPattern must compile", func(p *Profile) {
			p.Extensions.Marketplaces = []Marketplace{{Source: MarketplaceHostPattern, HostPattern: "("}}
		}, "regular expression"},
		{"plugin key shape", func(p *Profile) { p.Extensions.Plugins.Enabled = []string{"noat"} }, "must be PLUGIN@MARKETPLACE"},
		{"plugin enabled and blocked", func(p *Profile) {
			p.Extensions.Plugins = Plugins{Enabled: []string{"a@m"}, Blocked: []string{"a@m"}}
		}, "both enabled and blocked"},
		{"skill name injection", func(p *Profile) { p.Extensions.Skills.Deny = []string{"x)"} }, "without parentheses"},
		{"subagent empty name", func(p *Profile) { p.Extensions.Subagents.Deny = []string{""} }, "non-empty name"},
		{"output style newline", func(p *Profile) { p.Extensions.OutputStyle = "a\nb" }, "newline"},
		{"negative padding", func(p *Profile) {
			p.Extensions.StatusLine = StatusLine{Command: "x", Padding: -1}
		}, "must be >= 0"},
		{"padding without command", func(p *Profile) { p.Extensions.StatusLine = StatusLine{Padding: 1} }, "command is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := validOrg()
			tc.mut(o.Profiles["base"])
			var errs []string
			for _, i := range o.Validate() {
				if i.Severity == SeverityError {
					errs = append(errs, i.String())
				}
			}
			// "next" extends "base", so the finding is reported once per profile.
			switch {
			case tc.wantErr == "" && len(errs) != 0:
				t.Fatalf("unexpected errors: %v", errs)
			case tc.wantErr != "" && len(errs) == 0:
				t.Fatalf("no error, want one containing %q", tc.wantErr)
			}
			for _, e := range errs {
				if !strings.Contains(e, tc.wantErr) {
					t.Errorf("error %q does not contain %q", e, tc.wantErr)
				}
			}
		})
	}
}

// Deny and blocked lists only accumulate down an extends chain, like
// permissions.deny; allowlists and scalars follow the usual child-wins rule.
func TestExtensionsExtendsMerge(t *testing.T) {
	o := validOrg()
	base, next := o.Profiles["base"], o.Profiles["next"]
	base.Extensions = Extensions{
		Marketplaces:        []Marketplace{{Source: MarketplaceGitHub, Repo: "a/one"}},
		BlockedMarketplaces: []Marketplace{{Source: MarketplaceGitHub, Repo: "bad/one"}},
		Plugins:             Plugins{Enabled: []string{"p@m"}, Blocked: []string{"x@m"}},
		Skills:              ExtensionSet{Deny: []string{"s1"}},
		Subagents:           ExtensionSet{Deny: []string{"a1"}},
		OutputStyle:         "Learning",
	}
	base.Login = LoginSubscription
	next.Extensions = Extensions{
		Marketplaces:        []Marketplace{{Source: MarketplaceGitHub, Repo: "a/two"}},
		BlockedMarketplaces: []Marketplace{{Source: MarketplaceGitHub, Repo: "bad/two"}},
		Plugins:             Plugins{Blocked: []string{"y@m", "x@m"}},
		Skills:              ExtensionSet{Deny: []string{"s2"}},
		Subagents:           ExtensionSet{Deny: []string{"a2"}},
	}
	p, err := o.ResolveProfile("next")
	if err != nil {
		t.Fatal(err)
	}
	e := p.Extensions
	if want := []Marketplace{{Source: MarketplaceGitHub, Repo: "a/two"}}; !slices.Equal(e.Marketplaces, want) {
		t.Errorf("marketplaces = %v, want child to replace: %v", e.Marketplaces, want)
	}
	if len(e.BlockedMarketplaces) != 2 {
		t.Errorf("blockedMarketplaces = %v, want union", e.BlockedMarketplaces)
	}
	if want := []string{"x@m", "y@m"}; !slices.Equal(e.Plugins.Blocked, want) {
		t.Errorf("plugins.blocked = %v, want %v", e.Plugins.Blocked, want)
	}
	if !slices.Equal(e.Plugins.Enabled, []string{"p@m"}) {
		t.Errorf("plugins.enabled = %v, want inherited", e.Plugins.Enabled)
	}
	if !slices.Equal(e.Skills.Deny, []string{"s1", "s2"}) || !slices.Equal(e.Subagents.Deny, []string{"a1", "a2"}) {
		t.Errorf("deny = %v %v, want union", e.Skills.Deny, e.Subagents.Deny)
	}
	if e.OutputStyle != "Learning" || p.Login != LoginSubscription {
		t.Errorf("scalars not inherited: %q %q", e.OutputStyle, p.Login)
	}
}
