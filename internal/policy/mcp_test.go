package policy

import (
	"slices"
	"strings"
	"testing"
)

// The example registry (examples/acme-corp/halos.yaml): [0] acme-wiki
// (remote, auth halos, rings 0-1), [1] github (remote, unit payments),
// [2] playwright (npm, ring0).

func TestValidateMCPRegistry(t *testing.T) {
	sha := "sha256:" + strings.Repeat("c", 64)
	for _, tc := range []struct {
		name string
		mod  func(o *Org)
		want []string
	}{
		{"example is valid", func(*Org) {}, nil},
		{"bad mode fails closed (allowlist)", func(o *Org) { o.MCP.Mode = "block" },
			[]string{"mcp.mode", "profiles[base].mcp.servers[0]", "profiles[base].mcp.servers[1]"}},
		{"id with underscore, duplicate id", func(o *Org) {
			o.MCP.Servers[0].ID = "acme_wiki"
			o.MCP.Servers[2].ID = "github"
		}, []string{"mcp.servers[0].id", "mcp.servers[2].id"}},
		{"url and package", func(o *Org) {
			o.MCP.Servers[0].Package = &MCPPackage{Type: MCPPackageNPM, Identifier: "x", Version: "1.0.0"}
		},
			[]string{"mcp.servers[0]"}},
		{"plain http url", func(o *Org) { o.MCP.Servers[0].URL = "http://mcp-wiki.internal.acme.example/mcp" }, []string{"mcp.servers[0].url"}},
		{"npm range", func(o *Org) { o.MCP.Servers[2].Package.Version = "^0.0.41" }, []string{"mcp.servers[2].package.version"}},
		{"npm latest", func(o *Org) { o.MCP.Servers[2].Package.Version = "latest" }, []string{"mcp.servers[2].package.version"}},
		{"oci without digest, with tag", func(o *Org) {
			o.MCP.Servers[2].Package = &MCPPackage{Type: MCPPackageOCI, Identifier: "ghcr.io/acme/mcp:1.0"}
		}, []string{"mcp.servers[2].package.sha256", "mcp.servers[2].package.identifier"}},
		{"oci pinned", func(o *Org) {
			o.MCP.Servers[2].Package = &MCPPackage{Type: MCPPackageOCI, Identifier: "ghcr.io/acme/mcp", SHA256: sha}
		}, nil},
		{"binary without command", func(o *Org) { o.MCP.Servers[2].Package = &MCPPackage{Type: MCPPackageBinary, SHA256: sha} },
			[]string{"mcp.servers[2].command"}},
		{"package with command", func(o *Org) { o.MCP.Servers[2].Command = []string{"npx", "x"} }, []string{"mcp.servers[2].command"}},
		{"neither url, package nor command", func(o *Org) { o.MCP.Servers[2].Package = nil }, []string{"mcp.servers[2]"}},
		{"literal secret header", func(o *Org) { o.MCP.Servers[1].Headers["Authorization"] = "Bearer ghp_" + strings.Repeat("a", 36) },
			[]string{"mcp.servers[1].headers.Authorization"}},
		{"unknown ring and unit", func(o *Org) { o.MCP.Servers[0].Rings, o.MCP.Servers[0].Units = []string{"nope"}, []string{"nope"} },
			[]string{"mcp.servers[0].rings", "mcp.servers[0].units"}},
		{"tool both allowed and denied, bad tool name", func(o *Org) {
			o.MCP.Servers[0].Tools = MCPTools{Allow: []string{"delete_page", "a b"}, Deny: []string{"delete_page"}}
		}, []string{"mcp.servers[0].tools.allow[0]", "mcp.servers[0].tools.allow[1]"}},
		{"auth on a stdio server", func(o *Org) { o.MCP.Servers[2].Auth = MCPAuth{Mode: MCPAuthOAuth} }, []string{"mcp.servers[2].auth.mode"}},
		{"oauth with client id and metadata document", func(o *Org) {
			o.MCP.Servers[1].Auth = MCPAuth{Mode: MCPAuthOAuth, ClientID: "c", ClientIDMetadataURL: "https://acme.example/client.json"}
		}, []string{"mcp.servers[1].auth"}},
		{"oauth with http metadata document", func(o *Org) {
			o.MCP.Servers[1].Auth = MCPAuth{Mode: MCPAuthOAuth, ClientIDMetadataURL: "http://acme.example/client.json"}
		}, []string{"mcp.servers[1].auth.clientIDMetadataURL"}},
		{"unknown auth mode", func(o *Org) { o.MCP.Servers[1].Auth = MCPAuth{Mode: "passthrough"} }, []string{"mcp.servers[1].auth.mode"}},
		{"halos mode with scopes", func(o *Org) { o.MCP.Servers[0].Auth.Scopes = []string{"read"} }, []string{"mcp.servers[0].auth"}},
		{"enterprise without identity.issuer", func(o *Org) {
			o.Identity.Issuer = ""
			o.MCP.Servers[1].Auth = MCPAuth{Mode: MCPAuthEnterprise}
		}, []string{"mcp.servers[1].auth.mode"}},
		{"allowlist: profile server outside the registry", func(o *Org) {
			o.MCP.Mode = ""
			o.Profiles["base"].MCP.Servers = []MCPServer{{Name: "rogue", URL: "https://rogue.example/mcp"}}
		}, []string{"profiles[base].mcp.servers[0]"}},
		{"profile redefines a registry server", func(o *Org) {
			o.Profiles["base"].MCP.Servers = []MCPServer{{Name: "acme-wiki", URL: "https://mcp-wiki.internal.acme.example/mcp"}}
		}, []string{"profiles[base].mcp.servers[0]"}},
		{"toggle differs from the registry", func(o *Org) { o.MCP.Servers[1].URL = "https://api.githubcopilot.com/other/" },
			[]string{"toggles[github-mcp].client.harnesses.claude-code.mcpServers[0]"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := mustLoad(t)
			if o.MCP == nil || len(o.MCP.Servers) != 3 {
				t.Fatalf("example registry changed: %+v", o.MCP)
			}
			tc.mod(o)
			got := agentErrors(o)
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("errors %v, want %v", got, want)
			}
		})
	}
}

func TestWithMCPRegistry(t *testing.T) {
	o := mustLoad(t)
	base := o.Profiles["base"]
	own := len(base.MCP.Servers) // acme-docs, acme-tickets
	names := func(p *Profile) []string {
		var out []string
		for _, s := range p.MCP.Servers[own:] {
			out = append(out, s.Name)
		}
		return out
	}
	for _, tc := range []struct {
		name, ring, unit string
		allowlist        bool
		want             []string
	}{
		{"ga ring gets none", "ring3-ga", "", false, nil},
		{"canary ring", "ring1-canary", "", false, []string{"acme-wiki"}},
		{"harness team gets the pinned package", "ring0-harness-team", "", false, []string{"acme-wiki", "playwright"}},
		{"unit below payments", "ring3-ga", "checkout", false, []string{"github"}},
		{"allowlist locks", "ring1-canary", "", true, []string{"acme-wiki"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o.MCP.Mode = MCPModeWarn
			if tc.allowlist {
				o.MCP.Mode = MCPModeAllowlist
			}
			p, err := o.WithMCPRegistry(base, tc.ring, tc.unit)
			if err != nil {
				t.Fatal(err)
			}
			if got := names(p); !slices.Equal(got, tc.want) || p.MCP.ManagedOnly != (tc.allowlist || base.MCP.ManagedOnly) {
				t.Fatalf("servers %v managedOnly %v, want %v", got, p.MCP.ManagedOnly, tc.want)
			}
			if len(base.MCP.Servers) != own {
				t.Fatal("input profile modified")
			}
		})
	}
	p, err := o.WithMCPRegistry(base, "ring0-harness-team", "")
	if err != nil {
		t.Fatal(err)
	}
	if w, pw := p.MCP.Servers[own], p.MCP.Servers[own+1]; w.Auth.Mode != MCPAuthHalos || !slices.Equal(w.Tools.Deny, []string{"delete_page"}) ||
		!slices.Equal(pw.Command, []string{"npx", "-y", "@playwright/mcp@0.0.41"}) {
		t.Errorf("acme-wiki = %+v, playwright = %+v", w, pw)
	}
	// A server the profile already lists by name is kept as is.
	p2, _ := o.WithMCPRegistry(p, "ring0-harness-team", "")
	if len(p2.MCP.Servers) != len(p.MCP.Servers) {
		t.Errorf("re-applying added servers: %d -> %d", len(p.MCP.Servers), len(p2.MCP.Servers))
	}
	if _, err := o.WithMCPRegistry(base, "ring3-ga", "nope"); err == nil {
		t.Error("unknown unit: want error")
	}
	o.MCP = nil
	if p, err := o.WithMCPRegistry(base, "ring0-harness-team", ""); err != nil || len(p.MCP.Servers) != own {
		t.Errorf("no registry: %v %v", p.MCP.Servers, err)
	}
}

func TestMCPPins(t *testing.T) {
	o := mustLoad(t)
	for ring, want := range map[string][]string{
		"ring3-ga":           {"github=payments"},
		"ring0-harness-team": {"acme-wiki=", "github=payments", "playwright="},
	} {
		var got []string
		for _, p := range o.MCP.MCPPins(ring) {
			got = append(got, p.ID+"="+strings.Join(p.Units, ","))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s pins %v, want %v", ring, got, want)
		}
	}
	if pins := o.MCP.MCPPins("ring0-harness-team"); pins[2].Package == nil || !slices.Equal(pins[2].Command, []string{"npx", "-y", "@playwright/mcp@0.0.41"}) {
		t.Errorf("playwright pin = %+v", pins[2])
	}
	if (*MCPRegistry)(nil).MCPPins("ring3-ga") != nil {
		t.Error("nil registry: want no pins")
	}
}

func TestCanonicalResource(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"https://MCP.Example.com:443/mcp/", "https://mcp.example.com/mcp", true},
		{"https://mcp.example.com:8443/a", "https://mcp.example.com:8443/a", true},
		{"https://[::1]/mcp", "https://[::1]/mcp", true},
		{"https://mcp.example.com", "https://mcp.example.com", true},
		{"http://mcp.example.com/mcp", "", false},
		{"https://mcp.example.com/mcp?x=1", "", false},
		{"https://mcp.example.com/mcp#f", "", false},
		{"https://u:p@mcp.example.com/mcp", "", false},
		{"mcp.example.com/mcp", "", false},
	} {
		got, ok := CanonicalResource(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("CanonicalResource(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDecideMCPToken(t *testing.T) {
	o := mustLoad(t)
	o.MCP.Servers[1].Auth = MCPAuth{Mode: MCPAuthOAuth}
	team := Subject{ID: "pm@acme.example", Groups: []string{"ai-platform"}} // ring0-harness-team
	for _, tc := range []struct {
		name     string
		sub      Subject
		resource string
		allow    bool
		reason   string
	}{
		{"halos server for its ring", team, "https://MCP-wiki.internal.acme.example/mcp/", true, "allowed"},
		{"another ring", Subject{ID: "dev@acme.example"}, "https://mcp-wiki.internal.acme.example/mcp", false, "not enabled for the caller's ring or unit"},
		{"oauth server: Halos is not its authorization server", team, "https://api.githubcopilot.com/mcp/", false, "does not use auth mode halos"},
		{"not in the registry", team, "https://evil.example/mcp", false, "not a remote server in the mcp registry"},
		{"not https", team, "http://mcp-wiki.internal.acme.example/mcp", false, "absolute https URL"},
		{"query smuggles another resource", team, "https://mcp-wiki.internal.acme.example/mcp?r=x", false, "absolute https URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := o.DecideMCPToken(tc.sub, tc.resource)
			if d.Allow != tc.allow || !strings.Contains(d.Reason, tc.reason) {
				t.Fatalf("decision %+v, want allow=%v reason ~%q", d, tc.allow, tc.reason)
			}
		})
	}
	o.MCP = nil
	if d := o.DecideMCPToken(team, "https://mcp-wiki.internal.acme.example/mcp"); d.Allow {
		t.Fatalf("no registry: %+v", d)
	}
}
