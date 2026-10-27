package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestEgressRulesDecide(t *testing.T) {
	tests := []struct {
		name    string
		e       Egress
		host    string
		allowed bool
		rule    string
	}{
		{"unset is open", Egress{}, "example.com", true, "egress.default allow"},
		{"allowlist implies deny", Egress{AllowedDomains: []string{"github.com"}}, "evil.example", false, "egress.default deny"},
		{"exact allow", Egress{AllowedDomains: []string{"github.com"}}, "GitHub.com.", true, "egress allow github.com"},
		{"wildcard is subdomains only", Egress{AllowedDomains: []string{"*.example.com"}}, "example.com", false, "egress.default deny"},
		{"wildcard subdomain", Egress{AllowedDomains: []string{"*.example.com"}}, "a.b.example.com", true, "egress allow *.example.com"},
		{"suffix is not a subdomain", Egress{AllowedDomains: []string{"*.example.com"}}, "badexample.com", false, "egress.default deny"},
		{"deny wins over allow", Egress{AllowedDomains: []string{"*.example.com"}, DeniedDomains: []string{"x.example.com"}}, "x.example.com", false, "egress.deniedDomains x.example.com"},
		{"default allow with deny list", Egress{Default: EgressAllow, DeniedDomains: []string{"pastebin.com"}}, "pastebin.com", false, "egress.deniedDomains pastebin.com"},
		{"preset expands", Egress{Presets: []string{"package-registries"}}, "registry.npmjs.org", true, "egress allow registry.npmjs.org"},
		{"preset implies deny", Egress{Presets: []string{"vcs"}}, "registry.npmjs.org", false, "egress.default deny"},
		{"explicit deny default, empty allowlist", Egress{Default: EgressDeny}, "github.com", false, "egress.default deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, rule := tt.e.Rules().Decide(tt.host)
			if ok != tt.allowed || rule != tt.rule {
				t.Fatalf("Decide(%q) = %v, %q; want %v, %q", tt.host, ok, rule, tt.allowed, tt.rule)
			}
		})
	}
}

func TestEgressRulesDedupe(t *testing.T) {
	r := Egress{AllowedDomains: []string{"GitHub.com", "github.com"}, Presets: []string{"vcs"}}.Rules()
	n := 0
	for _, a := range r.Allow {
		if a == "github.com" {
			n++
		}
	}
	if n != 1 || !slices.IsSorted(r.Allow) {
		t.Fatalf("allow = %v, want sorted with github.com once", r.Allow)
	}
}

// Every preset entry must itself pass validation.
func TestEgressPresetsValid(t *testing.T) {
	for name, hosts := range EgressPresets {
		for _, h := range hosts {
			if !domainRe.MatchString(h) {
				t.Errorf("preset %s: %q is not a valid domain pattern", name, h)
			}
		}
	}
}

func TestEgressSandboxValidation(t *testing.T) {
	gw := "ai.acme.example"
	tests := []struct {
		name string
		mut  func(p *Profile)
		path string // "" = no error expected under profiles[base]
	}{
		{"valid", func(p *Profile) {
			p.Egress = Egress{Default: EgressDeny, AllowedDomains: []string{gw}, DeniedDomains: []string{"pastebin.com"}, Presets: []string{"vcs"}}
			p.Sandbox = Sandbox{WritableRoots: []string{"/opt/cache", "~/.cache/go-build"}, ProtectedPaths: []string{"~/.ssh", ".env*"}}
		}, ""},
		{"url not domain", func(p *Profile) { p.Egress.AllowedDomains = []string{gw, "https://x.example/"} }, "profiles[base].egress.allowedDomains[1]"},
		{"bare star", func(p *Profile) { p.Egress.DeniedDomains = []string{"*"} }, "profiles[base].egress.deniedDomains[0]"},
		{"unknown preset", func(p *Profile) { p.Egress.Presets = []string{"everything"} }, "profiles[base].egress.presets[0]"},
		{"bad default", func(p *Profile) { p.Egress.Default = "open" }, "profiles[base].egress.default"},
		{"default allow with allowlist", func(p *Profile) { p.Egress.Default = EgressAllow }, "profiles[base].egress.default"},
		{"gateway denied", func(p *Profile) { p.Egress.DeniedDomains = []string{gw} }, "profiles[base].egress.allowedDomains"},
		{"writable root is root", func(p *Profile) { p.Sandbox.WritableRoots = []string{"/"} }, "profiles[base].sandbox.writableRoots[0]"},
		{"writable root is home", func(p *Profile) { p.Sandbox.WritableRoots = []string{"~/"} }, "profiles[base].sandbox.writableRoots[0]"},
		{"writable root relative", func(p *Profile) { p.Sandbox.WritableRoots = []string{"build"} }, "profiles[base].sandbox.writableRoots[0]"},
		{"writable root glob", func(p *Profile) { p.Sandbox.WritableRoots = []string{"/opt/*"} }, "profiles[base].sandbox.writableRoots[0]"},
		{"writable root over protected", func(p *Profile) {
			p.Sandbox = Sandbox{WritableRoots: []string{"/home"}, ProtectedPaths: []string{"/home/alice/.ssh"}}
		}, "profiles[base].sandbox.writableRoots[0]"},
		{"writable root inside protected", func(p *Profile) {
			p.Sandbox = Sandbox{WritableRoots: []string{"~/.aws/cli"}, ProtectedPaths: []string{"~/.aws"}}
		}, "profiles[base].sandbox.writableRoots[0]"},
		{"writable root read-only", func(p *Profile) {
			p.Permissions.Sandbox = "read-only"
			p.Sandbox.WritableRoots = []string{"/opt/cache"}
		}, "profiles[base].sandbox.writableRoots[0]"},
		{"modes disagree", func(p *Profile) { p.Sandbox.Mode = "read-only" }, "profiles[base].sandbox.mode"},
		{"bad protected path", func(p *Profile) { p.Sandbox.ProtectedPaths = []string{"Read(x)"} }, "profiles[base].sandbox.protectedPaths[0]"},
		{"sandbox off with egress", func(p *Profile) { p.Permissions.Sandbox = "off" }, "profiles[base].sandbox.mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := mustLoad(t)
			tt.mut(o.Profiles["base"])
			var got []string
			for _, is := range o.Validate() {
				if is.Severity == SeverityError && strings.HasPrefix(is.Path, "profiles[base]") {
					got = append(got, is.Path)
				}
			}
			if tt.path == "" {
				if len(got) > 0 {
					t.Fatalf("unexpected errors %v", got)
				}
				return
			}
			if !slices.Contains(got, tt.path) {
				t.Fatalf("errors %v, want one at %s", got, tt.path)
			}
		})
	}
}

func TestResolveProfileEgressSandbox(t *testing.T) {
	o := &Org{Profiles: map[string]*Profile{
		"parent": {Meta: Meta{Name: "parent"}, Permissions: Permissions{Sandbox: "workspace-write"},
			Egress:  Egress{AllowedDomains: []string{"a.example"}, DeniedDomains: []string{"x.example"}},
			Sandbox: Sandbox{ProtectedPaths: []string{"~/.ssh"}, WritableRoots: []string{"/opt/a"}}},
		"child": {Meta: Meta{Name: "child"}, Extends: "parent", Sandbox: Sandbox{Mode: "read-only", ProtectedPaths: []string{".env*"}, WritableRoots: []string{"/opt/b"}},
			Egress: Egress{AllowedDomains: []string{"b.example"}, DeniedDomains: []string{"y.example"}}},
	}}
	p, err := o.ResolveProfile("child")
	if err != nil {
		t.Fatal(err)
	}
	if p.Sandbox.Mode != "read-only" || p.Permissions.Sandbox != "read-only" {
		t.Errorf("mode = %q / %q, want read-only in both", p.Sandbox.Mode, p.Permissions.Sandbox)
	}
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"protectedPaths union", p.Sandbox.ProtectedPaths, []string{"~/.ssh", ".env*"}},
		{"deniedDomains union", p.Egress.DeniedDomains, []string{"x.example", "y.example"}},
		{"allowedDomains replace", p.Egress.AllowedDomains, []string{"b.example"}},
		{"writableRoots replace", p.Sandbox.WritableRoots, []string{"/opt/b"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
