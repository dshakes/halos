package policy

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Egress defaults (ADR-0032).
const (
	EgressAllow = "allow"
	EgressDeny  = "deny"
)

// Sandbox is the agent sandbox policy (ADR-0032): how far the harness's
// shell and tools may write, and which paths they may never touch.
type Sandbox struct {
	// Mode: off | workspace-write | read-only. Same field as permissions.sandbox
	// (either may be set; ResolveProfile keeps the two equal).
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
	// WritableRoots are absolute (or ~/) directories writable beyond the
	// workspace, e.g. a build cache. A child list replaces its parent's, like
	// allowedDomains; a unit adding one is a loosening.
	WritableRoots []string `yaml:"writableRoots,omitempty" json:"writableRoots,omitempty"`
	// ProtectedPaths may never be read or written by the agent: credentials
	// (~/.ssh, ~/.aws) and secrets files (.env*). Absolute, ~/ or a
	// workspace-relative glob. Unions down an extends chain and across units.
	ProtectedPaths []string `yaml:"protectedPaths,omitempty" json:"protectedPaths,omitempty"`
}

// EgressPresets are the named domain sets egress.presets expands to. Each set
// is the hosts the named service documents for clients; see
// docs/guides/egress-and-sandbox.md for the source of every entry.
var EgressPresets = map[string][]string{
	// npm (registry.npmjs.org), PyPI (pypi.org + files.pythonhosted.org), the
	// Go module proxy and checksum DB, crates.io (sparse index + downloads),
	// Maven Central and RubyGems.
	"package-registries": {
		"registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "proxy.golang.org", "sum.golang.org",
		"index.crates.io", "static.crates.io", "repo.maven.apache.org", "rubygems.org",
	},
	// GitHub (web, API, git over HTTPS, release and raw content), GitLab.com
	// and Bitbucket Cloud.
	"vcs": {
		"github.com", "api.github.com", "codeload.github.com", "*.githubusercontent.com",
		"gitlab.com", "bitbucket.org",
	},
	// The model APIs the supported harnesses call when not behind a gateway.
	"model-providers": {
		"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
		"api.githubcopilot.com", "*.githubcopilot.com",
	},
}

// EgressRules is an Egress with its default decided and presets expanded:
// what every adapter renders and what `halo egress test` evaluates.
type EgressRules struct {
	Default string   `json:"default"` // allow | deny
	Allow   []string `json:"allow,omitempty"`
	Deny    []string `json:"deny,omitempty"`
}

// Restricted reports whether the profile says anything about egress.
func (e Egress) Restricted() bool {
	return e.Default != "" || len(e.AllowedDomains)+len(e.DeniedDomains)+len(e.Presets) > 0
}

// Rules resolves e: presets join the allow list after allowedDomains
// (lower-cased, de-duplicated, first occurrence kept), and an
// unset default is deny when anything is allowed (allowedDomains has always
// meant "the only egress permitted") and allow otherwise.
func (e Egress) Rules() EgressRules {
	allow := slices.Clone(e.AllowedDomains)
	for _, p := range e.Presets {
		allow = append(allow, EgressPresets[p]...)
	}
	r := EgressRules{Default: e.Default, Allow: dedupe(allow), Deny: dedupe(e.DeniedDomains)}
	if r.Default == "" {
		r.Default = EgressAllow
		if len(r.Allow) > 0 {
			r.Default = EgressDeny
		}
	}
	return r
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.ToLower(s); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// MatchDomain reports whether host matches pattern: an exact host, or
// "*.example.com", which matches every subdomain of example.com but not
// example.com itself. Case and a trailing dot are ignored.
func MatchDomain(pattern, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	pattern = strings.ToLower(pattern)
	if suf, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suf)
	}
	return host == pattern
}

// Decide is the egress decision for host and the rule that made it: a deny
// rule wins over an allow rule, and the default decides the rest.
func (r EgressRules) Decide(host string) (allowed bool, rule string) {
	for _, d := range r.Deny {
		if MatchDomain(d, host) {
			return false, "egress.deniedDomains " + d
		}
	}
	for _, a := range r.Allow {
		if MatchDomain(a, host) {
			return true, "egress allow " + a
		}
	}
	return r.Default == EgressAllow, "egress.default " + r.Default
}

// domainRe is a lower-case host name, optionally behind "*." (no scheme, port,
// path or bare "*": an allow-everything entry is default: allow).
var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// validateEgress checks e (a resolved profile's) under path.
func (v *validator) egress(path string, e Egress) {
	if e.Default != "" {
		v.oneOf(path+".default", "default", e.Default, []string{EgressAllow, EgressDeny})
	}
	for _, f := range []struct {
		field string
		list  []string
	}{{"allowedDomains", e.AllowedDomains}, {"deniedDomains", e.DeniedDomains}} {
		for i, d := range f.list {
			if !domainRe.MatchString(d) {
				v.errf(fmt.Sprintf("%s.%s[%d]", path, f.field, i), "%q must be a lower-case host name or *.domain (no scheme, port, path or bare *)", d)
			}
		}
	}
	for i, p := range e.Presets {
		if _, ok := EgressPresets[p]; !ok {
			v.errf(fmt.Sprintf("%s.presets[%d]", path, i), "unknown preset %q, want one of %v", p, sortedKeys(EgressPresets))
		}
	}
	if e.Default == EgressAllow && len(e.AllowedDomains)+len(e.Presets) > 0 {
		v.errf(path+".default", "default allow makes allowedDomains and presets meaningless; use default deny with an allowlist, or allow with deniedDomains")
	}
}

// sandbox checks a resolved profile's sandbox and the combinations that would
// amount to a bypass (invariant 1): writing everywhere or writing a protected
// path. guardSandboxOff covers egress rules with the sandbox switched off.
func (v *validator) sandbox(path string, p *Profile) {
	s := p.Sandbox
	if s.Mode != "" {
		v.oneOf(path+".sandbox.mode", "mode", s.Mode, sandboxModes)
	}
	if s.Mode != "" && p.Permissions.Sandbox != "" && s.Mode != p.Permissions.Sandbox {
		v.errf(path+".sandbox.mode", "%q contradicts permissions.sandbox %q; set one", s.Mode, p.Permissions.Sandbox)
	}
	for i, r := range s.WritableRoots {
		fp := fmt.Sprintf("%s.sandbox.writableRoots[%d]", path, i)
		switch c := cleanPath(r); {
		case !strings.HasPrefix(r, "/") && !strings.HasPrefix(r, "~/"):
			v.errf(fp, "%q must be absolute or start with ~/", r)
		case c == "/" || c == "~" || strings.ContainsAny(r, "*?["):
			v.errf(fp, "%q makes the whole disk or home writable, which is danger-full-access by another name (invariant 1)", r)
		default:
			for _, pp := range s.ProtectedPaths {
				if pathCovers(c, cleanPath(pp)) || pathCovers(cleanPath(pp), c) {
					v.errf(fp, "%q overlaps protected path %q", r, pp)
				}
			}
		}
		if s.Mode == "read-only" || p.Permissions.Sandbox == "read-only" {
			v.errf(fp, "writable roots contradict sandbox mode read-only")
		}
	}
	for i, pp := range s.ProtectedPaths {
		if strings.TrimSpace(pp) == "" || strings.ContainsAny(pp, "()\r\n") {
			v.errf(fmt.Sprintf("%s.sandbox.protectedPaths[%d]", path, i), "%q must be a non-empty path without parentheses or newlines", pp)
		}
	}
}

// guardSandboxOff (ADR-0032): sandbox mode "off" with egress, protectedPaths or
// writableRoots would leave shell commands outside every rule the profile
// states. Checked on declared profiles; a unit turning the sandbox off is
// already a loosening.
func guardSandboxOff(o *Org) []Issue {
	var out []Issue
	for _, name := range sortedKeys(o.Profiles) {
		p, err := o.ResolveProfile(name)
		if err != nil || p.Permissions.Sandbox != "off" {
			continue
		}
		if p.Egress.Restricted() || len(p.Sandbox.ProtectedPaths)+len(p.Sandbox.WritableRoots) > 0 {
			out = append(out, gi(SeverityError, "profiles["+name+"].sandbox.mode", `"off" leaves shell commands outside every egress and path rule; egress, protectedPaths and writableRoots need a sandbox (workspace-write or read-only)`))
		}
	}
	return out
}

// cleanPath normalises a policy path for overlap checks (~/x stays ~/x).
func cleanPath(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if c := path.Clean("/" + rest); c != "/" {
			return "~" + c
		}
		return "~"
	}
	if p == "~" {
		return "~"
	}
	return path.Clean(p)
}

// pathCovers reports whether dir is p or an ancestor of it.
func pathCovers(dir, p string) bool {
	return dir == p || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}
