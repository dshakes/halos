package policy

import (
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// MCP server registry (ADR-0029): halos.yaml mcp lists the MCP servers the
// org approves, each pinned (a remote URL, or a package version and digest),
// with its tool allow/deny lists, its authorization mode and the rings and
// units it is rendered for. Releases render the admitted servers into every
// harness's native MCP settings, halod reports unapproved and version-drifted
// servers in user configs, the gateway refuses model calls that declare a
// denied tool, and halo-server mints audience-bound tokens for servers whose
// authorization server is Halos.

// Registry modes.
const (
	// MCPModeAllowlist (the default) renders the registry as each harness's
	// managed allowlist: servers outside it are blocked where the harness can
	// block them, and profiles, units and toggles may only name registry servers.
	MCPModeAllowlist = "allowlist"
	// MCPModeWarn renders the registry servers but blocks nothing else: halod
	// reports unapproved servers as drift. A migration step, not an end state.
	MCPModeWarn = "warn"
)

// Authorization modes of a remote registry server (MCPAuth.Mode).
const (
	MCPAuthNone = "none"
	// MCPAuthOAuth: the server's own authorization server (MCP authorization,
	// OAuth 2.1), with a pre-registered client id or a Client ID Metadata Document.
	MCPAuthOAuth = "oauth"
	// MCPAuthEnterprise: Enterprise-Managed Authorization (the
	// io.modelcontextprotocol/enterprise-managed-authorization extension): the
	// org IdP (identity.issuer) issues an ID-JAG the client trades at the
	// server's authorization server.
	MCPAuthEnterprise = "enterprise"
	// MCPAuthHalos: halo-server is the server's authorization server and mints
	// short-lived, audience-bound access tokens for it (POST /api/v1/token/exchange
	// with resource=<server url>).
	MCPAuthHalos = "halos"
)

// Package types of a stdio registry server (MCPPackage.Type), as the official
// MCP Registry's server.json registryType names them (binary is Halos's).
const (
	MCPPackageNPM    = "npm"
	MCPPackagePyPI   = "pypi"
	MCPPackageOCI    = "oci"
	MCPPackageBinary = "binary"
)

// MCPRegistry is halos.yaml mcp.
type MCPRegistry struct {
	// Mode: allowlist (default) | warn.
	Mode    string           `yaml:"mode,omitempty" json:"mode,omitempty"`
	Servers []RegistryServer `yaml:"servers" json:"servers"`
}

// RegistryServer is one approved MCP server.
type RegistryServer struct {
	// ID is the server name rendered into every harness (and the <server> of
	// its tools' names, e.g. mcp__<id>__<tool>): lowercase letters, digits, '-'.
	ID string `yaml:"id" json:"id"`
	// RegistryName and Version are the official MCP Registry's server.json name
	// and version this entry was imported from (`halo mcp registry import`).
	RegistryName string `yaml:"registryName,omitempty" json:"registryName,omitempty"`
	Version      string `yaml:"version,omitempty" json:"version,omitempty"`
	// Exactly one transport: URL (remote, https), Package (stdio; npm, pypi and
	// oci derive the command line) or Command (stdio; required with a binary package).
	URL     string            `yaml:"url,omitempty" json:"url,omitempty"`
	Command []string          `yaml:"command,omitempty" json:"command,omitempty"`
	Package *MCPPackage       `yaml:"package,omitempty" json:"package,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Tools   MCPTools          `yaml:"tools,omitempty" json:"tools,omitzero"`
	Auth    MCPAuth           `yaml:"auth,omitempty" json:"auth,omitzero"`
	// Rings and Units it is rendered for: a member of a listed ring, or of a
	// listed unit or one below it. Both empty = rendered for nobody (approved
	// only: a toggle naming it may deliver it).
	Rings []string `yaml:"rings,omitempty" json:"rings,omitempty"`
	Units []string `yaml:"units,omitempty" json:"units,omitempty"`
}

// MCPPackage pins a stdio server's code.
type MCPPackage struct {
	// Type: npm | pypi | oci | binary.
	Type string `yaml:"type" json:"type"`
	// Identifier is the package name (npm, pypi) or image reference without
	// tag or digest (oci). Unused for binary.
	Identifier string `yaml:"identifier,omitempty" json:"identifier,omitempty"`
	// Version is the exact version (npm, pypi; no ranges, no "latest"), or the
	// image tag for information (oci).
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	// SHA256 is "sha256:<hex>": the image digest (oci, required) or the
	// executable's digest (binary, required; halod checks it).
	SHA256 string `yaml:"sha256,omitempty" json:"sha256,omitempty"`
	// Args are appended to the derived command line.
	Args []string `yaml:"args,omitempty" json:"args,omitempty"`
}

// MCPTools narrows a server's tools. Deny wins over Allow; empty Allow = all.
type MCPTools struct {
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty" json:"deny,omitempty"`
}

// MCPAuth is how clients authorize to a remote server.
type MCPAuth struct {
	// Mode: none (default) | oauth | enterprise | halos.
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
	// Issuer is the server's authorization server issuer (oauth, enterprise).
	Issuer string `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	// ClientID is a pre-registered OAuth client id (oauth: at the server's
	// authorization server; enterprise: at the org IdP).
	ClientID string `yaml:"clientID,omitempty" json:"clientID,omitempty"`
	// ClientIDMetadataURL is the https URL of a Client ID Metadata Document
	// the org hosts (oauth): the URL is the client id.
	ClientIDMetadataURL string   `yaml:"clientIDMetadataURL,omitempty" json:"clientIDMetadataURL,omitempty"`
	Scopes              []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// Allowlist reports whether the registry is enforced as an allowlist.
func (r *MCPRegistry) Allowlist() bool { return r != nil && r.Mode != MCPModeWarn }

// Server returns the registry server id, or nil.
func (r *MCPRegistry) Server(id string) *RegistryServer {
	if r == nil {
		return nil
	}
	for i := range r.Servers {
		if r.Servers[i].ID == id {
			return &r.Servers[i]
		}
	}
	return nil
}

// Resolved is the server as harness adapters render it: the package's
// derived command line when it has no explicit one.
func (s RegistryServer) Resolved() MCPServer {
	out := MCPServer{Name: s.ID, URL: s.URL, Command: slices.Clone(s.Command), Headers: maps.Clone(s.Headers),
		Tools: MCPTools{Allow: slices.Clone(s.Tools.Allow), Deny: slices.Clone(s.Tools.Deny)}, Auth: s.Auth}
	out.Auth.Scopes = slices.Clone(s.Auth.Scopes)
	if len(out.Command) == 0 && s.Package != nil {
		out.Command = s.Package.Command()
	}
	return out
}

// Command is the pinned command line a package runs as: npx, uvx or docker
// with the exact version or digest. nil for binary (its command is explicit).
func (p MCPPackage) Command() []string {
	var cmd []string
	switch p.Type {
	case MCPPackageNPM:
		cmd = []string{"npx", "-y", p.Identifier + "@" + p.Version}
	case MCPPackagePyPI:
		cmd = []string{"uvx", p.Identifier + "==" + p.Version}
	case MCPPackageOCI:
		cmd = []string{"docker", "run", "-i", "--rm", p.Identifier + "@" + p.SHA256}
	default:
		return nil
	}
	return append(cmd, p.Args...)
}

// admits reports whether a member of ring and of the unit chain units (the
// unit and its ancestors) gets the server.
func (s RegistryServer) admits(ring string, units []string) bool {
	return (ring != "" && slices.Contains(s.Rings, ring)) || slices.ContainsFunc(units, func(u string) bool { return slices.Contains(s.Units, u) })
}

// unitNames is unit's chain, root first; nil for "".
func (o *Org) unitNames(unit string) ([]string, error) {
	if unit == "" {
		return nil, nil
	}
	chain, err := o.UnitChain(unit)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(chain))
	for i, u := range chain {
		names[i] = u.Name
	}
	return names, nil
}

// WithMCPRegistry returns a copy of p with the registry servers admitted for
// ring and unit ("" = none) added to mcp.servers, and, in allowlist mode,
// mcp.managedOnly set. A server p already lists by name is kept as is (a ring
// release's profile already holds the ring's servers when its units are
// rendered). p is not modified.
func (o *Org) WithMCPRegistry(p *Profile, ring, unit string) (*Profile, error) {
	out := copyProfile(p)
	r := o.MCP
	if r == nil {
		return out, nil
	}
	units, err := o.unitNames(unit)
	if err != nil {
		return nil, err
	}
	if r.Allowlist() {
		out.MCP.ManagedOnly = true
	}
	for _, s := range r.Servers {
		if !s.admits(ring, units) || slices.ContainsFunc(out.MCP.Servers, func(x MCPServer) bool { return x.Name == s.ID }) {
			continue
		}
		out.MCP.Servers = append(out.MCP.Servers, s.Resolved())
	}
	return out, nil
}

// MCPPin is one registry server as a ring release manifest carries it for
// halod's drift check: identity, pin and the units it is limited to.
type MCPPin struct {
	ID      string      `json:"id"`
	URL     string      `json:"url,omitempty"`
	Command []string    `json:"command,omitempty"`
	Package *MCPPackage `json:"package,omitempty"`
	// Units, when set, are the only units (and units below them) that get it;
	// empty = every member of the ring.
	Units []string `json:"units,omitempty"`
}

// MCPPins lists the registry servers ring's members (or some of its units'
// members) get, for the release manifest.
func (r *MCPRegistry) MCPPins(ring string) []MCPPin {
	if r == nil {
		return nil
	}
	var out []MCPPin
	for _, s := range r.Servers {
		pin := MCPPin{ID: s.ID, URL: s.URL, Command: s.Resolved().Command, Package: s.Package}
		switch {
		case ring != "" && slices.Contains(s.Rings, ring):
		case len(s.Units) > 0:
			pin.Units = s.Units
		default:
			continue
		}
		out = append(out, pin)
	}
	return out
}

// HasToolDenies reports whether any registry server denies a tool.
func (r *MCPRegistry) HasToolDenies() bool {
	return r != nil && slices.ContainsFunc(r.Servers, func(s RegistryServer) bool { return len(s.Tools.Deny) > 0 })
}

// DeniedTool reports whether name, a function tool a model call declares,
// is a tool a registry server denies. Harnesses qualify MCP tool names with
// the server name: Claude Code mcp__<server>__<tool>, Gemini CLI
// mcp_<server>_<tool>. Registry ids hold no '_', so both split unambiguously.
func (r *MCPRegistry) DeniedTool(name string) (server, tool string, denied bool) {
	if r == nil {
		return "", "", false
	}
	switch {
	case strings.HasPrefix(name, "mcp__"):
		server, tool, _ = strings.Cut(name[len("mcp__"):], "__")
	case strings.HasPrefix(name, "mcp_"):
		server, tool, _ = strings.Cut(name[len("mcp_"):], "_")
	default:
		return "", "", false
	}
	s := r.Server(server)
	if s == nil || tool == "" || !slices.Contains(s.Tools.Deny, tool) {
		return "", "", false
	}
	return server, tool, true
}

// CanonicalResource is u in the form MCP authorization compares resources in
// (RFC 8707 section 2): https, lowercase scheme and host, no default port,
// fragment, query or credentials, and no trailing slash. ok is false for
// anything that is not such a URL.
func CanonicalResource(u string) (string, bool) {
	p, err := url.Parse(u)
	if err != nil || !strings.EqualFold(p.Scheme, "https") || p.Host == "" || p.User != nil || p.Fragment != "" || p.RawQuery != "" || p.Opaque != "" {
		return "", false
	}
	host := strings.ToLower(p.Hostname())
	if port := p.Port(); port != "" && port != "443" {
		host += ":" + port
	} else if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	return "https://" + host + strings.TrimRight(p.EscapedPath(), "/"), true
}

// MCPTokenDecision is halo-server's verdict on minting a token for a server.
type MCPTokenDecision struct {
	Allow  bool
	Server string
	Ring   string
	Unit   string
	Reason string
}

// DecideMCPToken decides whether s may get a Halos access token for the
// registry server at resource: the server must use auth mode halos and be
// rendered for s's ring or unit.
func (o *Org) DecideMCPToken(s Subject, resource string) MCPTokenDecision {
	res, ok := CanonicalResource(resource)
	if !ok {
		return MCPTokenDecision{Reason: "resource must be an absolute https URL without query, fragment or credentials"}
	}
	var srv *RegistryServer
	if o.MCP != nil {
		for i := range o.MCP.Servers {
			if c, ok := CanonicalResource(o.MCP.Servers[i].URL); ok && c == res {
				srv = &o.MCP.Servers[i]
				break
			}
		}
	}
	switch {
	case srv == nil:
		return MCPTokenDecision{Reason: "resource is not a remote server in the mcp registry"}
	case srv.Auth.Mode != MCPAuthHalos:
		return MCPTokenDecision{Server: srv.ID, Reason: fmt.Sprintf("mcp server %q does not use auth mode halos; Halos is not its authorization server", srv.ID)}
	}
	d := MCPTokenDecision{Server: srv.ID}
	if r := o.ResolveRing(s); r != nil {
		d.Ring = r.Name
	}
	if u := o.ResolveUnit(s); u != nil {
		d.Unit = u.Name
	}
	units, err := o.unitNames(d.Unit)
	if err != nil {
		d.Reason = "policy cannot be resolved for this caller: " + err.Error()
		return d
	}
	if !srv.admits(d.Ring, units) {
		d.Reason = fmt.Sprintf("mcp server %q is not enabled for the caller's ring or unit (mcp.servers[].rings/units)", srv.ID)
		return d
	}
	d.Allow, d.Reason = true, "allowed"
	return d
}

// MCPFinding is one MCP server halod found in a user config that the
// release's registry does not approve, or approves at another version.
type MCPFinding struct {
	Harness string `json:"harness"`
	File    string `json:"file"`
	Server  string `json:"server"`
	// Kind: unapproved | version-drift.
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

var (
	mcpIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// mcpToolRe is the MCP tool-name charset (spec 2025-11-25, tools: 1-128 of
	// A-Z a-z 0-9 _ - .); it also keeps names out of permission-rule syntax.
	mcpToolRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	// exactVersionRe: a concrete version, never a range, tag or "latest".
	exactVersionRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)
	sha256Re       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mcpModes       = []string{MCPModeAllowlist, MCPModeWarn}
	mcpAuthModes   = []string{MCPAuthNone, MCPAuthOAuth, MCPAuthEnterprise, MCPAuthHalos}
	mcpPackages    = []string{MCPPackageNPM, MCPPackagePyPI, MCPPackageOCI, MCPPackageBinary}
)

// mcpRegistry validates halos.yaml mcp, the tools and auth of every server a
// profile, unit or toggle declares, and, in allowlist mode, that those name
// only registry servers.
func (v *validator) mcpRegistry() {
	for _, name := range sortedKeys(v.org.Profiles) {
		for i, s := range v.org.Profiles[name].MCP.Servers {
			v.mcpExtras(fmt.Sprintf("profiles[%s].mcp.servers[%d]", name, i), s.URL, s.Tools, s.Auth)
		}
	}
	for _, u := range v.org.Units {
		for i, s := range u.Overlay.MCP.Servers {
			v.mcpExtras(fmt.Sprintf("units[%s].overlay.mcp.servers[%d]", u.Name, i), s.URL, s.Tools, s.Auth)
		}
	}
	r := v.org.MCP
	if r == nil {
		return
	}
	if r.Mode != "" {
		v.oneOf("mcp.mode", "mode", r.Mode, mcpModes)
	}
	rings := map[string]bool{}
	for _, rg := range v.org.Rings {
		rings[rg.Name] = true
	}
	ids := map[string]bool{}
	for i, s := range r.Servers {
		p := fmt.Sprintf("mcp.servers[%d]", i)
		if !mcpIDRe.MatchString(s.ID) {
			v.errf(p+".id", "id %q invalid: must match %s (no '_' or '.': harnesses join it into tool names)", s.ID, mcpIDRe)
		} else if ids[s.ID] {
			v.errf(p+".id", "duplicate mcp server %q", s.ID)
		}
		ids[s.ID] = true
		v.registryTransport(p, s)
		for _, k := range sortedKeys(s.Headers) {
			switch {
			case strings.ContainsAny(k+s.Headers[k], "\r\n"):
				v.errf(p+".headers."+k, "must not contain CR or LF")
			case looksSecret(s.Headers[k]):
				v.errf(p+".headers."+k, "value looks like a literal secret; use a ${VAR} reference resolved on the client")
			}
		}
		v.mcpExtras(p, s.URL, s.Tools, s.Auth)
		if len(s.Rings)+len(s.Units) == 0 {
			v.warnf(p, "no rings or units: rendered for nobody (approved only; a toggle naming it may deliver it)")
		}
		for _, rg := range s.Rings {
			if !rings[rg] {
				v.errf(p+".rings", "%q is not a ring", rg)
			}
		}
		for _, u := range s.Units {
			if v.org.Unit(u) == nil {
				v.errf(p+".units", "%q is not a unit", u)
			}
		}
	}
	v.mcpDeclared(r)
}

// registryTransport checks that s has exactly one transport and a real pin.
func (v *validator) registryTransport(p string, s RegistryServer) {
	pkg := s.Package
	switch {
	case s.URL != "" && (len(s.Command) > 0 || pkg != nil):
		v.errf(p, "set url (remote) or command/package (stdio), not both")
	case s.URL != "":
		if _, ok := CanonicalResource(s.URL); !ok {
			v.errf(p+".url", "%q must be an https URL without query, fragment or credentials", s.URL)
		}
	case pkg == nil && len(s.Command) == 0:
		v.errf(p, "set url, package or command")
	case pkg == nil:
		v.warnf(p+".command", "a stdio command without package is not pinned: halod cannot tell its version; set package")
	}
	if pkg == nil {
		return
	}
	pp := p + ".package"
	v.oneOf(pp+".type", "type", pkg.Type, mcpPackages)
	switch pkg.Type {
	case MCPPackageNPM, MCPPackagePyPI:
		if !exactVersionRe.MatchString(pkg.Version) {
			v.errf(pp+".version", "%q must be an exact version (no range, tag or latest)", pkg.Version)
		}
	case MCPPackageOCI:
		if !sha256Re.MatchString(pkg.SHA256) {
			v.errf(pp+".sha256", "%q must be the image digest sha256:<64 hex>; a tag can be re-pushed", pkg.SHA256)
		}
		if strings.ContainsAny(pkg.Identifier, "@") || strings.Contains(pkg.Identifier[strings.LastIndex(pkg.Identifier, "/")+1:], ":") {
			v.errf(pp+".identifier", "%q must be the image reference without tag or digest", pkg.Identifier)
		}
	case MCPPackageBinary:
		if !sha256Re.MatchString(pkg.SHA256) {
			v.errf(pp+".sha256", "%q must be the executable's digest sha256:<64 hex>", pkg.SHA256)
		}
		if len(s.Command) == 0 {
			v.errf(p+".command", "a binary package needs its command (the executable path first)")
		}
	}
	if pkg.Type != MCPPackageBinary {
		if len(s.Command) > 0 {
			v.errf(p+".command", "package %s derives the command; omit command", pkg.Type)
		}
		if pkg.Identifier == "" || strings.ContainsAny(pkg.Identifier, " \t\r\n") {
			v.errf(pp+".identifier", "%q must be a non-empty package name", pkg.Identifier)
		}
	}
}

// mcpExtras checks one server's tools and auth (registry or profile).
func (v *validator) mcpExtras(p, serverURL string, t MCPTools, a MCPAuth) {
	for _, l := range []struct {
		field string
		names []string
	}{{"allow", t.Allow}, {"deny", t.Deny}} {
		for j, n := range l.names {
			if !mcpToolRe.MatchString(n) {
				v.errf(fmt.Sprintf("%s.tools.%s[%d]", p, l.field, j), "%q is not an MCP tool name (1-128 of A-Z a-z 0-9 _ - .)", n)
			} else if l.field == "allow" && slices.Contains(t.Deny, n) {
				v.errf(fmt.Sprintf("%s.tools.allow[%d]", p, j), "tool %q is both allowed and denied", n)
			}
		}
	}
	if a.Mode == "" && a.Issuer+a.ClientID+a.ClientIDMetadataURL == "" && len(a.Scopes) == 0 {
		return
	}
	ap := p + ".auth"
	mode := a.Mode
	if mode == "" {
		mode = MCPAuthNone
	}
	v.oneOf(ap+".mode", "mode", mode, mcpAuthModes)
	if mode != MCPAuthNone && serverURL == "" {
		v.errf(ap+".mode", "auth mode %s needs a remote server (url); stdio servers take credentials from the environment", mode)
	}
	if a.Issuer != "" && !SecureAgentURL(a.Issuer) {
		v.errf(ap+".issuer", "%q must be an https URL", a.Issuer)
	}
	if a.ClientIDMetadataURL != "" && !SecureAgentURL(a.ClientIDMetadataURL) {
		v.errf(ap+".clientIDMetadataURL", "%q must be an https URL", a.ClientIDMetadataURL)
	}
	if strings.ContainsAny(a.ClientID, " \t\r\n") {
		v.errf(ap+".clientID", "must not contain whitespace")
	}
	for j, s := range a.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			v.errf(fmt.Sprintf("%s.scopes[%d]", ap, j), "%q must be one non-empty scope token", s)
		}
	}
	switch mode {
	case MCPAuthNone, MCPAuthHalos:
		if a.Issuer+a.ClientID+a.ClientIDMetadataURL != "" || len(a.Scopes) > 0 {
			v.errf(ap, "issuer, clientID, clientIDMetadataURL and scopes apply to modes oauth and enterprise only")
		}
	case MCPAuthOAuth:
		if a.ClientID != "" && a.ClientIDMetadataURL != "" {
			v.errf(ap, "set clientID or clientIDMetadataURL, not both (with a Client ID Metadata Document the URL is the client id)")
		}
	case MCPAuthEnterprise:
		if v.org.Identity.Issuer == "" {
			v.errf(ap+".mode", "enterprise authorization trades an ID-JAG from the org IdP: set identity.issuer")
		}
		if a.ClientIDMetadataURL != "" {
			v.errf(ap+".clientIDMetadataURL", "applies to mode oauth only")
		}
	}
}

// mcpDeclared checks the servers profiles, units and toggles declare against
// the registry: a name may never shadow a registry id with another
// definition, and in allowlist mode only registry servers may be declared.
func (v *validator) mcpDeclared(r *MCPRegistry) {
	check := func(p string, s MCPServer, toggle bool) {
		reg := r.Server(s.Name)
		switch {
		case reg == nil && r.Allowlist():
			v.errf(p, "mcp.mode allowlist: %q is not in the halos.yaml mcp registry; add it there (`halo mcp registry import`)", s.Name)
		case reg == nil:
		case !toggle:
			v.errf(p, "%q is a registry server: enable it with mcp.servers[].rings/units in halos.yaml, not here", s.Name)
		default:
			want := reg.Resolved()
			if s.URL != want.URL || !slices.Equal(s.Command, want.Command) {
				v.errf(p, "%q differs from the registry's url/command; a toggle delivers the registry definition as is", s.Name)
			}
		}
	}
	for _, name := range sortedKeys(v.org.Profiles) {
		for i, s := range v.org.Profiles[name].MCP.Servers {
			check(fmt.Sprintf("profiles[%s].mcp.servers[%d]", name, i), s, false)
		}
	}
	for _, u := range v.org.Units {
		for i, s := range u.Overlay.MCP.Servers {
			check(fmt.Sprintf("units[%s].overlay.mcp.servers[%d]", u.Name, i), s, false)
		}
	}
	for _, t := range v.org.Toggles {
		if t.Client == nil {
			continue
		}
		for _, h := range sortedKeys(t.Client.Harnesses) {
			for i, s := range t.Client.Harnesses[h].MCPServers {
				check(fmt.Sprintf("toggles[%s].client.harnesses.%s.mcpServers[%d]", t.Name, h, i), s, true)
			}
		}
	}
}
