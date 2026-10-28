package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// KindUnit is a node of the org hierarchy (ADR-0018): a business unit or team
// with delegated owners, a member selector and an overlay applied on top of the
// org baseline (the profile a user's ring, or experiment variant, ships).
const KindUnit Kind = "Unit"

// Unit is one business unit or team. Units nest through Parent; a user belongs
// to the deepest unit whose members selector, and every ancestor's, matches.
// The effective config is the ring's profile, then each ancestor's overlay
// (root first), then the unit's own. Enforced fields (see Loosenings) may
// only be tightened by an overlay; Validate rejects a loosening.
type Unit struct {
	Meta        `yaml:",inline"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Parent is the enclosing unit; empty for a top-level unit.
	Parent string `yaml:"parent,omitempty" json:"parent,omitempty"`
	// Owners approve changes to the unit's directory in the policy repo:
	// CODEOWNERS entries such as @acme/payments-platform, @alice or an email.
	Owners []string `yaml:"owners" json:"owners"`
	// Members selects the unit's users from its parent's (or, at the top, the org's).
	Members UnitMembers `yaml:"members" json:"members"`
	// Overlay is what the unit changes on top of the baseline.
	Overlay Overlay `yaml:"overlay,omitempty" json:"overlay,omitempty"`

	// Dir is the repo-relative directory of the file that declares the unit
	// (set by Load). The unit's owners own that directory.
	Dir string `yaml:"-" json:"-"`
	// File is the repo-relative file that declares the unit (set by Load). A
	// top-level unit's file stays with the root owners: its members selector
	// draws from the whole org.
	File string `yaml:"-" json:"-"`
}

// Delegation is what the org lets units add on top of the baseline
// (halos.yaml delegation:). Anything else a unit adds is a loosening.
type Delegation struct {
	// AllowHooks lets units add hooks.items. Default false: a hook is a shell
	// command every member's harness runs, so a unit owner could otherwise run
	// code on any member's machine.
	AllowHooks bool `yaml:"allowHooks,omitempty" json:"allowHooks,omitempty"`
	// EnvKeys are the env names units may add (exact). Provider, base-URL,
	// proxy and runtime-injection names (see UnitForbiddenEnv) are refused
	// even when listed.
	EnvKeys []string `yaml:"envKeys,omitempty" json:"envKeys,omitempty"`
}

// UnitForbiddenEnv reports why a unit may never set env key k ("" when it
// may): it would redirect model traffic, credentials or telemetry, or run
// code in the harness, its shell or the tools it calls (git, pagers,
// editors, compilers, language runtimes). Matching ignores case; families
// are prefixes.
func UnitForbiddenEnv(k string) string {
	u := strings.ToUpper(k)
	for _, s := range []string{"_BASE_URL", "_API_KEY"} {
		if strings.HasSuffix(u, s) {
			return "*" + s + " names a provider endpoint or credential"
		}
	}
	if why, ok := forbiddenEnvExact[u]; ok {
		return u + " " + why
	}
	if gitIdentityEnv[u] {
		return ""
	}
	for _, f := range forbiddenEnvPrefixes {
		if strings.HasPrefix(u, f.prefix) {
			return f.prefix + "* " + f.why
		}
	}
	return ""
}

const (
	envProvider = "configures the model provider or harness"
	envReroute  = "reroutes traffic around the gateway"
	envCA       = "trusts another CA, so TLS to the gateway can be intercepted"
	envInject   = "runs code in the harness, its shell or the tools it calls"
	envConfig   = "moves the harness or shell configuration, so a unit's file replaces the policy-rendered one"
)

// forbiddenEnvExact is every single name UnitForbiddenEnv refuses (upper case).
var forbiddenEnvExact = map[string]string{
	"CLOUD_ML_REGION": envProvider,
	"HTTP_PROXY":      envReroute, "HTTPS_PROXY": envReroute, "ALL_PROXY": envReroute, "NO_PROXY": envReroute,
	"SSL_CERT_FILE": envCA, "SSL_CERT_DIR": envCA, "REQUESTS_CA_BUNDLE": envCA, "CURL_CA_BUNDLE": envCA, "NODE_EXTRA_CA_CERTS": envCA,
	"GIT_SSL_CAINFO": envCA, "GIT_SSL_NO_VERIFY": "turns off TLS verification for git",
	// Shell start-up and prompt hooks.
	"PATH": envInject, "BASH_ENV": envInject, "ENV": envInject, "PROMPT_COMMAND": envInject, "SHELLOPTS": envInject,
	"BASHOPTS": envInject, "PS4": envInject, "ZDOTDIR": envConfig, "HOME": envConfig, "XDG_CONFIG_HOME": envConfig,
	// Programs tools start for the user.
	"PAGER": envInject, "GIT_PAGER": envInject, "MANPAGER": envInject, "LESSOPEN": envInject, "LESSCLOSE": envInject,
	"EDITOR": envInject, "VISUAL": envInject, "GIT_EDITOR": envInject,
	// git.
	"GIT_SSH": envInject, "GIT_SSH_COMMAND": envInject, "GIT_ASKPASS": envInject, "GIT_PROXY_COMMAND": envInject,
	"GIT_TEMPLATE_DIR": envInject, "GIT_EXEC_PATH": envInject,
	// Compilers and language runtimes.
	"GOFLAGS": envInject, "RUSTC": envInject, "PERL5LIB": envInject, "PERL5OPT": envInject, "RUBYLIB": envInject, "RUBYOPT": envInject,
	"JDK_JAVA_OPTIONS": envInject, "JAVA_TOOL_OPTIONS": envInject, "_JAVA_OPTIONS": envInject, "DOTNET_STARTUP_HOOKS": envInject,
	"ELECTRON_RUN_AS_NODE": envInject, "CC": envInject, "CXX": envInject, "CLASSPATH": envInject, "GCONV_PATH": envInject,
	"MAVEN_OPTS": envInject, "GRADLE_OPTS": envInject, "JAVA_OPTS": envInject, "PHPRC": envInject, "PHP_INI_SCAN_DIR": envInject,
	"MAKEFLAGS": envInject, "MAKEFILES": envInject, "GOENV": envInject, "GOTOOLCHAIN": envInject,
	// Package and module sources: a unit could serve its own dependencies.
	"GOPROXY": envReroute, "GONOPROXY": envReroute, "GOSUMDB": envReroute, "GONOSUMDB": envReroute, "GONOSUMCHECK": envReroute,
	"GOINSECURE": envReroute, "GOPRIVATE": envReroute,
	// Programs tools start for the user, and where containers run.
	"SUDO_ASKPASS": envInject, "BROWSER": envInject, "DOCKER_HOST": envReroute,
	// Harness configuration directories.
	"CLAUDE_CONFIG_DIR": envConfig, "CODEX_HOME": envConfig,
}

// gitIdentityEnv are the GIT_* names a unit may set (commit identity only):
// every other GIT_* is refused (GIT_EXTERNAL_DIFF, GIT_SEQUENCE_EDITOR, ...
// run programs; git adds such variables over time).
var gitIdentityEnv = map[string]bool{"GIT_AUTHOR_NAME": true, "GIT_AUTHOR_EMAIL": true, "GIT_COMMITTER_NAME": true, "GIT_COMMITTER_EMAIL": true}

// forbiddenEnvPrefixes are the families UnitForbiddenEnv refuses.
var forbiddenEnvPrefixes = []struct{ prefix, why string }{
	// CLAUDE_CODE_* covers CLAUDE_CODE_USE_BEDROCK/VERTEX and every other
	// harness switch; GEMINI_* covers the Gemini CLI's settings and config
	// dirs; AWS_* and GOOGLE_* pick the cloud account, endpoint
	// (AWS_ENDPOINT_URL*) and region model calls go to.
	{"ANTHROPIC_", envProvider}, {"OPENAI_", envProvider}, {"GEMINI_", envProvider}, {"CLAUDE_CODE_", envProvider},
	{"AWS_", envProvider}, {"GOOGLE_", envProvider},
	// Every OTEL_* setting: exporters, endpoints, headers, resource
	// attributes, sampling. Telemetry carries prompts and tool calls and is
	// the evidence experiments and budgets rest on.
	{"OTEL_", "changes telemetry (prompts and tool calls, experiment evidence), which only the policy sets"},
	// BASH_FUNC_* exports shell functions (BASH_FUNC_git%%) that shadow commands.
	{"BASH_FUNC_", envInject},
	// LD_* and DYLD_* cover LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH and their
	// macOS forms; NODE_* covers NODE_OPTIONS; PYTHON* covers PYTHONPATH and
	// PYTHONSTARTUP; GIT_* (but gitIdentityEnv) covers GIT_CONFIG_GLOBAL,
	// GIT_CONFIG_COUNT/KEY_n/VALUE_n (core.sshCommand, core.hooksPath),
	// GIT_EXTERNAL_DIFF and GIT_SEQUENCE_EDITOR;
	// NPM_CONFIG_* matches npm's case-insensitive npm_config_*; CARGO_* covers
	// CARGO_BUILD_RUSTC_WRAPPER, CARGO_TARGET_<triple>_LINKER and RUNNER;
	// RUSTC_* covers RUSTC_WRAPPER and RUSTC_WORKSPACE_WRAPPER; SSH_ASKPASS*
	// covers SSH_ASKPASS and SSH_ASKPASS_REQUIRE; CGO_* covers CGO_CFLAGS and
	// CGO_LDFLAGS; PIP_*, UV_*, YARN_*, BUNDLE_* and GEM_* configure package
	// managers (index URLs, build hooks, install paths); LUA_INIT* runs Lua.
	{"NODE_", envInject}, {"LD_", envInject}, {"DYLD_", envInject}, {"PYTHON", envInject}, {"GIT_", envInject},
	{"NPM_CONFIG_", envInject}, {"CARGO_", envInject}, {"RUSTC_", envInject}, {"SSH_ASKPASS", envInject},
	{"CGO_", envInject}, {"PIP_", envInject}, {"UV_", envInject}, {"YARN_", envInject}, {"BUNDLE_", envInject},
	{"GEM_", envInject}, {"LUA_INIT", envInject},
}

// UnitMembers selects users by IdP group or user id (any match).
type UnitMembers struct {
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	Users  []string `yaml:"users,omitempty" json:"users,omitempty"`
}

// Overlay is the part of a Profile a unit may change. Harness pins and
// overrides stay central (they ship per ring). Merge onto the baseline:
// scalars win when set; permissions.deny, mcp.denied and hooks.items union;
// egress.deniedDomains and sandbox.protectedPaths union;
// mcp.servers are added (a name already provided above is an error);
// models.allowed, permissions.allow/ask, egress.allowedDomains/presets and
// sandbox.writableRoots replace;
// env and telemetry.attributes merge per key; instructions are appended.
type Overlay struct {
	Models       Models            `yaml:"models,omitempty" json:"models,omitempty"`
	Permissions  Permissions       `yaml:"permissions,omitempty" json:"permissions,omitempty"`
	MCP          MCP               `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	Hooks        Hooks             `yaml:"hooks,omitempty" json:"hooks,omitempty"`
	Telemetry    Telemetry         `yaml:"telemetry,omitempty" json:"telemetry,omitempty"`
	Egress       Egress            `yaml:"egress,omitempty" json:"egress,omitempty"`
	Sandbox      Sandbox           `yaml:"sandbox,omitempty" json:"sandbox,omitzero"`
	Instructions string            `yaml:"instructions,omitempty" json:"instructions,omitempty"`
	Env          map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	// Agents may only lower maxDepth and narrow remote (ADR-0024).
	Agents AgentLimits `yaml:"agents,omitempty" json:"agents,omitzero"`
}

// Source is the repo-relative file that declared one document.
type Source struct {
	Path string
	Kind Kind
}

func (m UnitMembers) selects(s Subject) bool {
	return slices.Contains(m.Users, s.ID) || slices.ContainsFunc(m.Groups, func(g string) bool { return slices.Contains(s.Groups, g) })
}

// Unit returns the named unit, or nil.
func (o *Org) Unit(name string) *Unit {
	for _, u := range o.Units {
		if u.Name == name {
			return u
		}
	}
	return nil
}

// UnitChain returns name's ancestry, root first and name last. Unknown units
// and parent cycles are errors.
func (o *Org) UnitChain(name string) ([]*Unit, error) {
	var chain []*Unit
	for cur := name; cur != ""; {
		u := o.Unit(cur)
		if u == nil {
			if len(chain) == 0 {
				return nil, fmt.Errorf("policy: unit %q not found", cur)
			}
			return nil, fmt.Errorf("policy: unit %q has unknown parent %q", chain[0].Name, cur)
		}
		if slices.Contains(chain, u) {
			return nil, fmt.Errorf("policy: unit parent cycle through %q", cur)
		}
		chain = append([]*Unit{u}, chain...)
		cur = u.Parent
	}
	return chain, nil
}

// ResolveUnit returns the unit s belongs to, or nil (see MatchUnit).
func (o *Org) ResolveUnit(s Subject) *Unit { return MatchUnit(o.Units, s) }

// MatchUnit returns the deepest unit whose members selector, and every
// ancestor's, matches s; equal depth goes to the lexically smallest name, so
// halod and the CLI agree without any hashing. nil when none matches.
func MatchUnit(units []*Unit, s Subject) *Unit {
	byName := make(map[string]*Unit, len(units))
	for _, u := range units {
		byName[u.Name] = u
	}
	memo := map[string]int{} // depth (1 = top level) when a member, else -1
	var depth func(u *Unit, n int) int
	depth = func(u *Unit, n int) int {
		if d, ok := memo[u.Name]; ok {
			return d
		}
		d := -1
		if n <= len(units) && u.Members.selects(s) { // n bounds a parent cycle
			if u.Parent == "" {
				d = 1
			} else if p, ok := byName[u.Parent]; ok {
				if pd := depth(p, n+1); pd > 0 {
					d = pd + 1
				}
			}
		}
		memo[u.Name] = d
		return d
	}
	var best *Unit
	bestD := 0
	for _, u := range units {
		if d := depth(u, 0); d > bestD || (d == bestD && d > 0 && u.Name < best.Name) {
			best, bestD = u, d
		}
	}
	return best
}

// EffectiveProfile returns base with the overlays of unit's chain applied,
// root first. base is not modified; unit "" returns a copy of base.
func (o *Org) EffectiveProfile(base *Profile, unit string) (*Profile, error) {
	out := copyProfile(base)
	if unit == "" {
		return out, nil
	}
	chain, err := o.UnitChain(unit)
	if err != nil {
		return nil, err
	}
	for _, u := range chain {
		if err := applyOverlay(out, u); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func copyProfile(p *Profile) *Profile {
	out := &Profile{}
	mergeValue(reflect.ValueOf(out).Elem(), reflect.ValueOf(p).Elem())
	return out
}

// applyOverlay merges u's overlay into out (see Overlay for the semantics).
func applyOverlay(out *Profile, u *Unit) error {
	ov := u.Overlay
	deny, denied, hooks := out.Permissions.Deny, out.MCP.Denied, out.Hooks.Hooks
	servers, instr := slices.Clone(out.MCP.Servers), out.Instructions
	deniedDomains, protected := out.Egress.DeniedDomains, out.Sandbox.ProtectedPaths
	layer := &Profile{
		Models: ov.Models, Permissions: ov.Permissions, Telemetry: ov.Telemetry, Egress: ov.Egress, Sandbox: ov.Sandbox, Env: ov.Env, Agents: ov.Agents,
		MCP: MCP{ManagedOnly: ov.MCP.ManagedOnly}, Hooks: Hooks{ManagedOnly: ov.Hooks.ManagedOnly},
	}
	mergeValue(reflect.ValueOf(out).Elem(), reflect.ValueOf(layer).Elem())
	out.Permissions.Deny = unionAppend(slices.Clone(deny), ov.Permissions.Deny)
	out.MCP.Denied = unionAppend(slices.Clone(denied), ov.MCP.Denied)
	out.Hooks.Hooks = unionAppend(slices.Clone(hooks), ov.Hooks.Hooks)
	out.Egress.DeniedDomains = unionAppend(slices.Clone(deniedDomains), ov.Egress.DeniedDomains)
	out.Sandbox.ProtectedPaths = unionAppend(slices.Clone(protected), ov.Sandbox.ProtectedPaths)
	syncSandboxMode(out, ov.Sandbox.Mode, ov.Permissions.Sandbox)
	for _, s := range ov.MCP.Servers {
		if slices.ContainsFunc(servers, func(x MCPServer) bool { return x.Name == s.Name }) {
			return fmt.Errorf("policy: unit %q: mcp server %q is already provided above it; pick another name", u.Name, s.Name)
		}
		servers = append(servers, s)
	}
	out.MCP.Servers = servers
	if ov.Instructions != "" {
		if instr != "" {
			instr = strings.TrimRight(instr, "\n") + "\n\n"
		}
		out.Instructions = instr + ov.Instructions
	}
	return nil
}

// missing lists the entries of a that b lacks.
func missing(a, b []string) []string {
	var out []string
	for _, e := range a {
		if !slices.Contains(b, e) {
			out = append(out, e)
		}
	}
	return out
}

// Loosening is one enforced field an overlay weakens.
type Loosening struct {
	Field   string // e.g. "permissions.sandbox"
	Message string
}

var (
	modeRank    = map[string]int{"plan": 0, "": 1, "default": 1, "acceptEdits": 2, "auto": 3}
	sandboxRank = map[string]int{"read-only": 0, "workspace-write": 1, "off": 2, "": 2}
)

func rank(m map[string]int, v string) int {
	if r, ok := m[v]; ok {
		return r
	}
	return len(m) + 1 // unknown (e.g. bypassPermissions) is the loosest
}

// Loosenings lists the enforced fields child weakens relative to parent. The
// enforced fields are the org's security baseline: permissions (mode,
// sandbox, sandboxRequired, disableBypass, deny, allow, ask), mcp.denied and
// mcp.managedOnly, hooks.managedOnly, telemetry (enabled, endpoint, protocol,
// logPrompts, existing attributes), egress (allowlist, default, deny list),
// sandbox (writable roots, protected paths), existing env keys,
// models.allowed while the parent enforces it, and agents (maxDepth may only
// go down, remote may only narrow; ADR-0024). Additions that run code or
// reroute traffic on members' machines are loosenings too, unless o allows
// them: hooks (delegation.allowHooks), env keys (delegation.envKeys; provider,
// proxy and runtime-injection keys never), MCP servers (an exact
// selfService.catalog entry), and any extensions change.
func (o *Org) Loosenings(parent, child *Profile) []Loosening {
	var out []Loosening
	add := func(field, format string, a ...any) {
		out = append(out, Loosening{field, fmt.Sprintf(format, a...)})
	}
	pp, cp := parent.Permissions, child.Permissions
	if rank(modeRank, cp.Mode) > rank(modeRank, pp.Mode) {
		add("permissions.mode", "%q is looser than %q", cp.Mode, pp.Mode)
	}
	if rank(sandboxRank, cp.Sandbox) > rank(sandboxRank, pp.Sandbox) {
		add("permissions.sandbox", "%q is looser than %q", cp.Sandbox, pp.Sandbox)
	}
	if per, cer := parent.Egress.Rules(), child.Egress.Rules(); per.Default == EgressDeny && cer.Default == EgressAllow {
		add("egress.default", "allow is looser than deny")
	}
	for _, l := range []struct {
		field      string
		par, child []string
	}{
		{"egress.deniedDomains", parent.Egress.DeniedDomains, child.Egress.DeniedDomains},
		{"sandbox.protectedPaths", parent.Sandbox.ProtectedPaths, child.Sandbox.ProtectedPaths},
	} {
		if dropped := missing(l.par, l.child); len(dropped) > 0 {
			add(l.field, "drops %v", dropped)
		}
	}
	if added := missing(child.Sandbox.WritableRoots, parent.Sandbox.WritableRoots); len(added) > 0 {
		add("sandbox.writableRoots", "adds %v", added)
	}
	for _, b := range []struct {
		field     string
		par, chld bool
	}{
		{"permissions.disableBypass", pp.DisableBypass, cp.DisableBypass},
		{"permissions.sandboxRequired", pp.SandboxRequired, cp.SandboxRequired},
		{"mcp.managedOnly", parent.MCP.ManagedOnly, child.MCP.ManagedOnly},
		{"hooks.managedOnly", parent.Hooks.ManagedOnly, child.Hooks.ManagedOnly},
		{"telemetry.enabled", parent.Telemetry.Enabled, child.Telemetry.Enabled},
	} {
		if b.par && !b.chld {
			add(b.field, "cannot be turned off")
		}
	}
	for _, l := range []struct {
		field      string
		par, child []string
	}{
		{"permissions.deny", pp.Deny, cp.Deny},
		{"permissions.ask", pp.Ask, cp.Ask},
		{"mcp.denied", parent.MCP.Denied, child.MCP.Denied},
	} {
		var dropped []string
		for _, e := range l.par {
			if !slices.Contains(l.child, e) {
				dropped = append(dropped, e)
			}
		}
		if len(dropped) > 0 {
			add(l.field, "drops %v", dropped)
		}
	}
	for _, w := range widenings(child, parent) {
		if w.field != "permissions.ask" { // more confirmation prompts tighten
			add(w.field, "adds %v", w.added)
		}
	}
	pt, ct := parent.Telemetry, child.Telemetry
	if ct.OTLPEndpoint != pt.OTLPEndpoint {
		add("telemetry.otlpEndpoint", "%q replaces %q; the telemetry destination is enforced", ct.OTLPEndpoint, pt.OTLPEndpoint)
	}
	if ct.Protocol != pt.Protocol {
		add("telemetry.protocol", "%q replaces %q", ct.Protocol, pt.Protocol)
	}
	if ct.LogPrompts != pt.LogPrompts {
		add("telemetry.logPrompts", "%v replaces %v; prompt logging is decided centrally", ct.LogPrompts, pt.LogPrompts)
	}
	for _, kv := range []struct {
		field      string
		par, child map[string]string
	}{
		{"telemetry.attributes", pt.Attributes, ct.Attributes},
		{"env", parent.Env, child.Env},
	} {
		for _, k := range sortedKeys(kv.par) {
			if v, ok := kv.child[k]; !ok || v != kv.par[k] {
				add(kv.field+"."+k, "%q replaces %q; units may add keys, not change inherited ones", v, kv.par[k])
			}
		}
	}
	d := Delegation{}
	if o.Delegation != nil {
		d = *o.Delegation
	}
	for _, k := range sortedKeys(child.Env) {
		if _, inherited := parent.Env[k]; inherited {
			continue
		}
		if why := UnitForbiddenEnv(k); why != "" {
			add("env."+k, "adds %s: %s; units may never set it", k, why)
		} else if !slices.Contains(d.EnvKeys, k) {
			add("env."+k, "adds %s; units may add only the env keys halos.yaml delegation.envKeys lists", k)
		}
	}
	if !d.AllowHooks {
		for _, h := range child.Hooks.Hooks {
			if !slices.Contains(parent.Hooks.Hooks, h) {
				add("hooks.items", "adds a %s hook running %q; units may add hooks only when halos.yaml sets delegation.allowHooks", h.Event, h.Command)
			}
		}
	}
	for _, s := range child.MCP.Servers {
		same := func(x MCPServer) bool { return reflect.DeepEqual(x, s) }
		if !slices.ContainsFunc(parent.MCP.Servers, same) && !slices.ContainsFunc(o.SelfService.Catalog, same) {
			add("mcp.servers["+s.Name+"]", "adds MCP server %q, which is not an exact selfService.catalog entry; units may add only servers the org lists there", s.Name)
		}
	}
	if !reflect.DeepEqual(parent.Extensions, child.Extensions) {
		add("extensions", "changed; plugins, marketplaces, skills and subagents are decided centrally")
	}
	if parent.Models.Enforce {
		var added []string
		for _, m := range child.Models.Allowed {
			if !slices.Contains(parent.Models.Allowed, m) {
				added = append(added, m)
			}
		}
		if len(added) > 0 {
			add("models.allowed", "adds %v to an enforced allowlist", added)
		}
		if !child.Models.Enforce {
			add("models.enforce", "cannot be turned off")
		}
	}
	if pd, cd := o.agentDepth(parent), o.agentDepth(child); cd > pd {
		add("agents.maxDepth", "%d raises the delegation depth %d; units may only lower it", cd, pd)
	}
	if pr := parent.Agents.Remote; len(pr) > 0 {
		var added []string
		for _, n := range child.Agents.Remote {
			if !slices.Contains(pr, n) {
				added = append(added, n)
			}
		}
		switch {
		case len(added) > 0:
			add("agents.remote", "adds remote agents %v; units may only narrow the remote-agent allowlist", added)
		case len(child.Agents.Remote) == 0:
			add("agents.remote", "drops the remote-agent allowlist %v", pr)
		}
	}
	return out
}

// FieldSource is one leaf of an effective profile and the layer that set it.
type FieldSource struct {
	Path   string `json:"path"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// ExplainEffective returns profile's resolved config with unit's overlays
// applied (unit may be empty) and, for every leaf, the layer that set it:
// "profile <name>" along the extends chain (root first), then "unit <name>"
// along the unit chain. A value no single layer holds (appended instructions)
// names every layer that contributed, joined with " + ".
func (o *Org) ExplainEffective(profile, unit string) (*Profile, []FieldSource, error) {
	chain, err := o.profileChain(profile)
	if err != nil {
		return nil, nil, err
	}
	base, err := o.ResolveProfile(profile)
	if err != nil {
		return nil, nil, err
	}
	eff, err := o.EffectiveProfile(base, unit)
	if err != nil {
		return nil, nil, err
	}
	type layer struct {
		label  string
		values map[string][]string
	}
	var layers []layer
	addLayer := func(label string, doc any) error {
		kvs, err := flatten(doc)
		if err != nil {
			return err
		}
		m := map[string][]string{}
		for _, kv := range kvs {
			m[kv.Path] = append(m[kv.Path], kv.Value)
		}
		layers = append(layers, layer{label, m})
		return nil
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if err := addLayer("profile "+chain[i].Name, chain[i]); err != nil {
			return nil, nil, err
		}
	}
	if unit != "" {
		units, err := o.UnitChain(unit)
		if err != nil {
			return nil, nil, err
		}
		for _, u := range units {
			if err := addLayer("unit "+u.Name, u.Overlay); err != nil {
				return nil, nil, err
			}
		}
	}
	out, err := flatten(eff)
	if err != nil {
		return nil, nil, err
	}
	for i := range out {
		f := &out[i]
		for j := len(layers) - 1; j >= 0 && f.Source == ""; j-- {
			if slices.Contains(layers[j].values[f.Path], f.Value) {
				f.Source = layers[j].label
			}
		}
		if f.Source == "" {
			var from []string
			for _, l := range layers {
				if _, ok := l.values[f.Path]; ok {
					from = append(from, l.label)
				}
			}
			f.Source = strings.Join(from, " + ")
		}
	}
	return eff, out, nil
}

// flatten lists the non-zero leaves of v's JSON form as dotted paths; each
// array element is its own leaf under "<path>[]" (objects as compact JSON).
// Document metadata (apiVersion, kind, name, labels, extends) is skipped.
func flatten(v any) ([]FieldSource, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("policy: flatten: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("policy: flatten: %w", err)
	}
	for _, k := range []string{"apiVersion", "kind", "name", "labels", "extends"} {
		delete(root, k)
	}
	var out []FieldSource
	var walk func(path string, x any)
	walk = func(path string, x any) {
		switch t := x.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, t[k])
			}
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					out = append(out, FieldSource{Path: path + "[]", Value: s})
					continue
				}
				eb, _ := json.Marshal(e) // re-encoding decoded JSON cannot fail
				out = append(out, FieldSource{Path: path + "[]", Value: string(eb)})
			}
		case string:
			if t != "" {
				out = append(out, FieldSource{Path: path, Value: t})
			}
		case bool:
			if t {
				out = append(out, FieldSource{Path: path, Value: "true"})
			}
		case json.Number:
			if t.String() != "0" {
				out = append(out, FieldSource{Path: path, Value: t.String()})
			}
		}
	}
	walk("", root)
	return out, nil
}

// CodeOwners renders a CODEOWNERS file delegating each unit's directory to
// its owners, then its ancestors' owners (any one may approve), after a
// catch-all line for defaults (the central team, which keeps halos.yaml,
// profiles and rings). A top-level unit's own file goes to defaults alone
// (required then): its members draw from the whole org. prefix is the policy
// directory relative to the repository root ("" or "." when they are the
// same). Lines are sorted by path, so a nested unit's line, and a unit's file
// line, follow and override the directory line above them.
func (o *Org) CodeOwners(prefix string, defaults []string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Generated by `halo units codeowners` from the Unit documents (ADR-0018); do not edit by hand.\n")
	if len(defaults) > 0 {
		fmt.Fprintf(&b, "* %s\n", strings.Join(defaults, " "))
	}
	type line struct{ path, owners string }
	var lines []line
	for _, u := range o.Units {
		if u.Dir == "" || u.Dir == "." {
			continue
		}
		chain, err := o.UnitChain(u.Name)
		if err != nil {
			return nil, err
		}
		var owners []string
		for i := len(chain) - 1; i >= 0; i-- {
			owners = unionAppend(owners, chain[i].Owners)
		}
		lines = append(lines, line{path.Join("/", prefix, u.Dir) + "/", strings.Join(owners, " ")})
		if u.Parent == "" && u.File != "" {
			// Its members selector draws from the whole org, and any one listed
			// owner may approve, so the file goes to the root owners alone.
			if len(defaults) == 0 {
				return nil, fmt.Errorf("policy: top-level unit %q: set the root owners (--owner): they own %s, whose members selector draws from the whole org", u.Name, u.File)
			}
			lines = append(lines, line{path.Join("/", prefix, u.File), strings.Join(defaults, " ")})
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].path < lines[j].path })
	for _, l := range lines {
		fmt.Fprintf(&b, "%s %s\n", l.path, l.owners)
	}
	return []byte(b.String()), nil
}

// ownerRe is a CODEOWNERS owner: @user, @org/team, or an email address.
var ownerRe = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)?|[^@\s]+@[^@\s]+\.[^@\s]+)$`)

// unitGuardrails are the built-in guardrails that judge one profile; they
// are re-run on every unit's effective profile (see validator.units).
var unitGuardrails = []Guardrail{
	guardNoBypass, guardTelemetryOn, guardMCPServers, guardEgressHasGateway, guardGARing,
	guardSandboxEgress, guardRingProfiles, guardSecrets, guardEnvKeys,
}

// shippedProfiles are the profiles a unit overlay is applied to: every ring's
// profile and every running client-axis variant's (each ships as a release).
func (o *Org) shippedProfiles() []string {
	var out []string
	for _, r := range o.Rings {
		out = append(out, r.Profile)
		for _, e := range o.ClientExperiments(r.Name) {
			for _, va := range e.Variants {
				out = append(out, va.Profile)
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func (v *validator) units() {
	if d := v.org.Delegation; d != nil {
		for i, k := range d.EnvKeys {
			if why := UnitForbiddenEnv(k); why != "" {
				v.errf(fmt.Sprintf("delegation.envKeys[%d]", i), "%s: %s; units may never set it", k, why)
			}
		}
	}
	units := slices.Clone(v.org.Units)
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })
	dirs := map[string]string{}
	for _, u := range units {
		path := "units[" + u.Name + "]"
		if !ValidName(u.Name) {
			v.errf(path+".name", "name %q invalid: must match %s", u.Name, nameRe)
		}
		chain, err := v.org.UnitChain(u.Name)
		if err != nil {
			v.errf(path+".parent", "%v", err)
		}
		if len(u.Owners) == 0 {
			v.errf(path+".owners", "at least one owner is required (a CODEOWNERS @org/team, @user or email)")
		}
		for i, ow := range u.Owners {
			if !ownerRe.MatchString(ow) {
				v.errf(fmt.Sprintf("%s.owners[%d]", path, i), "%q is not a CODEOWNERS owner (@org/team, @user or email)", ow)
			}
		}
		if len(u.Members.Groups)+len(u.Members.Users) == 0 {
			v.errf(path+".members", "set members.groups or members.users; an empty selector would match nobody")
		}
		if u.Parent == "" && len(u.Members.Users) > 0 {
			v.errf(path+".members.users", "a top-level unit selects from the whole org, so it may name only IdP groups (members.groups); list users on a unit inside it")
		}
		for i, s := range u.Overlay.MCP.Servers {
			if !ValidName(s.Name) {
				v.errf(fmt.Sprintf("%s.overlay.mcp.servers[%d].name", path, i), "name %q invalid: must match %s", s.Name, nameRe)
			}
		}
		v.unitDir(path, u, chain, dirs)
	}
	for _, prof := range v.org.shippedProfiles() {
		base, err := v.org.ResolveProfile(prof)
		if err != nil {
			continue // reported on the ring or experiment
		}
		v.unitOverlays(prof, base, units)
	}
}

// unitDir enforces the CODEOWNERS delegation: a unit lives in a directory of
// its own, nested only inside its ancestors' directories, and unit
// directories hold nothing but Unit documents.
func (v *validator) unitDir(path string, u *Unit, chain []*Unit, dirs map[string]string) {
	if u.Dir == "" {
		return // not loaded from a repo
	}
	if u.Dir == "." {
		v.errf(path, "a Unit must live in its own directory (e.g. units/%s/unit.yaml), not the policy root, whose owners own the whole repo", u.Name)
		return
	}
	if prev, dup := dirs[u.Dir]; dup {
		v.errf(path, "directory %s/ already belongs to unit %q; one unit per directory", u.Dir, prev)
	}
	dirs[u.Dir] = u.Name
	for _, w := range v.org.Units {
		if w == u || w.Dir == "" || w.Dir == "." || !strings.HasPrefix(u.Dir+"/", w.Dir+"/") || w.Dir == u.Dir {
			continue
		}
		if !slices.Contains(chain, w) {
			v.errf(path, "declared in %s/, inside unit %q's directory, but %q is not one of its ancestors", u.Dir, w.Name, w.Name)
		}
	}
	for _, s := range v.org.Sources {
		if s.Kind != KindUnit && strings.HasPrefix(s.Path, u.Dir+"/") {
			v.errf(path, "%s declares a %s inside the unit's directory %s/; unit directories may hold only Unit documents", s.Path, s.Kind, u.Dir)
		}
	}
}

// unitOverlays applies every unit to the shipped profile prof (resolved as
// base): each overlay is checked against its parent's effective profile for
// loosenings, and the effective profile must pass the profile checks and
// guardrails that base passes. Issues name the unit, not the profile.
func (v *validator) unitOverlays(prof string, base *Profile, units []*Unit) {
	effs := map[string]*Profile{} // nil = could not be computed (reported)
	var eff func(u *Unit, depth int) *Profile
	eff = func(u *Unit, depth int) *Profile {
		if p, ok := effs[u.Name]; ok {
			return p
		}
		effs[u.Name] = nil
		parent := base
		if u.Parent != "" {
			pu := v.org.Unit(u.Parent)
			if pu == nil || depth > len(units) {
				return nil // reported by units()
			}
			if parent = eff(pu, depth+1); parent == nil {
				return nil
			}
		}
		out := copyProfile(parent)
		if err := applyOverlay(out, u); err != nil {
			v.onceErr("units["+u.Name+"].overlay.mcp.servers", err.Error(), err.Error())
			return nil
		}
		against := "profile " + prof
		if u.Parent != "" {
			against = "parent unit " + u.Parent + " on profile " + prof
		}
		for _, l := range v.org.Loosenings(parent, out) {
			v.onceErr("units["+u.Name+"].overlay."+l.Field, l.Message,
				fmt.Sprintf("%s (vs %s): units may only tighten the enforced baseline", l.Message, against))
		}
		effs[u.Name] = out
		return out
	}
	seen := v.unitChecks(prof, "", base, nil)
	for _, u := range units {
		if p := eff(u, 0); p != nil {
			v.unitChecks(prof, u.Name, p, seen)
		}
	}
}

// unitChecks runs the profile checks and unitGuardrails on p as profile prof
// and returns the issues; with base set (base's issues) it reports, under
// units[...], only issues base does not have.
func (v *validator) unitChecks(prof, unit string, p *Profile, base map[string]bool) map[string]bool {
	mini := &Org{Name: v.org.Name, Gateway: v.org.Gateway, Profiles: map[string]*Profile{prof: p}}
	for _, r := range v.org.Rings {
		if r.Profile == prof {
			mini.Rings = append(mini.Rings, r)
		}
	}
	tv := &validator{org: mini}
	tv.profileSpec("profiles["+prof+"]", p)
	issues := tv.issues
	for _, g := range unitGuardrails {
		issues = append(issues, g(mini)...)
	}
	got := map[string]bool{}
	for _, i := range issues {
		got[i.Path+"\x00"+i.Message] = true
		if base == nil || base[i.Path+"\x00"+i.Message] || i.Severity != SeverityError {
			continue
		}
		path := "units[" + unit + "]"
		if rest, ok := strings.CutPrefix(i.Path, "profiles["+prof+"]"); ok {
			path += ".overlay" + rest
		}
		v.onceErr(path, i.Message, i.Message+" (effective config on profile "+prof+")")
	}
	return got
}

// onceErr reports msg under path once per path+key: the same overlay is
// checked against every shipped profile, and the first profile is named.
func (v *validator) onceErr(path, key, msg string) {
	if v.once == nil {
		v.once = map[string]bool{}
	}
	if k := path + "\x00" + key; !v.once[k] {
		v.once[k] = true
		v.errf(path, "%s", msg)
	}
}
