// Package claudecode renders Claude Code's managed settings.
package claudecode

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
)

const name = "claude-code"

// builtinIDs are the first-party IDs Claude Code 2.1.280 resolves each alias to
// (verified in test/uat). ponytail: per-generation table; a new default ID shows
// up as the UAT "no silent fallback" row failing, then add it here.
var builtinIDs = map[string]string{"opus": "claude-opus-5-5", "sonnet": "claude-sonnet-5", "haiku": "claude-haiku-4-5-20251001"}

func init() { harness.Register(Adapter{}) }

// Adapter implements harness.Adapter for Claude Code.
type Adapter struct{}

func (Adapter) Name() string { return name }

// Meta implements harness.Describer.
func (Adapter) Meta() harness.Meta {
	return harness.Meta{Binary: "claude", Installer: harness.InstallerClaudeNative, UAPrefixes: []string{"claude-cli", "claude-code"},
		ManagedDirs: map[harness.OS][]string{harness.Darwin: {dir(harness.Darwin)}, harness.Linux: {dir(harness.Linux)}, harness.Windows: {dir(harness.Windows)}}}
}

func (Adapter) Capabilities() []harness.Capability {
	return []harness.Capability{
		harness.CapVersionPin, harness.CapModelLock, harness.CapMCPAllowlist, harness.CapHooksLock,
		harness.CapPermissions, harness.CapGateway, harness.CapTelemetry, harness.CapInstructions, harness.CapHeaders,
		harness.CapExtensions, harness.CapSandbox, harness.CapEgress,
	}
}

func (Adapter) InstallCommand(version string, os harness.OS) string {
	if os == harness.Windows {
		return "& ([scriptblock]::Create((irm https://claude.ai/install.ps1))) " + version
	}
	return "curl -fsSL https://claude.ai/install.sh | bash -s " + version
}

func dir(os harness.OS) string {
	switch os {
	case harness.Darwin:
		return "/Library/Application Support/ClaudeCode"
	case harness.Windows:
		return `C:\Program Files\ClaudeCode`
	default:
		return "/etc/claude-code"
	}
}

func (Adapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	warns := hutil.WarnUnsupported(name, p,
		"models.default", "models.allowed", "models.enforce",
		"permissions.mode", "permissions.allow", "permissions.deny", "permissions.ask", "permissions.disableBypass", "permissions.sandbox",
		"mcp.managedOnly", "mcp.servers", "mcp.denied", "mcp.tools.allow", "mcp.tools.deny", "mcp.auth", "hooks.managedOnly", "hooks.items",
		"telemetry.enabled", "telemetry.logPrompts", "telemetry.attributes",
		"egress.allowedDomains", "egress.default", "egress.deniedDomains", "egress.presets",
		"sandbox.writableRoots", "sandbox.protectedPaths", "instructions", "env",
		"extensions.marketplaces", "extensions.blockedMarketplaces", "extensions.plugins.enabled", "extensions.plugins.blocked",
		"extensions.skills.deny", "extensions.skills.pluginOnly", "extensions.subagents.deny", "extensions.subagents.pluginOnly",
		"extensions.outputStyle", "extensions.statusLine", "extensions.artifacts", "login")

	// The profile's env goes in first: every key Halos sets below (gateway
	// routing, model pins, telemetry's OTEL_*) is written after it and wins,
	// so an env key (a unit's, say) can never override them.
	env := map[string]any{}
	for k, v := range p.Env {
		env[k] = v
	}
	env["DISABLE_AUTOUPDATER"] = "1"
	// ANTHROPIC_CUSTOM_HEADERS is newline-separated: a CR/LF in a value would
	// inject extra headers (e.g. a spoofed x-halo-ring). Policy names are
	// validated upstream; this is the adapter's own backstop.
	if err := hutil.CheckHeaderValues(map[string]string{"ring": c.Ring, "release": c.Release}); err != nil {
		return nil, nil, fmt.Errorf("claudecode: %w", err)
	}
	var headers []string
	if c.Ring != "" {
		headers = append(headers, "x-halo-ring: "+c.Ring)
	}
	if c.Release != "" {
		headers = append(headers, "x-halo-release: "+c.Release)
	}
	// Keep a profile's own headers (a company gateway's routing or tenant
	// header, say); Halos's go last. Validated here too, as a backstop.
	if own, _ := env["ANTHROPIC_CUSTOM_HEADERS"].(string); strings.TrimSpace(own) != "" {
		if err := policy.CheckCustomHeaders(own); err != nil {
			return nil, nil, fmt.Errorf("claudecode: env ANTHROPIC_CUSTOM_HEADERS: %w", err)
		}
		headers = append([]string{strings.TrimRight(own, "\n")}, headers...)
	}
	if len(headers) > 0 {
		env["ANTHROPIC_CUSTOM_HEADERS"] = strings.Join(headers, "\n")
	}

	s := map[string]any{"env": env}
	if g := c.Gateway; g != nil {
		switch proto := hutil.Protocol(g, name, "anthropic-messages"); proto {
		case "anthropic-messages":
			env["ANTHROPIC_BASE_URL"] = g.BaseURL
		case "bedrock-invoke":
			env["CLAUDE_CODE_USE_BEDROCK"] = "1"
			env["ANTHROPIC_BEDROCK_BASE_URL"] = g.BaseURL
			env["CLAUDE_CODE_SKIP_BEDROCK_AUTH"] = "1"
		default:
			return nil, nil, fmt.Errorf("claudecode: unsupported gateway protocol %q", proto)
		}
		// Claude Code resolves its own aliases before sending (managed
		// `model: sonnet` goes out as e.g. claude-sonnet-5, seen in test/uat),
		// but the gateway allowlists policy aliases: pin each Claude alias the
		// gateway routes to itself so the request carries the alias.
		// The pins do not reach Claude's own fallback: a --model outside
		// availableModels is dropped silently and the tier default goes out as
		// its built-in ID (claude-opus-5-5[1m] on 2.1.280), ignoring the env.
		// modelOverrides does apply there, so map each built-in ID to its alias.
		// Behind an external gateway nothing rejects an unlisted model, so with
		// models enforced every tier Claude can fall back to is pinned to the
		// default model instead.
		lock := ""
		if g.Engine == policy.EngineExternal && p.Models.Enforce {
			lock = hutil.ClientModel(c, hutil.Model(p, name))
		}
		overrides := map[string]any{}
		for _, a := range []string{"opus", "sonnet", "haiku"} {
			m := lock
			if _, ok := g.Models[a]; ok {
				m = hutil.ClientModel(c, a)
			}
			if m != "" {
				env["ANTHROPIC_DEFAULT_"+strings.ToUpper(a)+"_MODEL"] = m
				overrides[builtinIDs[a]] = m
			}
		}
		if len(overrides) > 0 {
			s["modelOverrides"] = overrides
		}
		if g.Auth.HelperCommand != "" {
			s["apiKeyHelper"] = g.Auth.HelperCommand
		}
		if g.Auth.TTLSeconds > 0 {
			env["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"] = strconv.Itoa(g.Auth.TTLSeconds * 1000)
		}
	} else {
		warns = append(warns, name+": no gateway configured; traffic is not routed through Halos")
	}

	if t := p.Telemetry; t.Enabled {
		env["CLAUDE_CODE_ENABLE_TELEMETRY"] = "1"
		env["OTEL_METRICS_EXPORTER"] = "otlp"
		env["OTEL_LOGS_EXPORTER"] = "otlp"
		env["OTEL_METRICS_INCLUDE_VERSION"] = "true"
		if t.Protocol != "" {
			env["OTEL_EXPORTER_OTLP_PROTOCOL"] = t.Protocol
		}
		if t.OTLPEndpoint != "" {
			env["OTEL_EXPORTER_OTLP_ENDPOINT"] = t.OTLPEndpoint
		}
		if t.LogPrompts {
			env["OTEL_LOG_USER_PROMPTS"] = "1"
		}
		env["OTEL_RESOURCE_ATTRIBUTES"] = hutil.OTELResourceAttributes(name, t, c)
	}

	if m := hutil.ClientModel(c, hutil.Model(p, name)); m != "" {
		s["model"] = m
	}
	if len(p.Models.Allowed) > 0 {
		allowed := make([]string, len(p.Models.Allowed))
		for i, a := range p.Models.Allowed {
			allowed[i] = hutil.ClientModel(c, a)
		}
		s["availableModels"] = allowed
		if p.Models.Enforce {
			s["enforceAvailableModels"] = true
		}
	}

	// Skills and subagents are denied with permission rules: Skill(skill:NAME)
	// matches the skill under any of its names, Agent(NAME) the subagent.
	// https://code.claude.com/docs/en/permissions
	deny := slices.Clone(p.Permissions.Deny)
	// Protected paths: Read/Edit deny rules cover the built-in file tools, which
	// the sandbox does not confine; sandbox.filesystem below covers Bash.
	// Egress deny rules: WebFetch(domain:...) for the fetch tool, which the
	// sandbox proxy does not see. https://code.claude.com/docs/en/permissions
	deny = append(deny, hutil.ProtectedRules(p.Sandbox.ProtectedPaths, "/")...)
	er := p.Egress.Rules()
	for _, d := range er.Deny {
		deny = append(deny, "WebFetch(domain:"+d+")")
	}
	for _, n := range p.Extensions.Skills.Deny {
		deny = append(deny, "Skill(skill:"+n+")")
	}
	for _, n := range p.Extensions.Subagents.Deny {
		deny = append(deny, "Agent("+n+")")
	}
	// A bare-name deny rule removes the MCP tool from Claude's context; there is
	// no per-server allowlist (deny always wins over allow), so tools.allow warns.
	// https://code.claude.com/docs/en/permissions
	for _, sv := range p.MCP.Servers {
		for _, t := range sv.Tools.Deny {
			deny = append(deny, "mcp__"+sv.Name+"__"+t)
		}
		if len(sv.Tools.Allow) > 0 {
			warns = append(warns, fmt.Sprintf("%s: mcp server %q tools.allow is not rendered: Claude Code has no per-server tool allowlist (a deny rule always wins over allow), so every tool the server exposes stays available; deny the others with tools.deny", name, sv.Name))
		}
	}
	perms := map[string]any{}
	for k, v := range map[string][]string{"allow": p.Permissions.Allow, "deny": deny, "ask": p.Permissions.Ask} {
		if len(v) > 0 {
			perms[k] = v
		}
	}
	if p.Permissions.Mode != "" {
		perms["defaultMode"] = p.Permissions.Mode
	}
	// Claude Code reads the bypass lock only inside the permissions object; a
	// top-level key is ignored. Verified 2026-10-27 at
	// https://code.claude.com/docs/en/settings-reference#permissions-disablebypasspermissionsmode
	if p.Permissions.DisableBypass {
		perms["disableBypassPermissionsMode"] = "disable"
	}
	if len(perms) > 0 {
		s["permissions"] = perms
	}

	// Plugin, skill, subagent, output style, status line and login keys. All are
	// managed-settings keys, verified at https://code.claude.com/docs/en/settings-reference
	// (strictKnownMarketplaces, blockedMarketplaces, enabledPlugins,
	// strictPluginOnlyCustomization, outputStyle, statusLine, forceLoginMethod).
	ext := p.Extensions
	if len(ext.Marketplaces) > 0 {
		s["strictKnownMarketplaces"] = ext.Marketplaces
	}
	if len(ext.BlockedMarketplaces) > 0 {
		s["blockedMarketplaces"] = ext.BlockedMarketplaces
	}
	if len(ext.Plugins.Enabled)+len(ext.Plugins.Blocked) > 0 {
		plugins := map[string]any{}
		for _, k := range ext.Plugins.Enabled {
			plugins[k] = true
		}
		for _, k := range ext.Plugins.Blocked {
			plugins[k] = false // blocked wins: managed false blocks install at every scope
		}
		s["enabledPlugins"] = plugins
	}
	var pluginOnly []string
	if ext.Skills.PluginOnly {
		pluginOnly = append(pluginOnly, "skills")
	}
	if ext.Subagents.PluginOnly {
		pluginOnly = append(pluginOnly, "agents")
	}
	if len(pluginOnly) > 0 {
		s["strictPluginOnlyCustomization"] = pluginOnly
		if len(ext.Marketplaces) == 0 {
			warns = append(warns, name+": skills/subagents pluginOnly without extensions.marketplaces lets users install plugins from any marketplace; set an allowlist")
		}
	}
	if ext.OutputStyle != "" {
		s["outputStyle"] = ext.OutputStyle
	}
	if sl := ext.StatusLine; sl.Command != "" {
		line := map[string]any{"type": "command", "command": sl.Command}
		if sl.Padding > 0 {
			line["padding"] = sl.Padding
		}
		s["statusLine"] = line
	}
	switch p.Login {
	case policy.LoginSubscription:
		s["forceLoginMethod"] = "claudeai"
	case policy.LoginAPI:
		s["forceLoginMethod"] = "console"
	}

	if p.Hooks.ManagedOnly {
		s["allowManagedHooksOnly"] = true
	}
	if len(p.Hooks.Hooks) > 0 {
		s["hooks"] = hooks(p.Hooks.Hooks)
	}

	// MCP allow/deny entries match on what actually runs (serverUrl /
	// serverCommand), not serverName: a name is a user-chosen label, so any
	// server can be renamed to pass a name-based list.
	// https://code.claude.com/docs/en/managed-mcp#match-servers-by-url-command-or-name
	if p.MCP.ManagedOnly || len(p.MCP.Servers) > 0 {
		s["allowManagedMcpServersOnly"] = true
	}
	if len(p.MCP.Servers) > 0 {
		var allowed []any
		for _, sv := range p.MCP.Servers {
			switch {
			case sv.URL != "":
				allowed = append(allowed, map[string]any{"serverUrl": sv.URL})
			case len(sv.Command) > 0:
				allowed = append(allowed, map[string]any{"serverCommand": sv.Command})
			default:
				return nil, nil, fmt.Errorf("claudecode: mcp server %q has neither url nor command", sv.Name)
			}
		}
		s["allowedMcpServers"] = allowed
	}
	if len(p.MCP.Denied) > 0 {
		var denied []any
		for _, n := range p.MCP.Denied {
			if strings.Contains(n, "://") {
				denied = append(denied, map[string]any{"serverUrl": n})
				continue
			}
			denied = append(denied, map[string]any{"serverName": n})
			warns = append(warns, fmt.Sprintf("%s: mcp.denied %q is matched by name only, which a user can bypass by renaming the server; deny by URL instead", name, n))
		}
		s["deniedMcpServers"] = denied
	}

	spec := p.Harnesses[name]
	if spec.Version != "" {
		s["requiredMinimumVersion"] = spec.Version
		s["requiredMaximumVersion"] = spec.Version
	} else {
		warns = append(warns, name+": no version pinned; CLI version is not enforced")
	}

	sb, sw := sandbox(p, er, c.OS)
	warns = append(warns, sw...)
	if sb != nil {
		s["sandbox"] = sb
	}

	hutil.DeepMerge(s, spec.Overrides)

	data, err := hutil.JSON(s)
	if err != nil {
		return nil, nil, err
	}
	d := dir(c.OS)
	files := []harness.File{{Path: hutil.Join(c.OS, d, "managed-settings.json"), Mode: 0o644, Data: data}}

	if len(p.MCP.Servers) > 0 {
		servers := map[string]any{}
		for _, sv := range p.MCP.Servers {
			switch {
			case sv.URL != "":
				e := map[string]any{"type": "http", "url": sv.URL}
				if len(sv.Headers) > 0 {
					// Values are rendered as-is: Claude Code expands ${VAR} in
					// headers, so secrets stay on the client.
					if err := hutil.CheckHeaderValues(sv.Headers); err != nil {
						return nil, nil, fmt.Errorf("claudecode: mcp server %q: %w", sv.Name, err)
					}
					e["headers"] = sv.Headers
				}
				warns = append(warns, claudeAuth(e, sv)...)
				servers[sv.Name] = e
			case len(sv.Command) > 0:
				e := map[string]any{"command": sv.Command[0]}
				if len(sv.Command) > 1 {
					e["args"] = sv.Command[1:]
				}
				servers[sv.Name] = e
			default:
				return nil, nil, fmt.Errorf("claudecode: mcp server %q has neither url nor command", sv.Name)
			}
		}
		md, err := hutil.JSON(map[string]any{"mcpServers": servers})
		if err != nil {
			return nil, nil, err
		}
		files = append(files, harness.File{Path: hutil.Join(c.OS, d, "managed-mcp.json"), Mode: 0o644, Data: md})
	}
	if p.Instructions != "" {
		files = append(files, harness.File{Path: hutil.Join(c.OS, d, "CLAUDE.md"), Mode: 0o644, Data: []byte(p.Instructions)})
	}
	af, aw := hutil.RenderArtifacts(name, c.OS, p, artifactDirs(c.OS))
	return append(files, af...), append(warns, aw...), nil
}

// sandbox renders the sandbox block: mode, filesystem lists and the network
// allow/deny lists (ADR-0032). sandbox.network.* and sandbox.filesystem.* are
// inert unless sandbox.enabled; allowUnsandboxedCommands false removes the
// dangerouslyDisableSandbox retry escape hatch; allowManagedDomainsOnly makes
// the managed allowlist the only one and refuses other hosts without a
// prompt; a deniedDomains host is refused in every permission mode.
// Claude's sandbox confines Bash writes to the working directory, which is
// workspace-write; it has no read-only mode.
// https://code.claude.com/docs/en/sandboxing, .../settings-reference#sandbox-settings
func sandbox(p *policy.Profile, er policy.EgressRules, os harness.OS) (map[string]any, []string) {
	var warns []string
	restricted := p.Egress.Restricted()
	paths := len(p.Sandbox.ProtectedPaths)+len(p.Sandbox.WritableRoots) > 0
	on := restricted || paths || p.Permissions.SandboxRequired
	switch p.Permissions.Sandbox {
	case "workspace-write":
		on = true
	case "read-only":
		on = true
		warns = append(warns, name+`: permissions.sandbox "read-only" has no Claude Code equivalent; rendered as the workspace-write sandbox`)
	case "off":
		if restricted || paths {
			warns = append(warns, name+`: permissions.sandbox "off" overridden: egress and sandbox paths are enforced by the sandbox, so it is enabled`)
		}
	}
	if !on {
		return nil, nil
	}
	sb := map[string]any{"enabled": true, "allowUnsandboxedCommands": false}
	if p.Permissions.SandboxRequired {
		// Missing bubblewrap/socat blocks startup instead of running unsandboxed.
		sb["failIfUnavailable"] = true
	}
	fs := map[string]any{}
	if len(p.Sandbox.WritableRoots) > 0 {
		fs["allowWrite"] = p.Sandbox.WritableRoots
	}
	// Relative sandbox paths resolve against the project (project settings) or
	// ~/.claude (user settings); managed settings are not documented, so only
	// absolute and ~/ protected paths go in; the rest stay permission rules.
	abs, rel := hutil.SplitPaths(p.Sandbox.ProtectedPaths, true)
	if len(abs) > 0 {
		fs["denyRead"], fs["denyWrite"] = abs, abs
	}
	if len(rel) > 0 {
		warns = append(warns, fmt.Sprintf("%s: sandbox.protectedPaths %v are workspace-relative; managed sandbox.filesystem paths have no documented project root, so they are enforced on the Read/Edit tools only, not on Bash", name, rel))
	}
	if len(fs) > 0 {
		sb["filesystem"] = fs
	}
	if restricted {
		net := map[string]any{}
		if er.Default == policy.EgressDeny {
			net["allowedDomains"] = append([]string{}, er.Allow...) // [] (not null): nothing allowed
			net["allowManagedDomainsOnly"] = true
			warns = append(warns, name+": egress default deny: the WebFetch tool still asks before fetching a host outside the allowlist (deny rules win over allow rules, so deny-by-default cannot be expressed for it); Bash is held to the allowlist by the sandbox")
		} else {
			warns = append(warns, name+": egress default allow: the sandbox still asks before Bash reaches a new host (Claude Code has no allow-everything sandbox network setting)")
		}
		if len(er.Deny) > 0 {
			net["deniedDomains"] = er.Deny
		}
		sb["network"] = net
	}
	if os == harness.Windows {
		warns = append(warns, name+": the Claude Code sandbox does not run on native Windows; sandbox and egress settings are not enforced there (use WSL2)")
	}
	return sb, warns
}

// artifactDirs places supply-chain artifacts (ADR-0028) in the managed
// directory's .claude/ tree, the managed scope of Claude Code's skills,
// subagents and commands. Hook scripts get a Halos-owned directory that a
// hooks.items command runs (`sh <managed dir>/hooks/<name>/<script>`; halod
// writes 0644, so invoke them through an interpreter). ponytail: placement
// read from the skills/subagents docs' managed scope, not yet UAT'd
// (ADR-0028 open items).
func artifactDirs(os harness.OS) hutil.ArtifactDirs {
	d := dir(os)
	return hutil.ArtifactDirs{
		Dirs: map[string]string{
			policy.ArtifactSkill: hutil.Join(os, d, ".claude", "skills"),
			policy.ArtifactHook:  hutil.Join(os, d, "hooks"),
		},
		Single: map[string]string{
			policy.ArtifactAgent:   hutil.Join(os, d, ".claude", "agents"),
			policy.ArtifactCommand: hutil.Join(os, d, ".claude", "commands"),
		},
		Why: map[string]string{
			policy.ArtifactPlugin: "Claude Code installs plugins from marketplaces; allow its marketplace with extensions.marketplaces and pin it with extensions.plugins.enabled",
		},
	}
}

// claudeAuth renders a remote server's authorization into its managed-mcp.json
// entry e: oauth.clientId and oauth.scopes (a space-separated string) for mode
// oauth, headersHelper running `halo mcp token` for mode halos.
// https://code.claude.com/docs/en/mcp (pre-configured OAuth credentials, headersHelper)
func claudeAuth(e map[string]any, sv policy.MCPServer) []string {
	a := sv.Auth
	var warns []string
	switch a.Mode {
	case policy.MCPAuthOAuth:
		o := map[string]any{}
		if a.ClientID != "" {
			o["clientId"] = a.ClientID
		}
		if len(a.Scopes) > 0 {
			o["scopes"] = strings.Join(a.Scopes, " ")
		}
		if len(o) > 0 {
			e["oauth"] = o
		}
		if a.ClientIDMetadataURL != "" {
			warns = append(warns, fmt.Sprintf("%s: mcp server %q auth.clientIDMetadataURL is not rendered: Claude Code presents its own Client ID Metadata Document and has no setting for an org-hosted one", name, sv.Name))
		}
		if a.Issuer != "" {
			warns = append(warns, fmt.Sprintf("%s: mcp server %q auth.issuer is not rendered: Claude Code discovers the authorization server (RFC 9728, then RFC 8414)", name, sv.Name))
		}
	case policy.MCPAuthEnterprise:
		warns = append(warns, fmt.Sprintf("%s: mcp server %q auth mode enterprise is not rendered: Claude Code documents no Enterprise-Managed Authorization (ID-JAG) client; users authorize the server with /mcp", name, sv.Name))
	case policy.MCPAuthHalos:
		// Managed servers' helpers run from ~/.claude with the user's environment.
		e["headersHelper"] = hutil.MCPTokenHelper(sv.URL)
	}
	return warns
}

// hooks groups hooks by event then matcher, preserving first-seen order.
func hooks(hs []policy.Hook) map[string]any {
	type key struct{ event, matcher string }
	idx := map[key]int{}
	byEvent := map[string][]map[string]any{}
	for _, h := range hs {
		k := key{h.Event, h.Matcher}
		cmd := map[string]any{"type": "command", "command": h.Command}
		if i, ok := idx[k]; ok {
			g := byEvent[h.Event][i]
			g["hooks"] = append(g["hooks"].([]any), cmd)
			continue
		}
		g := map[string]any{"hooks": []any{cmd}}
		if h.Matcher != "" {
			g["matcher"] = h.Matcher
		}
		idx[k] = len(byEvent[h.Event])
		byEvent[h.Event] = append(byEvent[h.Event], g)
	}
	out := map[string]any{}
	for e, gs := range byEvent {
		out[e] = gs
	}
	return out
}
