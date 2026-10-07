// Package claudecode renders Claude Code's managed settings.
package claudecode

import (
	"fmt"
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
		"mcp.managedOnly", "mcp.servers", "mcp.denied", "hooks.managedOnly", "hooks.items",
		"telemetry.enabled", "telemetry.logPrompts", "telemetry.attributes",
		"egress.allowedDomains", "instructions", "env")

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
	if len(headers) > 0 {
		// Keep a profile's own headers (a company gateway's routing or tenant
		// header, say); Halos's go last.
		if own, _ := env["ANTHROPIC_CUSTOM_HEADERS"].(string); strings.TrimSpace(own) != "" {
			own = strings.TrimRight(own, "\n")
			for _, l := range strings.Split(own, "\n") {
				if strings.Contains(l, "\r") {
					return nil, nil, fmt.Errorf("claudecode: env ANTHROPIC_CUSTOM_HEADERS: a header line contains CR")
				}
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "x-halo-") {
					return nil, nil, fmt.Errorf("claudecode: env ANTHROPIC_CUSTOM_HEADERS: %q is set by Halos only", strings.SplitN(l, ":", 2)[0])
				}
			}
			headers = append([]string{own}, headers...)
		}
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

	perms := map[string]any{}
	for k, v := range map[string][]string{"allow": p.Permissions.Allow, "deny": p.Permissions.Deny, "ask": p.Permissions.Ask} {
		if len(v) > 0 {
			perms[k] = v
		}
	}
	if p.Permissions.Mode != "" {
		perms["defaultMode"] = p.Permissions.Mode
	}
	if len(perms) > 0 {
		s["permissions"] = perms
	}
	if p.Permissions.DisableBypass {
		s["disableBypassPermissionsMode"] = "disable"
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

	// sandbox.network.* is inert unless sandbox.enabled; allowUnsandboxedCommands
	// false removes the dangerouslyDisableSandbox retry escape hatch.
	// Claude's sandbox confines Bash writes to the working directory, which is
	// workspace-write; it has no read-only mode.
	// https://code.claude.com/docs/en/sandboxing#enforce-sandboxing-with-managed-settings
	egress := p.Egress.AllowedDomains
	sandboxOn := len(egress) > 0
	switch p.Permissions.Sandbox {
	case "workspace-write":
		sandboxOn = true
	case "read-only":
		sandboxOn = true
		warns = append(warns, name+`: permissions.sandbox "read-only" has no Claude Code equivalent; rendered as the workspace-write sandbox`)
	case "off":
		if sandboxOn {
			warns = append(warns, name+`: permissions.sandbox "off" overridden: egress.allowedDomains is enforced by the sandbox, so it is enabled`)
		}
	}
	if p.Permissions.SandboxRequired {
		sandboxOn = true
	}
	if sandboxOn {
		sb := map[string]any{"enabled": true, "allowUnsandboxedCommands": false}
		if p.Permissions.SandboxRequired {
			// Missing bubblewrap/socat blocks startup instead of running unsandboxed.
			// https://code.claude.com/docs/en/sandboxing
			sb["failIfUnavailable"] = true
		}
		if len(egress) > 0 {
			sb["network"] = map[string]any{"allowedDomains": egress, "allowManagedDomainsOnly": true}
		}
		s["sandbox"] = sb
		if c.OS == harness.Windows {
			warns = append(warns, name+": the Claude Code sandbox does not run on native Windows; sandbox and egress settings are not enforced there (use WSL2)")
		}
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
	return files, warns, nil
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
