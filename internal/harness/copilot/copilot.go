// Package copilot renders GitHub Copilot CLI file-based enterprise managed
// settings (managed-settings.json). Facts and sources: internal/harness/FACTS.md.
package copilot

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
)

const (
	name     = "copilot-cli"
	profileD = "/etc/profile.d/halos-copilot-cli.sh"
)

func init() { harness.Register(Adapter{}) }

// Adapter implements harness.Adapter for GitHub Copilot CLI.
type Adapter struct{}

func (Adapter) Name() string { return name }

// Meta implements harness.Describer.
func (Adapter) Meta() harness.Meta {
	return harness.Meta{Binary: "copilot", Installer: harness.InstallerNPM, NPMPackage: "@github/copilot",
		ManagedDirs:  map[harness.OS][]string{harness.Darwin: {"/Library/Application Support/GitHubCopilot"}, harness.Linux: {"/etc/github-copilot"}, harness.Windows: {`C:\Program Files\GitHubCopilot`}},
		ManagedFiles: map[harness.OS][]string{harness.Linux: {profileD}}}
}

func (Adapter) Capabilities() []harness.Capability {
	return []harness.Capability{harness.CapTelemetry, harness.CapMCPAllowlist, harness.CapPermissions,
		harness.CapExtensions, harness.CapSandbox, harness.CapEgress, // partial: plugin marketplaces and plugin pins only
	}
}

func (Adapter) InstallCommand(version string, _ harness.OS) string {
	return "npm install -g @github/copilot@" + version
}

// sandbox renders the managed sandbox (ADR-0032): enabled with no bypass,
// failIfUnavailable for sandboxRequired, userPolicy.filesystem (readwritePaths
// = writable roots, deniedPaths = protected paths) and userPolicy.network
// (allowedHosts: a non-empty list blocks every other host, *.x = subdomains
// only; blockedHosts win and also block subdomains; allowOutbound false for a
// default deny with nothing allowed). Managed sandbox settings are minimums a
// user cannot lower. Clients below Copilot CLI 1.0.93 are blocked from
// Copilot once the key is present, so an older pin renders nothing.
// https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings
func sandbox(p *policy.Profile, os harness.OS) (map[string]any, []string) {
	m := p.Permissions.Sandbox
	paths := len(p.Sandbox.ProtectedPaths)+len(p.Sandbox.WritableRoots) > 0
	if (m == "" || m == "off") && !p.Egress.Restricted() && !paths && !p.Permissions.SandboxRequired {
		return nil, nil
	}
	if v := p.Harnesses[name].Version; hutil.PatchBefore(v, 1, 0, 93) {
		return nil, []string{fmt.Sprintf("copilot-cli: %s is below 1.0.93, the first Copilot CLI that supports the managed sandbox (older clients are blocked from Copilot while the key is set); sandbox and egress are not rendered", v)}
	}
	var warns []string
	if p.Harnesses[name].Version == "" {
		warns = append(warns, "copilot-cli: no version pinned; the managed sandbox needs Copilot CLI >= 1.0.93 and blocks older clients from Copilot")
	}
	if m == "off" {
		warns = append(warns, `copilot-cli: permissions.sandbox "off" overridden: egress and sandbox paths are enforced by the sandbox, so it is enabled`)
	}
	if m == "read-only" {
		warns = append(warns, `copilot-cli: permissions.sandbox "read-only" has no Copilot equivalent; rendered as the default sandbox (the working directory stays writable)`)
	}
	sb := map[string]any{"enabled": true, "allowBypass": false}
	if p.Permissions.SandboxRequired {
		sb["failIfUnavailable"] = true
	}
	user := map[string]any{}
	fs := map[string]any{}
	if roots, rest := hutil.SplitPaths(p.Sandbox.WritableRoots, false); len(roots) > 0 || len(rest) > 0 {
		if len(roots) > 0 {
			fs["readwritePaths"] = roots
		}
		if len(rest) > 0 {
			warns = append(warns, fmt.Sprintf("copilot-cli: sandbox.writableRoots %v are not absolute (readwritePaths are matched by exact absolute path); not rendered", rest))
		}
	}
	if denied, rest := hutil.SplitPaths(p.Sandbox.ProtectedPaths, true); len(denied) > 0 || len(rest) > 0 {
		if len(denied) > 0 {
			fs["deniedPaths"] = denied
			if slices.ContainsFunc(denied, func(d string) bool { return strings.HasPrefix(d, "~/") }) {
				warns = append(warns, "copilot-cli: deniedPaths \"should be absolute\"; ~/ expansion is not documented (UNVERIFIED), so ~/ protected paths may not be enforced")
			}
		}
		if len(rest) > 0 {
			warns = append(warns, fmt.Sprintf("copilot-cli: sandbox.protectedPaths %v are workspace-relative; deniedPaths takes absolute paths, so they are not rendered", rest))
		}
	}
	if len(fs) > 0 {
		user["filesystem"] = fs
	}
	if p.Egress.Restricted() {
		er := p.Egress.Rules()
		net := map[string]any{}
		if er.Default == policy.EgressDeny {
			if len(er.Allow) > 0 {
				net["allowedHosts"] = er.Allow
			} else {
				net["allowOutbound"] = false
			}
		}
		if len(er.Deny) > 0 {
			net["blockedHosts"] = er.Deny
			warns = append(warns, "copilot-cli: blockedHosts also blocks subdomains of an exact host (stricter than egress.deniedDomains)")
		}
		user["network"] = net
		if os == harness.Windows {
			warns = append(warns, "copilot-cli: on Windows the sandbox relies on programs honoring the proxy settings, so egress host rules do not stop direct connections")
		}
		warns = append(warns, "copilot-cli: egress host rules apply to sandboxed commands; whether the CLI's own URL fetches use the sandbox proxy is not documented (UNVERIFIED)")
	}
	if len(user) > 0 {
		sb["userPolicy"] = user
	}
	return sb, warns
}

func settingsPath(os harness.OS) string {
	switch os {
	case harness.Darwin:
		return "/Library/Application Support/GitHubCopilot/managed-settings.json"
	case harness.Windows:
		return `C:\Program Files\GitHubCopilot\managed-settings.json`
	default:
		return "/etc/github-copilot/managed-settings.json"
	}
}

func (Adapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	warns := hutil.WarnUnsupported(name, p,
		"models.default", "permissions.disableBypass", "mcp.servers", "mcp.managedOnly", "mcp.denied", "mcp.tools.allow", "mcp.tools.deny", "mcp.auth", "telemetry.enabled", "telemetry.logPrompts", "telemetry.attributes",
		"extensions.marketplaces", "extensions.plugins.enabled", "extensions.plugins.blocked",
		"permissions.sandbox", "egress.allowedDomains", "egress.default", "egress.deniedDomains", "egress.presets",
		"sandbox.writableRoots", "sandbox.protectedPaths")
	warns = append(warns, "copilot-cli: cannot self-enforce version; halod enforces")
	if c.Gateway != nil {
		warns = append(warns, "copilot-cli: gateway not rendered; BYOK is env-only (COPILOT_PROVIDER_BASE_URL, COPILOT_PROVIDER_API_KEY, COPILOT_MODEL) and managed-settings.json cannot set env; traffic is not routed through Halos")
	} else {
		warns = append(warns, name+": no gateway configured; traffic is not routed through Halos")
	}
	if p.Permissions.Mode != "" {
		warns = append(warns, "copilot-cli: permissions.mode has no managed-settings.json equivalent; not rendered")
	}
	if c.Ring != "" || c.Release != "" {
		warns = append(warns, "copilot-cli: ring/release request headers are not supported")
	}

	s := map[string]any{}
	if m := hutil.Model(p, name); m != "" {
		s["model"] = m // a default, not a lock: users may still pick another model
		warns = append(warns, "copilot-cli: models.default is only a default; users can select another model")
	}
	if p.Permissions.DisableBypass {
		s["permissions"] = map[string]any{"disableBypassPermissionsMode": "disable"}
	}
	// allowedMcpServers: omitted allows all, [] blocks all but built-ins, so
	// managedOnly with no servers renders [] (block everything).
	// https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings
	if p.MCP.ManagedOnly && len(p.MCP.Servers) == 0 {
		s["allowedMcpServers"] = []map[string]any{}
	}
	if len(p.MCP.Servers) > 0 {
		var allow []map[string]any
		for _, sv := range p.MCP.Servers {
			switch {
			case sv.URL != "":
				allow = append(allow, map[string]any{"serverUrl": sv.URL})
			case len(sv.Command) > 0:
				allow = append(allow, map[string]any{"serverCommand": sv.Command})
			default:
				return nil, nil, fmt.Errorf("copilot-cli: mcp server %q has neither url nor command", sv.Name)
			}
			// managed-settings.json only matches servers (allowedMcpServers); the
			// definitions, their tool filters and credentials live in the user's
			// ~/.copilot/mcp-config.json, which Halos does not write.
			for field, l := range map[string][]string{"allow": sv.Tools.Allow, "deny": sv.Tools.Deny} {
				if len(l) > 0 {
					warns = append(warns, fmt.Sprintf("copilot-cli: mcp server %q tools.%s is not rendered: managed settings have no per-tool MCP key (only allowedMcpServers/deniedMcpServers)", sv.Name, field))
				}
			}
			if hutil.HasAuth(sv) {
				warns = append(warns, fmt.Sprintf("copilot-cli: mcp server %q auth mode %s is not rendered: managed settings allowlist servers but do not define them, so users authorize the server in their own mcp-config.json", sv.Name, sv.Auth.Mode))
			}
		}
		s["allowedMcpServers"] = allow
	}
	sb, sw := sandbox(p, c.OS)
	warns = append(warns, sw...)
	if sb != nil {
		s["sandbox"] = sb
	}
	if len(p.MCP.Denied) > 0 {
		var denied []map[string]any
		for _, n := range p.MCP.Denied {
			if strings.Contains(n, "://") {
				denied = append(denied, map[string]any{"serverUrl": n})
				continue
			}
			denied = append(denied, map[string]any{"serverName": n})
			warns = append(warns, fmt.Sprintf("copilot-cli: mcp.denied %q is matched by name only, which a user can bypass by renaming the server; deny by URL instead", n))
		}
		s["deniedMcpServers"] = denied
	}
	// Plugin keys share Claude Code's managed-settings shapes: enabledPlugins
	// {"plugin@marketplace": bool} and strictKnownMarketplaces [{source, ...}].
	if len(p.Extensions.Marketplaces) > 0 {
		s["strictKnownMarketplaces"] = p.Extensions.Marketplaces
	}
	if pl := p.Extensions.Plugins; len(pl.Enabled)+len(pl.Blocked) > 0 {
		plugins := map[string]any{}
		for _, k := range pl.Enabled {
			plugins[k] = true
		}
		for _, k := range pl.Blocked {
			plugins[k] = false
		}
		s["enabledPlugins"] = plugins
	}
	if t := p.Telemetry; t.Enabled {
		switch t.Protocol {
		case "", "grpc":
			warns = append(warns, "copilot-cli: telemetry protocol grpc is not supported (http/json, http/protobuf only); telemetry not rendered")
		default:
			proto := "http/protobuf"
			if t.Protocol == "http/json" {
				proto = "http/json"
			}
			s["telemetry"] = map[string]any{
				"enabled": true, "endpoint": t.OTLPEndpoint, "protocol": proto,
				"captureContent": t.LogPrompts, "lockCaptureContent": !t.LogPrompts,
			}
		}
	}
	hutil.DeepMerge(s, p.Harnesses[name].Overrides)
	if len(s) == 0 {
		return nil, warns, nil
	}
	data, err := hutil.JSON(s)
	if err != nil {
		return nil, nil, fmt.Errorf("copilot-cli: encode managed-settings.json: %w", err)
	}
	// Copilot CLI on macOS/Linux rejects the file unless it is a root-owned regular file that is not group/world-writable.
	files := []harness.File{{Path: settingsPath(c.OS), Mode: 0o644, Data: data}}
	// managed-settings.json has no resource-attribute key; the CLI honors the env var (test/uat).
	if _, ok := s["telemetry"]; ok {
		if c.OS == harness.Linux {
			files = append(files, harness.File{Path: profileD, Mode: 0o644,
				Data: []byte(hutil.OTELShellWrapper("copilot", hutil.OTELResourceAttributes(name, p.Telemetry, c)))})
		} else {
			warns = append(warns, name+": no telemetry resource-attribute setting off Linux (no profile.d); CLI telemetry carries no halo.ring/halo.release")
		}
	}
	return files, warns, nil
}
