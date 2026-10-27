// Package gemini renders Gemini CLI system settings.
package gemini

import (
	"fmt"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
)

const name = "gemini-cli"

func init() { harness.Register(Adapter{}) }

// Adapter implements harness.Adapter for Gemini CLI.
type Adapter struct{}

func (Adapter) Name() string { return name }

// Meta implements harness.Describer.
func (Adapter) Meta() harness.Meta {
	return harness.Meta{Binary: "gemini", Installer: harness.InstallerNPM, NPMPackage: "@google/gemini-cli", UAPrefixes: []string{"geminicli"},
		ManagedDirs:  map[harness.OS][]string{harness.Darwin: {"/Library/Application Support/GeminiCli"}, harness.Linux: {"/etc/gemini-cli"}, harness.Windows: {`C:\ProgramData\gemini-cli`}},
		ManagedFiles: map[harness.OS][]string{harness.Darwin: {"/etc/profile.d/halos-*.sh"}, harness.Linux: {"/etc/profile.d/halos-*.sh"}}}
}

func (Adapter) Capabilities() []harness.Capability {
	return []harness.Capability{harness.CapModelLock, harness.CapMCPAllowlist, harness.CapTelemetry, harness.CapGateway,
		harness.CapExtensions, // partial: skills and subagent deny; no plugin marketplaces
	}
}

func (Adapter) InstallCommand(version string, _ harness.OS) string {
	return "npm install -g @google/gemini-cli@" + version
}

// Paths and keys verified in internal/harness/FACTS.md.
func settingsPath(os harness.OS) string {
	switch os {
	case harness.Darwin:
		return "/Library/Application Support/GeminiCli/settings.json"
	case harness.Windows:
		return `C:\ProgramData\gemini-cli\settings.json`
	default:
		return "/etc/gemini-cli/settings.json"
	}
}

func (Adapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	warns := hutil.WarnUnsupported(name, p,
		"models.default", "permissions.disableBypass", "mcp.servers", "mcp.managedOnly", "mcp.denied", "mcp.tools.allow", "mcp.tools.deny", "mcp.auth", "telemetry.enabled", "telemetry.logPrompts", "telemetry.attributes",
		"extensions.skills.deny", "extensions.subagents.deny", "login")
	warns = append(warns, "gemini: cannot self-enforce version; halod enforces")
	if c.Ring != "" || c.Release != "" {
		warns = append(warns, "gemini: ring/release request headers are not supported")
	}

	s := map[string]any{}
	if m := hutil.ClientModel(c, hutil.Model(p, name)); m != "" {
		s["model"] = map[string]any{"name": m}
	}
	if p.Permissions.DisableBypass {
		// security.disableYoloMode refuses --yolo / YOLO approval mode (in every
		// version since at least 0.12.0). admin.secureModeEnabled is not used: on
		// 0.34.0 the admin block comes only from Google's remote admin controls, so
		// the system settings file's copy is ignored (verified in test/uat).
		s["security"] = map[string]any{"disableYoloMode": true}
	}
	if len(p.MCP.Servers) > 0 {
		servers := map[string]any{}
		var names []string
		for _, sv := range p.MCP.Servers {
			e := map[string]any{}
			switch {
			case sv.URL != "":
				e["httpUrl"] = sv.URL
				if len(sv.Headers) > 0 {
					e["headers"] = sv.Headers
				}
			case len(sv.Command) > 0:
				e["command"] = sv.Command[0]
				if len(sv.Command) > 1 {
					e["args"] = sv.Command[1:]
				}
			default:
				return nil, nil, fmt.Errorf("gemini: mcp server %q has neither url nor command", sv.Name)
			}
			// includeTools / excludeTools: exclude wins; across settings files
			// inclusions intersect and exclusions union, so a user file cannot widen them.
			// https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md
			if len(sv.Tools.Allow) > 0 {
				e["includeTools"] = sv.Tools.Allow
			}
			if len(sv.Tools.Deny) > 0 {
				e["excludeTools"] = sv.Tools.Deny
			}
			warns = append(warns, geminiAuth(e, sv)...)
			servers[sv.Name] = e
			names = append(names, sv.Name)
		}
		s["mcpServers"] = servers
		s["mcp"] = map[string]any{"allowed": names}
	} else if p.MCP.ManagedOnly {
		warns = append(warns, "gemini: mcp.managedOnly without mcp.servers is not rendered: mcp.allowed has no documented empty-list meaning, and the admin allowlist (admin.mcp.config) is honored only from Google's remote admin controls")
	}
	// mcp.allowed / mcp.excluded are name lists (the server key in mcpServers),
	// so a user can rename a server to slip past either.
	// https://geminicli.com/docs/reference/configuration/
	if len(p.MCP.Servers) > 0 || len(p.MCP.Denied) > 0 {
		warns = append(warns, "gemini: mcp.allowed and mcp.excluded match server names only, which a user can bypass by renaming a server")
	}
	if len(p.MCP.Denied) > 0 {
		var excluded []string
		for _, n := range p.MCP.Denied {
			if strings.Contains(n, "://") {
				warns = append(warns, fmt.Sprintf("gemini: mcp.denied %q is a URL; mcp.excluded matches names only, so it is not rendered", n))
				continue
			}
			excluded = append(excluded, n)
		}
		if len(excluded) > 0 {
			hutil.DeepMerge(s, map[string]any{"mcp": map[string]any{"excluded": excluded}})
		}
	}
	// Skills and subagents: skills.disabled and agents.overrides.<name>.enabled
	// (https://geminicli.com/docs/reference/configuration/,
	// https://geminicli.com/docs/core/subagents/). Gemini has no marketplace,
	// output-style or status-line command settings, and no allowlist for either.
	if len(p.Extensions.Skills.Deny) > 0 {
		s["skills"] = map[string]any{"disabled": p.Extensions.Skills.Deny}
	}
	if len(p.Extensions.Subagents.Deny) > 0 {
		overrides := map[string]any{}
		for _, n := range p.Extensions.Subagents.Deny {
			overrides[n] = map[string]any{"enabled": false}
		}
		s["agents"] = map[string]any{"overrides": overrides}
	}
	if t := p.Telemetry; t.Enabled {
		proto := "grpc"
		if t.Protocol != "" && t.Protocol != "grpc" {
			proto = "http"
		}
		if v := p.Harnesses[name].Version; proto == "http" && hutil.VersionBefore(v, 0, 34) {
			warns = append(warns, fmt.Sprintf("gemini: %s posts every OTLP/HTTP signal to otlpEndpoint verbatim (no /v1/logs|metrics|traces; fixed in gemini-cli 0.34.0), so a standard collector rejects it; use grpc or gemini-cli >= 0.34.0", v))
		}
		s["telemetry"] = map[string]any{
			"enabled": true, "target": "local", "otlpEndpoint": t.OTLPEndpoint,
			"otlpProtocol": proto, "logPrompts": t.LogPrompts,
		}
	}
	if p.Login == policy.LoginSubscription && c.Gateway == nil {
		// security.auth.enforcedType refuses any other auth type at startup
		// (verified in test/uat); oauth-personal is the Google login.
		hutil.DeepMerge(s, map[string]any{"security": map[string]any{"auth": map[string]any{"enforcedType": "oauth-personal"}}})
	}
	if p.Login == policy.LoginSubscription && c.Gateway != nil {
		warns = append(warns, "gemini: login subscription conflicts with the gateway, which needs gemini-api-key auth; enforcing gemini-api-key")
	}
	if p.Login == policy.LoginAPI && c.Gateway == nil {
		hutil.DeepMerge(s, map[string]any{"security": map[string]any{"auth": map[string]any{"enforcedType": "gemini-api-key"}}})
	}
	if c.Gateway != nil {
		// GOOGLE_GEMINI_BASE_URL only applies to gemini-api-key auth; enforcing
		// that type stops a Google-login session from bypassing the gateway
		// (gemini refuses to start with another type; verified on 0.12.0 in test/uat).
		hutil.DeepMerge(s, map[string]any{"security": map[string]any{"auth": map[string]any{"enforcedType": "gemini-api-key"}}})
	}
	hutil.DeepMerge(s, p.Harnesses[name].Overrides)
	data, err := hutil.JSON(s)
	if err != nil {
		return nil, nil, err
	}
	files := []harness.File{{Path: settingsPath(c.OS), Mode: 0o644, Data: data}}

	script := ""
	if g := c.Gateway; g != nil {
		if proto := hutil.Protocol(g, name, "gemini"); proto != "gemini" {
			return nil, nil, fmt.Errorf("gemini: unsupported gateway protocol %q", proto)
		}
		switch c.OS {
		case harness.Linux:
			script += "export GOOGLE_GEMINI_BASE_URL=" + hutil.ShQuote(g.BaseURL) + "\n"
			if h := g.Auth.HelperCommand; h != "" {
				// gemini-cli reads its credential from GEMINI_API_KEY and sends it as
				// x-goog-api-key, which halo-proxy verifies like a bearer token. The
				// token is minted at shell start (never written to disk) and is
				// short-lived: open a new shell when it expires.
				script += "export GEMINI_API_KEY=\"$(sh -c " + hutil.ShQuote(h) + " 2>/dev/null)\"\n"
			} else {
				warns = append(warns, "gemini: gateway.auth.helperCommand is unset, so GEMINI_API_KEY is not rendered; set it to a Halos token yourself")
			}
			warns = append(warns, "gemini: settings cannot set env; gateway is applied via /etc/profile.d (login shells only); GOOGLE_GEMINI_BASE_URL is only honored with gemini-api-key auth and must be HTTPS or localhost")
		default:
			warns = append(warns, "gemini: settings cannot set env and no profile.d equivalent is rendered for "+string(c.OS)+"; set GOOGLE_GEMINI_BASE_URL="+g.BaseURL+" yourself")
		}
	} else {
		warns = append(warns, name+": no gateway configured; traffic is not routed through Halos")
	}
	if p.Telemetry.Enabled {
		if c.OS == harness.Linux {
			script += hutil.OTELShellWrapper("gemini", hutil.OTELResourceAttributes(name, p.Telemetry, c))
		} else {
			warns = append(warns, name+": no telemetry resource-attribute setting off Linux (no profile.d); CLI telemetry carries no halo.ring/halo.release")
		}
	}
	if script != "" {
		files = append(files, harness.File{Path: "/etc/profile.d/halos-gemini.sh", Mode: 0o644, Data: []byte(script)})
	}
	return files, warns, nil
}

// geminiAuth renders a remote server's authorization into its mcpServers
// entry e: the oauth block (enabled, clientId, issuer, scopes) for mode oauth.
// https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md
func geminiAuth(e map[string]any, sv policy.MCPServer) []string {
	a := sv.Auth
	switch a.Mode {
	case policy.MCPAuthOAuth:
		o := map[string]any{"enabled": true}
		if a.ClientID != "" {
			o["clientId"] = a.ClientID
		}
		if a.Issuer != "" {
			o["issuer"] = a.Issuer
		}
		if len(a.Scopes) > 0 {
			o["scopes"] = a.Scopes
		}
		e["oauth"] = o
		if a.ClientIDMetadataURL != "" {
			return []string{fmt.Sprintf("gemini: mcp server %q auth.clientIDMetadataURL is not rendered: Gemini CLI documents no Client ID Metadata Document setting (clientId or dynamic registration only)", sv.Name)}
		}
	case policy.MCPAuthEnterprise:
		return []string{fmt.Sprintf("gemini: mcp server %q auth mode enterprise is not rendered: Gemini CLI documents no Enterprise-Managed Authorization (ID-JAG) client; users authorize the server with /mcp auth", sv.Name)}
	case policy.MCPAuthHalos:
		return []string{fmt.Sprintf("gemini: mcp server %q auth mode halos is not rendered: Gemini CLI has no per-connection header helper (headers are static), so a Halos token cannot be minted per session; run `halo mcp token` and set the header yourself, or use mode oauth", sv.Name)}
	}
	return nil
}
