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
		harness.CapSandbox,    // partial: tools.sandbox on macOS only, a default the user can override
	}
}

func (Adapter) InstallCommand(version string, _ harness.OS) string {
	return "npm install -g @google/gemini-cli@" + version
}

// sandboxOn: the profile asks for a sandbox. Egress and path rules do not turn
// it on: Gemini CLI's sandbox enforces neither (they warn as unsupported).
func sandboxOn(p *policy.Profile) bool {
	m := p.Permissions.Sandbox
	return m == "workspace-write" || m == "read-only"
}

// sandboxWarnings: what Gemini CLI's sandbox cannot hold (ADR-0032). The
// system settings file sets tools.sandbox, but the --sandbox flag and the
// GEMINI_SANDBOX environment variable take precedence; on Linux and Windows
// the sandbox needs Docker/Podman (or the experimental Windows-native one),
// so it is rendered on macOS only, where Seatbelt is built in. There is no
// domain allow/deny list (Seatbelt's *-proxied profiles route through a
// user-supplied proxy; tools.sandboxNetworkAccess is all-or-nothing with an
// undocumented scope) and no managed path list, so egress.* and sandbox.*
// warn as unsupported.
// https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/sandbox.md
func sandboxWarnings(p *policy.Profile, os harness.OS) []string {
	if !sandboxOn(p) {
		return nil
	}
	w := []string{"gemini: the sandbox (tools.sandbox) is a default, not a lock: the --sandbox flag and GEMINI_SANDBOX take precedence over the system settings file"}
	if os != harness.Darwin {
		w = append(w, "gemini: the sandbox is not rendered on "+string(os)+": it needs Docker or Podman there; set GEMINI_SANDBOX=docker|podman on the device")
	}
	if p.Permissions.Sandbox == "read-only" {
		w = append(w, `gemini: permissions.sandbox "read-only" has no Gemini CLI equivalent; the Seatbelt default confines writes to the project (workspace-write)`)
	}
	return w
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
	handled := []string{"models.default", "permissions.disableBypass", "mcp.servers", "mcp.managedOnly", "mcp.denied", "telemetry.enabled", "telemetry.logPrompts", "telemetry.attributes",
		"extensions.skills.deny", "extensions.subagents.deny", "login"}
	if sandboxOn(p) {
		handled = append(handled, "permissions.sandbox") // "off" (Gemini's default) still warns: nothing is rendered for it
	}
	warns := hutil.WarnUnsupported(name, p, handled...)
	warns = append(warns, sandboxWarnings(p, c.OS)...)
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
	if sandboxOn(p) && c.OS == harness.Darwin {
		// macOS Seatbelt (sandbox-exec) ships with the OS; its default profile
		// confines writes to the project directory.
		s["tools"] = map[string]any{"sandbox": true}
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
