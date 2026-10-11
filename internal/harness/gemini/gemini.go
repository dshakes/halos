// Package gemini renders Gemini CLI system settings.
package gemini

import (
	"fmt"

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
	return []harness.Capability{harness.CapModelLock, harness.CapMCPAllowlist, harness.CapTelemetry, harness.CapGateway}
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
		"models.default", "permissions.disableBypass", "mcp.servers", "telemetry.enabled", "telemetry.logPrompts", "telemetry.attributes")
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
			servers[sv.Name] = e
			names = append(names, sv.Name)
		}
		s["mcpServers"] = servers
		s["mcp"] = map[string]any{"allowed": names}
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
