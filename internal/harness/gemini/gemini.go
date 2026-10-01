// Package gemini renders Gemini CLI system settings.
package gemini

import (
	"fmt"

	"github.com/halos-dev/halos/internal/harness"
	"github.com/halos-dev/halos/internal/harness/hutil"
	"github.com/halos-dev/halos/internal/policy"
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
		"models.default", "permissions.disableBypass", "mcp.servers", "telemetry.enabled", "telemetry.logPrompts")
	warns = append(warns, "gemini: cannot self-enforce version; halod enforces")
	if c.Ring != "" || c.Release != "" {
		warns = append(warns, "gemini: ring/release request headers are not supported")
	}

	if c.Experiment != "" {
		warns = append(warns, name+": no telemetry resource-attribute setting; CLI metrics are not attributed to experiment "+c.Experiment+" (the gateway still attributes its own metrics)")
	}

	s := map[string]any{}
	if p.Models.Default != "" {
		s["model"] = map[string]any{"name": p.Models.Default}
	}
	if p.Permissions.DisableBypass {
		s["admin"] = map[string]any{"secureModeEnabled": true} // disallows YOLO mode and "Always allow"
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
		s["telemetry"] = map[string]any{
			"enabled": true, "target": "local", "otlpEndpoint": t.OTLPEndpoint,
			"otlpProtocol": proto, "logPrompts": t.LogPrompts,
		}
	}
	hutil.DeepMerge(s, p.Harnesses[name].Overrides)
	data, err := hutil.JSON(s)
	if err != nil {
		return nil, nil, err
	}
	files := []harness.File{{Path: settingsPath(c.OS), Mode: 0o644, Data: data}}

	if g := c.Gateway; g != nil {
		if proto := hutil.Protocol(g, name, "gemini"); proto != "gemini" {
			return nil, nil, fmt.Errorf("gemini: unsupported gateway protocol %q", proto)
		}
		switch c.OS {
		case harness.Linux:
			files = append(files, harness.File{
				Path: "/etc/profile.d/halos-gemini.sh", Mode: 0o644,
				Data: []byte("export GOOGLE_GEMINI_BASE_URL=" + shQuote(g.BaseURL) + "\n"),
			})
			warns = append(warns, "gemini: settings cannot set env; gateway is applied via /etc/profile.d (login shells only); GOOGLE_GEMINI_BASE_URL is only honored with gemini-api-key auth and must be HTTPS or localhost")
		default:
			warns = append(warns, "gemini: settings cannot set env and no profile.d equivalent is rendered for "+string(c.OS)+"; set GOOGLE_GEMINI_BASE_URL="+g.BaseURL+" yourself")
		}
	} else {
		warns = append(warns, name+": no gateway configured; traffic is not routed through Halos")
	}
	return files, warns, nil
}

func shQuote(s string) string {
	out := "'"
	for _, r := range s {
		if r == '\'' {
			out += `'\''`
			continue
		}
		out += string(r)
	}
	return out + "'"
}
