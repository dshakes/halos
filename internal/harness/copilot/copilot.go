// Package copilot renders GitHub Copilot CLI file-based enterprise managed
// settings (managed-settings.json). Facts and sources: internal/harness/FACTS.md.
package copilot

import (
	"fmt"

	"github.com/halos-dev/halos/internal/harness"
	"github.com/halos-dev/halos/internal/harness/hutil"
	"github.com/halos-dev/halos/internal/policy"
)

const name = "copilot-cli"

func init() { harness.Register(Adapter{}) }

// Adapter implements harness.Adapter for GitHub Copilot CLI.
type Adapter struct{}

func (Adapter) Name() string { return name }

// Meta implements harness.Describer.
func (Adapter) Meta() harness.Meta {
	return harness.Meta{Binary: "copilot", Installer: harness.InstallerNPM, NPMPackage: "@github/copilot",
		ManagedDirs: map[harness.OS][]string{harness.Darwin: {"/Library/Application Support/GitHubCopilot"}, harness.Linux: {"/etc/github-copilot"}, harness.Windows: {`C:\Program Files\GitHubCopilot`}}}
}

func (Adapter) Capabilities() []harness.Capability {
	return []harness.Capability{harness.CapTelemetry, harness.CapMCPAllowlist, harness.CapPermissions}
}

func (Adapter) InstallCommand(version string, _ harness.OS) string {
	return "npm install -g @github/copilot@" + version
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
		"models.default", "permissions.disableBypass", "mcp.servers", "telemetry.enabled", "telemetry.logPrompts")
	warns = append(warns, "copilot-cli: cannot self-enforce version; halod enforces")
	if c.Gateway != nil {
		warns = append(warns, "copilot-cli: gateway not rendered; BYOK is env-only (COPILOT_PROVIDER_BASE_URL, COPILOT_PROVIDER_API_KEY, COPILOT_MODEL) and managed-settings.json cannot set env; traffic is not routed through Halos")
	} else {
		warns = append(warns, name+": no gateway configured; traffic is not routed through Halos")
	}
	if p.Permissions.Mode != "" || p.Permissions.Sandbox != "" {
		warns = append(warns, "copilot-cli: permissions.mode and permissions.sandbox have no managed-settings.json equivalent; not rendered")
	}
	if c.Ring != "" || c.Release != "" {
		warns = append(warns, "copilot-cli: ring/release request headers are not supported")
	}

	if c.Experiment != "" {
		warns = append(warns, name+": no telemetry resource-attribute setting; CLI metrics are not attributed to experiment "+c.Experiment+" (the gateway still attributes its own metrics)")
	}

	s := map[string]any{}
	if p.Models.Default != "" {
		s["model"] = p.Models.Default // a default, not a lock: users may still pick another model
		warns = append(warns, "copilot-cli: models.default is only a default; users can select another model")
	}
	if p.Permissions.DisableBypass {
		s["permissions"] = map[string]any{"disableBypassPermissionsMode": "disable"}
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
		}
		s["allowedMcpServers"] = allow
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
	return []harness.File{{Path: settingsPath(c.OS), Mode: 0o644, Data: data}}, warns, nil
}
