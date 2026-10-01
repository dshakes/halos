// Package codex renders OpenAI Codex CLI admin configuration.
package codex

import (
	"fmt"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
)

const name = "codex"

func init() { harness.Register(Adapter{}) }

// Adapter implements harness.Adapter for Codex CLI.
type Adapter struct{}

func (Adapter) Name() string { return name }

// Meta implements harness.Describer.
func (Adapter) Meta() harness.Meta {
	return harness.Meta{Binary: "codex", Installer: harness.InstallerNPM, NPMPackage: "@openai/codex", UAPrefixes: []string{"codex"},
		ManagedDirs: map[harness.OS][]string{harness.Darwin: {"/etc/codex"}, harness.Linux: {"/etc/codex"}, harness.Windows: {`C:\ProgramData\OpenAI\Codex`}}}
}

func (Adapter) Capabilities() []harness.Capability {
	return []harness.Capability{
		harness.CapModelLock, // partial: default only, no allowlist
		harness.CapGateway, harness.CapHeaders, harness.CapTelemetry,
		harness.CapMCPAllowlist,
		harness.CapPermissions,
	}
}

func (Adapter) InstallCommand(version string, _ harness.OS) string {
	return "npm install -g @openai/codex@" + version
}

// Paths verified in internal/harness/FACTS.md. managed_config.toml has no
// system-wide Windows location (only ~/.codex), so nothing is rendered for it there.
const (
	managedConfigPath   = "/etc/codex/managed_config.toml"
	requirementsPath    = "/etc/codex/requirements.toml"
	requirementsPathWin = `C:\ProgramData\OpenAI\Codex\requirements.toml`
)

// approval maps profile permission mode to Codex approval_policy. Codex now
// accepts only on-request | never | granular (untrusted is unsupported and
// on-failure deprecated), so every mode maps to on-request.
var approval = map[string]string{
	"default":     "on-request",
	"acceptEdits": "on-request",
	"plan":        "on-request",
	"auto":        "on-request",
}

func (Adapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	warns := hutil.WarnUnsupported(name, p,
		"models.default", "permissions.mode", "permissions.sandbox", "permissions.disableBypass",
		"mcp.servers", "telemetry.enabled", "telemetry.logPrompts")
	warns = append(warns, "codex cannot self-enforce version; halod enforces")
	if c.Experiment != "" {
		warns = append(warns, name+": no telemetry resource-attribute setting; CLI metrics are not attributed to experiment "+c.Experiment+" (the gateway still attributes its own metrics)")
	}
	win := c.OS == harness.Windows
	if win {
		warns = append(warns, "codex: Windows has no system-wide managed_config.toml (only ~/.codex); model, gateway, telemetry and MCP server definitions are not rendered, only requirements.toml")
	}

	cfg := map[string]any{}
	if p.Models.Default != "" {
		cfg["model"] = p.Models.Default
	}
	if g := c.Gateway; g != nil {
		if proto := hutil.Protocol(g, name, "openai-responses"); proto != "openai-responses" {
			return nil, nil, fmt.Errorf("codex: unsupported gateway protocol %q", proto)
		}
		hdr := map[string]any{}
		if c.Ring != "" {
			hdr["x-halo-ring"] = c.Ring
		}
		if c.Release != "" {
			hdr["x-halo-release"] = c.Release
		}
		prov := map[string]any{
			"name":     "Halos",
			"base_url": strings.TrimRight(g.BaseURL, "/") + "/v1",
			"wire_api": "responses",
			"env_key":  "HALO_GATEWAY_TOKEN",
		}
		if len(hdr) > 0 {
			prov["http_headers"] = hdr
		}
		cfg["model_provider"] = "halos"
		cfg["model_providers"] = map[string]any{"halos": prov}
	} else {
		warns = append(warns, name+": no gateway configured; traffic is not routed through Halos")
	}

	policyName := ""
	if m := p.Permissions.Mode; m != "" {
		var ok bool
		if policyName, ok = approval[m]; !ok {
			return nil, nil, fmt.Errorf("codex: unknown permissions.mode %q", m)
		}
		if m != "default" {
			warns = append(warns, fmt.Sprintf("codex: permissions.mode %q has no Codex equivalent; mapped to on-request", m))
		}
		cfg["approval_policy"] = policyName
	}
	sandbox := ""
	switch s := p.Permissions.Sandbox; s {
	case "":
	case "read-only", "workspace-write":
		sandbox = s
	case "off":
		sandbox = "workspace-write" // never emit danger-full-access
		warns = append(warns, `codex: permissions.sandbox "off" mapped to workspace-write; danger-full-access is never emitted`)
	default:
		return nil, nil, fmt.Errorf("codex: unknown permissions.sandbox %q", s)
	}
	if sandbox != "" {
		cfg["sandbox_mode"] = sandbox
	}

	if len(p.MCP.Servers) > 0 {
		servers := map[string]any{}
		for _, sv := range p.MCP.Servers {
			e := map[string]any{}
			switch {
			case sv.URL != "":
				e["url"] = sv.URL
				if len(sv.Headers) > 0 {
					e["http_headers"] = sv.Headers
				}
			case len(sv.Command) > 0:
				e["command"] = sv.Command[0]
				if len(sv.Command) > 1 {
					e["args"] = sv.Command[1:]
				}
			default:
				return nil, nil, fmt.Errorf("codex: mcp server %q has neither url nor command", sv.Name)
			}
			servers[sv.Name] = e
		}
		cfg["mcp_servers"] = servers
	}

	if t := p.Telemetry; t.Enabled {
		exp := map[string]any{"otlp-grpc": map[string]any{"endpoint": t.OTLPEndpoint}}
		if t.Protocol != "" && t.Protocol != "grpc" {
			proto := "binary" // otlp-http requires protocol: binary | json
			if strings.Contains(t.Protocol, "json") {
				proto = "json"
			}
			exp = map[string]any{"otlp-http": map[string]any{"endpoint": t.OTLPEndpoint, "protocol": proto}}
		}
		otel := map[string]any{
			"exporter":        exp,
			"log_user_prompt": t.LogPrompts,
		}
		if c.Ring != "" {
			otel["environment"] = c.Ring
		}
		cfg["otel"] = otel
	}

	hutil.DeepMerge(cfg, p.Harnesses[name].Overrides)
	data, err := toml.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("codex: encode managed_config.toml: %w", err)
	}
	var files []harness.File
	if !win {
		files = append(files, harness.File{Path: managedConfigPath, Mode: 0o644, Data: data})
	}

	req := map[string]any{}
	if policyName != "" {
		req["allowed_approval_policies"] = []string{policyName}
	}
	if sandbox != "" {
		req["allowed_sandbox_modes"] = []string{sandbox}
	} else if p.Permissions.DisableBypass {
		req["allowed_sandbox_modes"] = []string{"read-only", "workspace-write"}
	}
	if len(p.MCP.Servers) > 0 {
		// requirements.toml mcp_servers is an allowlist: name AND identity must match.
		allow := map[string]any{}
		for _, sv := range p.MCP.Servers {
			id := map[string]any{}
			if sv.URL != "" {
				id["url"] = sv.URL
			} else {
				args := []map[string]any{}
				for _, a := range sv.Command[1:] {
					args = append(args, map[string]any{"match": "exact", "value": a})
				}
				id["command"] = map[string]any{"executable": sv.Command[0], "args": args}
			}
			allow[sv.Name] = map[string]any{"identity": id}
		}
		req["mcp_servers"] = allow
	}
	if len(req) > 0 {
		rp := requirementsPath
		if win {
			rp = requirementsPathWin
		}
		rd, err := toml.Marshal(req)
		if err != nil {
			return nil, nil, fmt.Errorf("codex: encode requirements.toml: %w", err)
		}
		files = append(files, harness.File{Path: rp, Mode: 0o644, Data: rd})
	}
	return files, warns, nil
}
