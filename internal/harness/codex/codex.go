// Package codex renders OpenAI Codex CLI admin configuration.
package codex

import (
	"fmt"
	"strconv"
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
		ManagedDirs:  map[harness.OS][]string{harness.Darwin: {"/etc/codex"}, harness.Linux: {"/etc/codex"}, harness.Windows: {`C:\ProgramData\OpenAI\Codex`}},
		ManagedFiles: map[harness.OS][]string{harness.Linux: {profileD}}}
}

func (Adapter) Capabilities() []harness.Capability {
	return []harness.Capability{
		harness.CapModelLock, // partial: default only, no allowlist
		harness.CapGateway, harness.CapHeaders, harness.CapTelemetry,
		harness.CapMCPAllowlist,
		harness.CapPermissions,
		harness.CapExtensions, // partial: marketplace allowlist; plugin pins are defaults
		harness.CapSandbox,    // allowed_sandbox_modes + deny_read; writable roots are defaults
		harness.CapEgress,     // requirements.toml [experimental_network]
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
	profileD            = "/etc/profile.d/halos-codex.sh"
)

// workspaceWrite renders [sandbox_workspace_write] in managed_config.toml: a
// default the user's config.toml can change, which requirements.toml then
// limits (allowed_sandbox_modes, [experimental_network], deny_read).
// writable_roots are absolute paths (AbsolutePathBuf in the schema).
// network_access stays false under a default-deny egress policy: the release
// check refuses true, and commands then reach only what the managed proxy allows
// once a user turns it on.
func workspaceWrite(p *policy.Profile, mode string) (map[string]any, []string) {
	var warns []string
	out := map[string]any{}
	abs, rest := hutil.SplitPaths(p.Sandbox.WritableRoots, false)
	if len(rest) > 0 {
		warns = append(warns, fmt.Sprintf("codex: sandbox.writableRoots %v are not absolute (writable_roots takes absolute paths only); not rendered", rest))
	}
	if len(abs) > 0 && mode == "workspace-write" {
		out["writable_roots"] = abs
	}
	if p.Egress.Restricted() {
		er := p.Egress.Rules()
		out["network_access"] = er.Default == policy.EgressAllow
		if er.Default == policy.EgressDeny && len(er.Allow) > 0 {
			warns = append(warns, "codex: egress default deny renders network_access = false, so sandboxed commands reach the allowlisted hosts only after the user sets network_access = true; [experimental_network] in requirements.toml then limits them")
		}
	}
	if len(out) == 0 || mode != "workspace-write" {
		return nil, warns
	}
	return out, warns
}

// requirementsSandbox adds the enforced sandbox and egress requirements to req:
// [permissions.filesystem] deny_read (absolute, ~ or /**/ globs; "./" is
// refused) and [experimental_network] (domain -> allow|deny, deny wins,
// *.x = subdomains only, managed_allowed_domains_only for default deny).
// https://learn.chatgpt.com/docs/enterprise/managed-configuration
func requirementsSandbox(p *policy.Profile, req map[string]any, os harness.OS) []string {
	var warns []string
	if pp := p.Sandbox.ProtectedPaths; len(pp) > 0 {
		var deny []string
		for _, x := range pp {
			if !strings.HasPrefix(x, "/") && !strings.HasPrefix(x, "~/") {
				x = "/**/" + strings.TrimPrefix(strings.TrimPrefix(x, "./"), "**/")
			}
			deny = append(deny, x)
		}
		req["permissions"] = map[string]any{"filesystem": map[string]any{"deny_read": deny}}
		warns = append(warns, "codex: sandbox.protectedPaths are rendered as deny_read (reads); Codex has no managed deny-write list, so writes are held only by the sandbox mode")
		if os == harness.Windows {
			warns = append(warns, "codex: on native Windows deny_read applies to direct file tools only, not shell subprocess reads")
		}
	}
	if p.Egress.Restricted() {
		er := p.Egress.Rules()
		domains := map[string]any{}
		for _, d := range er.Allow {
			domains[d] = "allow"
		}
		for _, d := range er.Deny {
			domains[d] = "deny"
		}
		net := map[string]any{"enabled": true, "managed_allowed_domains_only": er.Default == policy.EgressDeny}
		if len(domains) > 0 {
			net["domains"] = domains
		}
		req["experimental_network"] = net
		warns = append(warns, "codex: egress is rendered as requirements.toml [experimental_network], which OpenAI documents as experimental; the minimum codex version honoring it is not documented (UNVERIFIED), and it does not filter web search, MCP servers or Codex's own service requests")
	}
	return warns
}

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
		"egress.allowedDomains", "egress.default", "egress.deniedDomains", "egress.presets",
		"sandbox.writableRoots", "sandbox.protectedPaths",
		"mcp.servers", "mcp.tools.allow", "mcp.tools.deny", "mcp.auth", "telemetry.enabled", "telemetry.logPrompts", "telemetry.attributes",
		"extensions.marketplaces", "extensions.plugins.enabled", "extensions.plugins.blocked", "login")
	warns = append(warns, "codex cannot self-enforce version; halod enforces")
	win := c.OS == harness.Windows
	if win {
		warns = append(warns, "codex: Windows has no system-wide managed_config.toml (only ~/.codex); model, gateway, telemetry and MCP server definitions (with their tool lists) are not rendered, only requirements.toml")
	}

	cfg := map[string]any{}
	if m := hutil.ClientModel(c, hutil.Model(p, name)); m != "" {
		cfg["model"] = m
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
	if sandbox == "" && (p.Egress.Restricted() || len(p.Sandbox.ProtectedPaths)+len(p.Sandbox.WritableRoots) > 0) {
		sandbox = "workspace-write" // egress and path rules hold only inside a sandbox
	}
	if sandbox != "" {
		cfg["sandbox_mode"] = sandbox
	}
	sw, ww := workspaceWrite(p, sandbox)
	warns = append(warns, ww...)
	if sw != nil {
		cfg["sandbox_workspace_write"] = sw
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
			// enabled_tools is the allowlist, disabled_tools applied after it.
			// https://learn.chatgpt.com/docs/config-file/config-reference
			if len(sv.Tools.Allow) > 0 {
				e["enabled_tools"] = sv.Tools.Allow
			}
			if len(sv.Tools.Deny) > 0 {
				e["disabled_tools"] = sv.Tools.Deny
			}
			if hutil.HasAuth(sv) {
				// The schema (config.schema.json) has http_headers_helper, oauth.client_id,
				// scopes and auth = "ema_auth", but mcp_servers entries reject unknown
				// keys, so a pin that predates one would refuse to start.
				warns = append(warns, fmt.Sprintf("codex: mcp server %q auth mode %s is not rendered: codex rejects unknown mcp_servers keys and support for http_headers_helper, oauth and auth = \"ema_auth\" at the pinned version is unverified, so the server is rendered without auth (users authorize OAuth servers with codex mcp login)", sv.Name, sv.Auth.Mode))
			}
			servers[sv.Name] = e
		}
		cfg["mcp_servers"] = servers
	}

	if t := p.Telemetry; t.Enabled {
		// headers is required by codex <= 0.58 ("missing field `headers`" and
		// codex refuses to start; seen in test/uat); an empty table is valid everywhere.
		exp := map[string]any{"otlp-grpc": map[string]any{"endpoint": t.OTLPEndpoint, "headers": map[string]any{}}}
		if t.Protocol != "" && t.Protocol != "grpc" {
			proto := "binary" // otlp-http requires protocol: binary | json
			if strings.Contains(t.Protocol, "json") {
				proto = "json"
			}
			// Codex POSTs OTLP/HTTP logs to the endpoint verbatim (0.58.0 hit the
			// bare collector URL and got 404; test/uat), so name the signal path.
			ep := strings.TrimRight(t.OTLPEndpoint, "/")
			if !strings.HasSuffix(ep, "/v1/logs") {
				ep += "/v1/logs"
			}
			exp = map[string]any{"otlp-http": map[string]any{"endpoint": ep, "protocol": proto, "headers": map[string]any{}}}
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

	// plugins.<plugin@marketplace>.enabled is a config default, not a lock: Codex
	// reads it from the merged config, so a trusted project can override it, and
	// requirements.toml has no per-plugin pin (only features.plugins, all or none).
	// https://learn.chatgpt.com/docs/config-file/config-reference
	if pl := p.Extensions.Plugins; len(pl.Enabled)+len(pl.Blocked) > 0 {
		plugins := map[string]any{}
		for _, k := range pl.Enabled {
			plugins[k] = map[string]any{"enabled": true}
		}
		for _, k := range pl.Blocked {
			plugins[k] = map[string]any{"enabled": false}
		}
		cfg["plugins"] = plugins
		warns = append(warns, "codex: extensions.plugins.enabled/blocked are rendered as config.toml defaults (plugins.<name>.enabled), not enforced: Codex has no per-plugin requirement, and a trusted project can override them")
		if win {
			warns = append(warns, "codex: extensions.plugins.enabled/blocked are not rendered on Windows (no system-wide managed_config.toml)")
		}
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
	// codex config has no resource-attribute key (only otel.environment).
	if p.Telemetry.Enabled {
		if c.OS == harness.Linux {
			files = append(files, harness.File{Path: profileD, Mode: 0o644,
				Data: []byte(hutil.OTELShellWrapper("codex", hutil.OTELResourceAttributes(name, p.Telemetry, c)))})
		} else {
			warns = append(warns, name+": no telemetry resource-attribute setting off Linux (no profile.d); CLI telemetry carries no halo.ring/halo.release")
		}
	}

	req := map[string]any{}
	if policyName != "" {
		req["allowed_approval_policies"] = []string{policyName}
	}
	if sandbox != "" {
		// codex refuses to start unless the list includes read-only ("must
		// include 'read-only' to allow any SandboxPolicy"; 0.77.0 in test/uat).
		// read-only is stricter than any mode we render, so allowing it is safe.
		modes := []string{"read-only"}
		if sandbox != "read-only" {
			modes = append(modes, sandbox)
		}
		req["allowed_sandbox_modes"] = modes
	} else if p.Permissions.DisableBypass {
		req["allowed_sandbox_modes"] = []string{"read-only", "workspace-write"}
	}
	rw := requirementsSandbox(p, req, c.OS)
	warns = append(warns, rw...)
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
	// [marketplaces] restricts which plugin sources users can add and use; git
	// rules match the normalized repository URL plus an optional exact ref.
	// https://learn.chatgpt.com/docs/enterprise/managed-configuration
	if len(p.Extensions.Marketplaces) > 0 {
		sources := map[string]any{}
		for i, m := range p.Extensions.Marketplaces {
			rule := map[string]any{}
			switch m.Source {
			case policy.MarketplaceGitHub:
				rule["source"], rule["url"] = "git", "https://github.com/"+m.Repo+".git"
			case policy.MarketplaceGit:
				rule["source"], rule["url"] = "git", m.URL
			case policy.MarketplaceHostPattern:
				rule["source"], rule["host_pattern"] = "host_pattern", m.HostPattern
			default:
				warns = append(warns, fmt.Sprintf("codex: marketplace source %q has no requirements.toml equivalent (git, host_pattern and local only); not rendered", m.Source))
				continue
			}
			if m.Ref != "" {
				rule["ref"] = m.Ref
			}
			sources["source_"+strconv.Itoa(i+1)] = rule
		}
		// Every rule skipped would leave restrict_to_allowed_sources=true with no
		// sources, i.e. block all marketplaces; refuse to widen or silently lock out.
		if len(sources) > 0 {
			req["marketplaces"] = map[string]any{"restrict_to_allowed_sources": true, "allowed_sources": sources}
		} else {
			warns = append(warns, "codex: no extensions.marketplaces entry is expressible in requirements.toml; marketplace restriction not rendered")
		}
	}
	// allowed_login_methods is read from the local requirements file only.
	switch p.Login {
	case policy.LoginSubscription:
		req["allowed_login_methods"] = []string{"chatgpt"}
	case policy.LoginAPI:
		req["allowed_login_methods"] = []string{"api"}
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
		switch v := p.Harnesses[name].Version; {
		case v != "" && hutil.VersionBefore(v, 0, 77):
			warns = append(warns, fmt.Sprintf("codex: %s does not enforce requirements.toml (allowed_sandbox_modes needs codex >= 0.77.0; 0.58.0 reads no requirements.toml at all), so sandbox, approval and MCP limits are defaults the user can override", v))
		case v != "" && policyName != "never" && hutil.VersionBefore(v, 0, 99):
			// codex exec forces approval_policy=never; before 0.99.0 that is a hard
			// error under requirements, later it falls back to the allowed value (test/uat).
			warns = append(warns, fmt.Sprintf("codex: %s refuses to run `codex exec` (headless, CI, evals) when allowed_approval_policies excludes never (\"Never is not in the allowed set\"); use codex >= 0.99.0", v))
		}
	}
	return files, warns, nil
}
