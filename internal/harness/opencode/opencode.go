// Package opencode renders OpenCode (sst/opencode, npm "opencode-ai") managed
// configuration: an opencode.json in the system managed-config directory, which
// OpenCode loads at the highest precedence. Facts and sources:
// internal/harness/FACTS.md.
package opencode

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
)

const (
	name = "opencode"
	// providerID is the provider the adapter defines for the Halos gateway;
	// model ids are "<providerID>/<alias>".
	providerID = "halos"
	// tokenEnv is the variable the rendered provider reads its credential from
	// ({env:...} substitution), like Codex's env_key.
	tokenEnv = "HALO_GATEWAY_TOKEN"
	// instructionsFile sits next to opencode.json in the managed directory.
	instructionsFile = "halos-instructions.md"
)

func init() { harness.Register(Adapter{}) }

// Adapter implements harness.Adapter for OpenCode.
type Adapter struct{}

func (Adapter) Name() string { return name }

// Meta implements harness.Describer.
func (Adapter) Meta() harness.Meta {
	return harness.Meta{Binary: "opencode", Installer: harness.InstallerNPM, NPMPackage: "opencode-ai", UAPrefixes: []string{"opencode/"},
		ManagedDirs: map[harness.OS][]string{harness.Darwin: {"/Library/Application Support/opencode"}, harness.Linux: {"/etc/opencode"}, harness.Windows: {`C:\ProgramData\opencode`}}}
}

func (Adapter) Capabilities() []harness.Capability {
	return []harness.Capability{
		harness.CapModelLock, // provider + model allowlist via enabled_providers and provider.<id>.models
		harness.CapPermissions,
		harness.CapGateway, harness.CapHeaders,
		harness.CapInstructions,
	}
}

func (Adapter) InstallCommand(version string, _ harness.OS) string {
	return "npm install -g opencode-ai@" + version
}

// managedDir is OpenCode's system config directory (FACTS.md).
func managedDir(os harness.OS) string {
	switch os {
	case harness.Darwin:
		return "/Library/Application Support/opencode"
	case harness.Windows:
		return `C:\ProgramData\opencode`
	default:
		return "/etc/opencode"
	}
}

// providerPkg maps a gateway protocol to the AI SDK package OpenCode loads for
// it. Both append their own path to baseURL: /v1/messages and /v1/responses
// (observed against a recording server in test/uat notes, FACTS.md).
var providerPkg = map[string]string{
	"anthropic-messages": "@ai-sdk/anthropic",
	"openai-responses":   "@ai-sdk/openai",
}

// permTools maps Claude-style permission rule tools to OpenCode permission keys.
var permTools = map[string]string{
	"Bash": "bash", "Read": "read", "Edit": "edit", "Write": "edit", "MultiEdit": "edit", "NotebookEdit": "edit",
	"Glob": "glob", "Grep": "grep", "Task": "task",
}

// ordered is a JSON object whose keys keep insertion order. OpenCode evaluates
// permission rules in key order with the last match winning, so a sorted-key
// encoding would change what a rule set means.
type ordered struct{ kv [][2]string }

func (o *ordered) set(pattern, action string) {
	o.kv = slices.DeleteFunc(o.kv, func(e [2]string) bool { return e[0] == pattern })
	o.kv = append(o.kv, [2]string{pattern, action})
}

func (o ordered) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range o.kv {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := hutil.JSON(e[0])
		if err != nil {
			return nil, err
		}
		v, err := hutil.JSON(e[1])
		if err != nil {
			return nil, err
		}
		b.Write(bytes.TrimSpace(k))
		b.WriteByte(':')
		b.Write(bytes.TrimSpace(v))
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// rule splits "Tool(arg)" (or bare "Tool") into its parts.
func rule(r string) (tool, arg string, ok bool) {
	tool, rest, found := strings.Cut(strings.TrimSpace(r), "(")
	if !found {
		return tool, "", tool != ""
	}
	arg, closed := strings.CutSuffix(rest, ")")
	return tool, arg, closed && tool != ""
}

// patterns turns one rule argument into OpenCode patterns for key. A Claude
// `cmd:*` prefix matches the bare command and any arguments; OpenCode needs
// both "cmd" and "cmd *" for that.
func patterns(key, arg string) []string {
	switch {
	case arg == "":
		return []string{"*"}
	case key == "bash":
		if cmd, ok := strings.CutSuffix(arg, ":*"); ok {
			return []string{cmd, cmd + " *"}
		}
		return []string{arg}
	case key == "read" || key == "edit":
		// OpenCode matches the path relative to the worktree, where "*" spans
		// "/" but "**/x" still needs a "/": add the root-level form too.
		p := strings.TrimPrefix(arg, "./")
		if rest, ok := strings.CutPrefix(p, "**/"); ok {
			return []string{p, rest}
		}
		return []string{p}
	}
	return []string{arg}
}

// permission builds the permission object and the warnings for rules it cannot
// express. bash and edit start from "ask" once they have any rule (Claude
// Code's behaviour for an unlisted command or edit; OpenCode's own default is
// allow). Within a tool the order is allow, ask, deny so deny wins.
func permission(p policy.Permissions) (map[string]any, []string) {
	var warns []string
	tools := map[string]*ordered{}
	add := func(list []string, action string) {
		for _, r := range list {
			t, arg, ok := rule(r)
			key := permTools[t]
			if !ok || key == "" {
				warns = append(warns, fmt.Sprintf("opencode: permission rule %q has no verified OpenCode equivalent and was not rendered", r))
				continue
			}
			if (key == "read" || key == "edit") && (strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~") || strings.HasPrefix(arg, "$HOME")) {
				// read/edit patterns are worktree-relative; an absolute or home
				// path is only ever seen by external_directory (FACTS.md).
				key = "external_directory"
			}
			o := tools[key]
			if o == nil {
				o = &ordered{}
				if key == "bash" || key == "edit" {
					o.set("*", "ask")
				}
				tools[key] = o
			}
			for _, pat := range patterns(key, arg) {
				o.set(pat, action)
			}
		}
	}
	add(p.Allow, "allow")
	add(p.Ask, "ask")
	add(p.Deny, "deny")
	if len(tools) == 0 {
		return nil, warns
	}
	out := map[string]any{}
	for k, o := range tools {
		out[k] = *o
	}
	return out, warns
}

// modelSet is the sorted, de-duplicated model names the provider exposes: the
// default plus models.allowed, each as the name a client sends.
func modelSet(p *policy.Profile, c harness.Context, def string) []string {
	var out []string
	for _, a := range append([]string{def}, p.Models.Allowed...) {
		if m := hutil.ClientModel(c, a); a != "" && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}

func (Adapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	warns := hutil.WarnUnsupported(name, p,
		"models.default", "models.allowed", "permissions.allow", "permissions.deny", "permissions.ask",
		"mcp.servers", "mcp.denied", "mcp.tools.allow", "mcp.tools.deny", "mcp.auth", "instructions")
	warns = append(warns, "opencode: cannot self-enforce version; halod enforces")

	cfg := map[string]any{}
	def := hutil.Model(p, name)
	if g := c.Gateway; g != nil {
		proto := hutil.Protocol(g, name, "anthropic-messages")
		pkg, ok := providerPkg[proto]
		if !ok {
			return nil, nil, fmt.Errorf("opencode: unsupported gateway protocol %q (want anthropic-messages or openai-responses)", proto)
		}
		aliases := modelSet(p, c, def)
		if len(aliases) == 0 {
			return nil, nil, fmt.Errorf("opencode: a gateway is configured but the profile names no model (models.default, harnesses.%s.model or models.allowed)", name)
		}
		models := map[string]any{}
		for _, a := range aliases {
			models[a] = map[string]any{"name": a}
		}
		opts := map[string]any{
			"baseURL": strings.TrimRight(g.BaseURL, "/") + "/v1",
			"apiKey":  "{env:" + tokenEnv + "}",
		}
		hdr := map[string]any{}
		if c.Ring != "" {
			hdr["x-halo-ring"] = c.Ring
		}
		if c.Release != "" {
			hdr["x-halo-release"] = c.Release
		}
		if len(hdr) > 0 {
			opts["headers"] = hdr
		}
		cfg["provider"] = map[string]any{providerID: map[string]any{"npm": pkg, "name": "Halos", "options": opts, "models": models}}
		// enabled_providers is an allowlist: a user's own provider block cannot
		// re-open a direct path to a model vendor (FACTS.md, managed-dir test).
		cfg["enabled_providers"] = []string{providerID}
		if m := hutil.ClientModel(c, def); m != "" {
			cfg["model"] = providerID + "/" + m
		}
		if h := g.Auth.HelperCommand; h != "" {
			warns = append(warns, "opencode: gateway.auth.helperCommand is not supported (no apiKeyHelper equivalent); set "+tokenEnv+" in the environment")
		}
	} else {
		warns = append(warns, name+": no gateway configured; traffic is not routed through Halos")
		if strings.Contains(def, "/") {
			cfg["model"] = def // already "<provider>/<model>"
		} else if def != "" {
			warns = append(warns, fmt.Sprintf("opencode: models.default %q is not rendered without a gateway (OpenCode model ids are <provider>/<model>)", def))
		}
		if len(p.Models.Allowed) > 0 {
			warns = append(warns, "opencode: models.allowed is not rendered without a gateway (the allowlist is the gateway provider's model set)")
		}
		if c.Ring != "" || c.Release != "" {
			warns = append(warns, "opencode: ring/release request headers need a gateway provider; not rendered")
		}
	}

	perm, pw := permission(p.Permissions)
	warns = append(warns, pw...)
	if perm != nil {
		cfg["permission"] = perm
	}
	if p.Permissions.DisableBypass {
		warns = append(warns, "opencode: permissions.disableBypass cannot be enforced: `--auto` approves every ask (explicit deny rules still hold) and the OPENCODE_PERMISSION environment variable overrides the managed permission block; render deny rules for what must never run")
	}

	if len(p.MCP.Servers) > 0 || len(p.MCP.Denied) > 0 {
		mcp, disabled := map[string]any{}, map[string]any{}
		for _, sv := range p.MCP.Servers {
			if slices.Contains(p.MCP.Denied, sv.Name) {
				return nil, nil, fmt.Errorf("opencode: mcp server %q is both defined and denied", sv.Name)
			}
			e := map[string]any{}
			switch {
			case sv.URL != "":
				e["type"], e["url"] = "remote", sv.URL
				if len(sv.Headers) > 0 {
					e["headers"] = sv.Headers
				}
			case len(sv.Command) > 0:
				e["type"], e["command"] = "local", sv.Command
			default:
				return nil, nil, fmt.Errorf("opencode: mcp server %q has neither url nor command", sv.Name)
			}
			warns = append(warns, opencodeAuth(e, sv)...)
			mcp[sv.Name] = e
			// MCP tools are registered as <server>_<tool>; tools.<name>: false
			// disables one (M). The order of mixed true/false globs is not
			// documented, so an allowlist is not rendered.
			for _, t := range sv.Tools.Deny {
				disabled[sv.Name+"_"+t] = false
			}
			if len(sv.Tools.Allow) > 0 {
				warns = append(warns, fmt.Sprintf("opencode: mcp server %q tools.allow is not rendered: OpenCode documents tools.<glob>: false to disable tools but not how a later true overrides an earlier false glob; deny the others with tools.deny", sv.Name))
			}
		}
		for _, d := range p.MCP.Denied {
			mcp[d] = map[string]any{"enabled": false}
		}
		cfg["mcp"] = mcp
		if len(disabled) > 0 {
			cfg["tools"] = disabled
		}
		warns = append(warns, "opencode: OpenCode has no MCP allowlist: user-defined servers still load, and mcp.denied disables by name only (a renamed server is not matched)")
	}

	if v := p.Harnesses[name].Version; v != "" {
		cfg["autoupdate"] = false // halod installs the pin; the CLI must not drift from it
	}

	dir := managedDir(c.OS)
	var files []harness.File
	if p.Instructions != "" {
		ip := hutil.Join(c.OS, dir, instructionsFile)
		cfg["instructions"] = []string{ip}
		files = append(files, harness.File{Path: ip, Mode: 0o644, Data: []byte(p.Instructions)})
	}

	hutil.DeepMerge(cfg, p.Harnesses[name].Overrides)
	if len(cfg) == 0 && len(files) == 0 {
		return nil, warns, nil
	}
	cfg["$schema"] = "https://opencode.ai/config.json"
	data, err := hutil.JSON(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("opencode: encode opencode.json: %w", err)
	}
	files = append([]harness.File{{Path: hutil.Join(c.OS, dir, "opencode.json"), Mode: 0o644, Data: data}}, files...)
	return files, warns, nil
}

// opencodeAuth renders a remote server's authorization into its mcp entry e:
// oauth.clientId and oauth.scope (space-separated) for mode oauth (M).
func opencodeAuth(e map[string]any, sv policy.MCPServer) []string {
	a := sv.Auth
	var warns []string
	switch a.Mode {
	case policy.MCPAuthOAuth:
		o := map[string]any{}
		if a.ClientID != "" {
			o["clientId"] = a.ClientID
		}
		if len(a.Scopes) > 0 {
			o["scope"] = strings.Join(a.Scopes, " ")
		}
		if len(o) > 0 {
			e["oauth"] = o
		}
		if a.ClientIDMetadataURL != "" {
			warns = append(warns, fmt.Sprintf("opencode: mcp server %q auth.clientIDMetadataURL is not rendered: OpenCode documents clientId or dynamic client registration only", sv.Name))
		}
		if a.Issuer != "" {
			warns = append(warns, fmt.Sprintf("opencode: mcp server %q auth.issuer is not rendered: OpenCode discovers the authorization server after a 401", sv.Name))
		}
	case policy.MCPAuthEnterprise:
		warns = append(warns, fmt.Sprintf("opencode: mcp server %q auth mode enterprise is not rendered: OpenCode documents no Enterprise-Managed Authorization (ID-JAG) client; users authorize with opencode mcp auth", sv.Name))
	case policy.MCPAuthHalos:
		warns = append(warns, fmt.Sprintf("opencode: mcp server %q auth mode halos is not rendered: OpenCode has no header helper ({env:VAR} headers are fixed per process), so a Halos token cannot be minted per connection", sv.Name))
	}
	return warns
}
