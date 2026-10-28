package release

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// strictHarnesses are the adapters whose rendered JSON/TOML must parse; for
// any other adapter unparseable files skip the parsed checks (the raw
// invariant 1 scan still runs on every byte).
var strictHarnesses = []string{"claude-code", "codex", "gemini-cli", "cursor-agent", "opencode"}

// CheckRendered asserts security invariants on the files an adapter rendered,
// by parsing the output rather than trusting how it was produced. It is the
// backstop for adapter regressions and for harnesses.<h>.overrides, which
// are deep-merged after rendering. Any violation fails the build.
func CheckRendered(harnessName string, os harness.OS, files []harness.File, p *policy.Profile, g *policy.Gateway) error {
	strict := slices.Contains(strictHarnesses, harnessName)
	for _, f := range files {
		fail := func(format string, a ...any) error {
			return fmt.Errorf("%s/%s %s: security invariant violated: %s", harnessName, os, f.Path, fmt.Sprintf(format, a...))
		}
		// Every file, any format: bundles land world-readable (0644 ceiling).
		// The value is not echoed, so the error itself never leaks it.
		if policy.HasTokenShape(string(f.Data)) {
			return fmt.Errorf("%s/%s %s: security invariant violated: contains a literal credential (token, access key or private key); use a ${VAR} reference resolved on the client", harnessName, os, f.Path)
		}
		var doc map[string]any
		var err error
		switch {
		case strings.HasSuffix(f.Path, ".json"):
			err = json.Unmarshal(f.Data, &doc)
		case strings.HasSuffix(f.Path, ".toml"):
			err = toml.Unmarshal(f.Data, &doc)
		}
		if err != nil && strict {
			return fmt.Errorf("%s/%s %s: parse rendered config: %w", harnessName, os, f.Path, err)
		}
		// Invariant 1: decoded values first (names the field, sees through
		// escapes), then every raw byte, so no format or parse failure skips it.
		if err := walk(doc, "", func(path string, v any) error {
			if s, ok := v.(string); ok {
				if tok := policy.BypassToken(s); tok != "" {
					return fail("%s = %q contains permission-bypass token %q (invariant 1)", path, s, tok)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if tok := policy.BypassToken(string(f.Data)); tok != "" {
			return fail("contains permission-bypass token %q (invariant 1)", tok)
		}
		if doc == nil || err != nil {
			continue
		}
		switch {
		case harnessName == "claude-code" && strings.HasSuffix(f.Path, "managed-settings.json"):
			err = checkClaude(doc, p, g, fail)
		case harnessName == "codex":
			err = checkCodex(doc, p, g, !strings.HasSuffix(f.Path, "requirements.toml"), fail)
		case harnessName == "gemini-cli":
			err = checkGemini(doc, p, fail)
		case harnessName == "opencode" && strings.HasSuffix(f.Path, "opencode.json"):
			err = checkOpenCode(doc, g, fail)
		case harnessName == "cursor-agent":
			err = checkCursor(doc, fail)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func checkClaude(d map[string]any, p *policy.Profile, g *policy.Gateway, fail func(string, ...any) error) error {
	if p.Permissions.SandboxRequired {
		if sb, _ := d["sandbox"].(map[string]any); sb["enabled"] != true || sb["failIfUnavailable"] != true {
			return fail("profile sets permissions.sandboxRequired but sandbox.enabled/failIfUnavailable = %v", d["sandbox"])
		}
	}
	// Claude Code reads the bypass lock only as permissions.disableBypassPermissionsMode
	// (https://code.claude.com/docs/en/settings-reference#permissions-disablebypasspermissionsmode).
	// A top-level key (rendered by Halos before v0.4) is ignored, so it fails
	// rather than reading as enforced; any other value anywhere fails too.
	if _, ok := d["disableBypassPermissionsMode"]; ok {
		return fail(`disableBypassPermissionsMode is set at the top level, where Claude Code does not read it; set permissions.disableBypassPermissionsMode = "disable" instead`)
	}
	if err := walkKey(d, "", "disableBypassPermissionsMode", func(path string, v any) error {
		if v != "disable" {
			return fail(`%s = %v, want "disable"`, path, v)
		}
		return nil
	}); err != nil {
		return err
	}
	if perms, _ := d["permissions"].(map[string]any); p.Permissions.DisableBypass && perms["disableBypassPermissionsMode"] != "disable" {
		return fail(`profile sets permissions.disableBypass but permissions.disableBypassPermissionsMode = %v, want "disable"`, perms["disableBypassPermissionsMode"])
	}
	if p.Hooks.ManagedOnly && d["allowManagedHooksOnly"] != true {
		return fail("profile sets hooks.managedOnly but allowManagedHooksOnly = %v", d["allowManagedHooksOnly"])
	}
	if p.MCP.ManagedOnly && d["allowManagedMcpServersOnly"] != true {
		return fail("profile sets mcp.managedOnly but allowManagedMcpServersOnly = %v", d["allowManagedMcpServersOnly"])
	}
	if v := p.Harnesses["claude-code"].Version; v != "" {
		if d["requiredMinimumVersion"] != v || d["requiredMaximumVersion"] != v {
			return fail("version pin %q not enforced: requiredMinimumVersion = %v, requiredMaximumVersion = %v", v, d["requiredMinimumVersion"], d["requiredMaximumVersion"])
		}
	}
	if g != nil {
		env, _ := d["env"].(map[string]any)
		n := 0
		for _, k := range []string{"ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL"} {
			if v, ok := env[k]; ok {
				n++
				if v != g.BaseURL {
					return fail("env.%s = %v, want gateway %q", k, v, g.BaseURL)
				}
			}
		}
		if n == 0 {
			return fail("gateway is configured but neither env.ANTHROPIC_BASE_URL nor env.ANTHROPIC_BEDROCK_BASE_URL points at it")
		}
		if h, ok := d["apiKeyHelper"]; ok || g.Auth.HelperCommand != "" {
			if h != g.Auth.HelperCommand {
				return fail("apiKeyHelper = %v, want gateway helperCommand %q", h, g.Auth.HelperCommand)
			}
		}
	}
	return nil
}

// checkCodex: approval_policy "never" is never allowed (no profile field can
// request it); nor are sandbox escapes an override could smuggle in (writable
// roots outside the workspace, network with a restricted egress profile,
// notify commands, trusted projects). With a gateway, every model provider
// must point under it and the selected provider must be one of them.
// Keys per https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json.
func checkCodex(d map[string]any, p *policy.Profile, g *policy.Gateway, managedConfig bool, fail func(string, ...any) error) error {
	if err := walk(d, "", func(path string, v any) error {
		key := path[strings.LastIndex(path, ".")+1:]
		if i := strings.IndexByte(key, '['); i >= 0 {
			key = key[:i]
		}
		switch {
		case (key == "approval_policy" || key == "allowed_approval_policies") && v == "never":
			return fail(`%s = "never" is not permitted by any profile`, path)
		case key == "writable_roots" && !tmpRoot(v) && !policyRoot(p, v):
			return fail("%s = %v is outside the workspace (only /tmp and sandbox.writableRoots are permitted)", path, v)
		case key == "network_access" && v == true && p.Egress.Restricted() && p.Egress.Rules().Default == policy.EgressDeny:
			return fail("%s = true but the profile's egress default is deny (allowlist %v)", path, p.Egress.Rules().Allow)
		case path == "notify" || strings.HasPrefix(path, "notify["):
			return fail("%s: notify runs an arbitrary command and is not permitted", path)
		case key == "trust_level" && v == "trusted":
			return fail(`%s = "trusted" is not permitted`, path)
		}
		return nil
	}); err != nil {
		return err
	}
	if g == nil {
		return nil
	}
	base := strings.TrimRight(g.BaseURL, "/")
	provs, _ := d["model_providers"].(map[string]any)
	for _, id := range sortedKeys(provs) {
		pm, _ := provs[id].(map[string]any)
		if u, _ := pm["base_url"].(string); u != base && !strings.HasPrefix(u, base+"/") {
			return fail("model_providers.%s.base_url = %q is not under gateway %q", id, u, g.BaseURL)
		}
	}
	mp, ok := d["model_provider"]
	if managedConfig && !ok {
		return fail("gateway is configured but model_provider is unset (Codex would call OpenAI directly)")
	}
	if _, known := provs[fmt.Sprint(mp)]; ok && !known {
		return fail("model_provider = %v does not name a gateway provider", mp)
	}
	// A Codex named profile could switch provider; it may only pick a gateway one.
	profiles, _ := d["profiles"].(map[string]any)
	for _, name := range sortedKeys(profiles) {
		pm, _ := profiles[name].(map[string]any)
		if _, ok := pm["model_providers"]; ok {
			return fail("profiles.%s.model_providers is not permitted", name)
		}
		if mp, ok := pm["model_provider"]; ok {
			if _, known := provs[fmt.Sprint(mp)]; !known {
				return fail("profiles.%s.model_provider = %v does not name a gateway provider", name, mp)
			}
		}
	}
	return nil
}

// tmpRoot: Codex's documented default temp root; anything else widens the
// workspace-write sandbox (writable_roots are absolute paths).
func tmpRoot(v any) bool {
	s, _ := v.(string)
	c := path.Clean(s)
	return c == "/tmp" || strings.HasPrefix(c, "/tmp/")
}

// policyRoot: a writable root the profile's sandbox.writableRoots names and
// validation would accept (no home or system directory, no overlap with a
// protected path): a profile that skipped validation cannot smuggle one in.
func policyRoot(p *policy.Profile, v any) bool {
	s, ok := v.(string)
	return ok && slices.Contains(p.Sandbox.WritableRoots, s) && policy.WritableRootProblem(s, p.Sandbox.ProtectedPaths) == ""
}

// checkGemini: security.disableYoloMode refuses YOLO mode. (admin.secureModeEnabled
// in the system file is ignored by gemini-cli: the admin block is remote-only;
// verified in test/uat.)
func checkGemini(d map[string]any, p *policy.Profile, fail func(string, ...any) error) error {
	if sec, _ := d["security"].(map[string]any); p.Permissions.DisableBypass && sec["disableYoloMode"] != true {
		return fail("profile sets permissions.disableBypass but security.disableYoloMode = %v, want true", sec["disableYoloMode"])
	}
	t, _ := d["telemetry"].(map[string]any)
	if t["logPrompts"] == true && !p.Telemetry.LogPrompts {
		return fail("telemetry.logPrompts = true but the profile does not enable telemetry.logPrompts")
	}
	return nil
}

// checkOpenCode: a permission block that is the bare string "allow" or has a
// "*": "allow" entry approves every action (OpenCode's bypass equivalent), which
// no profile may render. With a gateway, every provider must point under it and
// only gateway providers may be enabled (a user provider could otherwise reach
// a model vendor directly). Keys per https://opencode.ai/config.json.
func checkOpenCode(d map[string]any, g *policy.Gateway, fail func(string, ...any) error) error {
	switch perm := d["permission"].(type) {
	case string:
		if perm == "allow" {
			return fail(`permission = "allow" approves every action and is never allowed`)
		}
	case map[string]any:
		if perm["*"] == "allow" {
			return fail(`permission["*"] = "allow" approves every action and is never allowed`)
		}
	}
	if g == nil {
		return nil
	}
	base := strings.TrimRight(g.BaseURL, "/")
	provs, _ := d["provider"].(map[string]any)
	for _, id := range sortedKeys(provs) {
		pm, _ := provs[id].(map[string]any)
		opts, _ := pm["options"].(map[string]any)
		if u, _ := opts["baseURL"].(string); u != base && !strings.HasPrefix(u, base+"/") {
			return fail("provider.%s.options.baseURL = %q is not under gateway %q", id, u, g.BaseURL)
		}
	}
	enabled, _ := d["enabled_providers"].([]any)
	if len(enabled) == 0 {
		return fail("gateway is configured but enabled_providers is unset (OpenCode would also load direct providers)")
	}
	for _, e := range enabled {
		if _, ok := provs[fmt.Sprint(e)]; !ok {
			return fail("enabled_providers names %v, which is not a gateway provider", e)
		}
	}
	if m, ok := d["model"].(string); ok {
		if id, _, _ := strings.Cut(m, "/"); provs[id] == nil {
			return fail("model = %q does not name a gateway provider", m)
		}
	}
	return nil
}

// checkCursor: every rendered hook must be a command hook with a command (a
// "prompt" hook would hand the decision to a model).
func checkCursor(d map[string]any, fail func(string, ...any) error) error {
	hooks, _ := d["hooks"].(map[string]any)
	for _, ev := range sortedKeys(hooks) {
		list, _ := hooks[ev].([]any)
		for i, e := range list {
			h, _ := e.(map[string]any)
			if t, ok := h["type"]; ok && t != "command" {
				return fail("hooks.%s[%d].type = %v, only command hooks are rendered", ev, i, t)
			}
			if c, _ := h["command"].(string); c == "" {
				return fail("hooks.%s[%d] has no command", ev, i)
			}
		}
	}
	return nil
}

// walk visits every leaf value of a decoded JSON/TOML document with a dotted
// path (array elements share their parent's path plus "[i]").
// walkKey calls fn with the path and value of every map entry named key, at
// any depth and whatever the value's type.
func walkKey(v any, path, key string, fn func(string, any) error) error {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(t) {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if k == key {
				if err := fn(p, t[k]); err != nil {
					return err
				}
			}
			if err := walkKey(t[k], p, key, fn); err != nil {
				return err
			}
		}
	case []any:
		for i, c := range t {
			if err := walkKey(c, fmt.Sprintf("%s[%d]", path, i), key, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

func walk(v any, path string, fn func(string, any) error) error {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(t) {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if err := walk(t[k], p, fn); err != nil {
				return err
			}
		}
	case []any:
		for i, c := range t {
			if err := walk(c, fmt.Sprintf("%s[%d]", path, i), fn); err != nil {
				return err
			}
		}
	default:
		return fn(path, v)
	}
	return nil
}
