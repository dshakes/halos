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
// any other adapter unparseable files are skipped (only parseable ones get
// the universal checks).
var strictHarnesses = []string{"claude-code", "codex", "gemini-cli"}

// forbiddenValues may never appear as a config value in any rendered file
// (AGENTS.md invariant 1).
var forbiddenValues = []string{"bypassPermissions", "danger-full-access"}

// CheckRendered asserts security invariants on the files an adapter rendered,
// by parsing the output rather than trusting how it was produced. It is the
// backstop for adapter regressions and for harnesses.<h>.overrides, which
// are deep-merged after rendering. Any violation fails the build.
func CheckRendered(harnessName string, os harness.OS, files []harness.File, p *policy.Profile, g *policy.Gateway) error {
	strict := slices.Contains(strictHarnesses, harnessName)
	for _, f := range files {
		var doc map[string]any
		var err error
		switch {
		case strings.HasSuffix(f.Path, ".json"):
			err = json.Unmarshal(f.Data, &doc)
		case strings.HasSuffix(f.Path, ".toml"):
			err = toml.Unmarshal(f.Data, &doc)
		default:
			continue
		}
		if err != nil {
			if strict {
				return fmt.Errorf("%s/%s %s: parse rendered config: %w", harnessName, os, f.Path, err)
			}
			continue
		}
		fail := func(format string, a ...any) error {
			return fmt.Errorf("%s/%s %s: security invariant violated: %s", harnessName, os, f.Path, fmt.Sprintf(format, a...))
		}
		if err := walk(doc, "", func(path string, v any) error {
			if s, ok := v.(string); ok && slices.Contains(forbiddenValues, s) {
				return fail("%s = %q is never allowed", path, s)
			}
			return nil
		}); err != nil {
			return err
		}
		switch {
		case harnessName == "claude-code" && strings.HasSuffix(f.Path, "managed-settings.json"):
			err = checkClaude(doc, p, g, fail)
		case harnessName == "codex":
			err = checkCodex(doc, p, g, !strings.HasSuffix(f.Path, "requirements.toml"), fail)
		case harnessName == "gemini-cli":
			err = checkGemini(doc, p, fail)
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
	if p.Permissions.DisableBypass && d["disableBypassPermissionsMode"] != "disable" {
		return fail(`profile sets permissions.disableBypass but disableBypassPermissionsMode = %v, want "disable"`, d["disableBypassPermissionsMode"])
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
		case key == "writable_roots" && !tmpRoot(v):
			return fail("%s = %v is outside the workspace (only /tmp is permitted)", path, v)
		case key == "network_access" && v == true && len(p.Egress.AllowedDomains) > 0:
			return fail("%s = true but the profile restricts egress to %v", path, p.Egress.AllowedDomains)
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

// checkGemini: admin.secureModeEnabled disables YOLO mode and "Always allow"
// (https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md).
func checkGemini(d map[string]any, p *policy.Profile, fail func(string, ...any) error) error {
	if a, _ := d["admin"].(map[string]any); p.Permissions.DisableBypass && a["secureModeEnabled"] != true {
		return fail("profile sets permissions.disableBypass but admin.secureModeEnabled = %v, want true", a["secureModeEnabled"])
	}
	t, _ := d["telemetry"].(map[string]any)
	if t["logPrompts"] == true && !p.Telemetry.LogPrompts {
		return fail("telemetry.logPrompts = true but the profile does not enable telemetry.logPrompts")
	}
	return nil
}

// walk visits every leaf value of a decoded JSON/TOML document with a dotted
// path (array elements share their parent's path plus "[i]").
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
