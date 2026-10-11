// Package hutil holds helpers shared by harness adapters.
package hutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// Join joins path parts with the separator of the target OS.
func Join(os harness.OS, parts ...string) string {
	if os == harness.Windows {
		return strings.Join(parts, `\`)
	}
	return strings.Join(parts, "/")
}

// DeepMerge merges src into dst recursively (maps merge, everything else is
// replaced by src) and returns dst. src is never aliased into dst.
func DeepMerge(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			dm, _ := dst[k].(map[string]any)
			dst[k] = DeepMerge(dm, sm)
			continue
		}
		dst[k] = v
	}
	return dst
}

// JSON renders v deterministically: sorted keys (maps), 2-space indent, trailing newline.
func JSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("hutil: encode json: %w", err)
	}
	return buf.Bytes(), nil
}

// Protocol returns the gateway protocol configured for harness, or def.
func Protocol(g *policy.Gateway, harnessName, def string) string {
	if g != nil {
		if p := g.Protocols[harnessName]; p != "" {
			return p
		}
	}
	return def
}

// PctEncode percent-encodes s for OTEL resource attributes (RFC 3986 unreserved kept).
func PctEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// SortedKeys returns m's keys sorted.
func SortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Populated lists the profile fields that are set, by dotted name.
func Populated(p *policy.Profile) []string {
	var out []string
	add := func(cond bool, n string) {
		if cond {
			out = append(out, n)
		}
	}
	add(p.Models.Default != "", "models.default")
	add(len(p.Models.Allowed) > 0, "models.allowed")
	add(p.Models.Enforce, "models.enforce")
	add(p.Permissions.Mode != "", "permissions.mode")
	add(len(p.Permissions.Allow) > 0, "permissions.allow")
	add(len(p.Permissions.Deny) > 0, "permissions.deny")
	add(len(p.Permissions.Ask) > 0, "permissions.ask")
	add(p.Permissions.DisableBypass, "permissions.disableBypass")
	add(p.Permissions.Sandbox != "", "permissions.sandbox")
	add(p.MCP.ManagedOnly, "mcp.managedOnly")
	add(len(p.MCP.Servers) > 0, "mcp.servers")
	add(len(p.MCP.Denied) > 0, "mcp.denied")
	add(p.Hooks.ManagedOnly, "hooks.managedOnly")
	add(len(p.Hooks.Hooks) > 0, "hooks.items")
	add(p.Telemetry.Enabled, "telemetry.enabled")
	add(p.Telemetry.LogPrompts, "telemetry.logPrompts")
	add(len(p.Telemetry.Attributes) > 0, "telemetry.attributes")
	add(len(p.Egress.AllowedDomains) > 0, "egress.allowedDomains")
	add(p.Instructions != "", "instructions")
	add(len(p.Env) > 0, "env")
	return out
}

// WarnUnsupported returns one warning per populated profile field not in handled.
func WarnUnsupported(adapter string, p *policy.Profile, handled ...string) []string {
	h := map[string]bool{}
	for _, n := range handled {
		h[n] = true
	}
	var out []string
	for _, n := range Populated(p) {
		if !h[n] {
			out = append(out, fmt.Sprintf("%s: profile field %q is not supported and was not rendered", adapter, n))
		}
	}
	return out
}

// CheckHeaderValues rejects header names or values containing CR or LF, which
// would let a value smuggle extra headers into newline-joined header lists.
func CheckHeaderValues(h map[string]string) error {
	for _, k := range SortedKeys(h) {
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(h[k], "\r\n") {
			return fmt.Errorf("header %q: value contains CR/LF", k)
		}
	}
	return nil
}

// VersionBefore reports whether a "major.minor[.patch...]" version is below
// major.minor. Unparseable versions report false (nothing to warn about).
func VersionBefore(v string, major, minor int) bool {
	var a, b int
	if _, err := fmt.Sscanf(v, "%d.%d", &a, &b); err != nil {
		return false
	}
	return a < major || (a == major && b < minor)
}

// Model is the default model alias for harness name: its own harnesses.<name>.model,
// else the profile's models.default.
func Model(p *policy.Profile, name string) string {
	if m := p.Harnesses[name].Model; m != "" {
		return m
	}
	return p.Models.Default
}

// ClientModel is the model name a client should send for alias. Behind a
// gateway Halos runs (halo-proxy, kong) that is the alias itself; behind an
// external gateway nothing translates aliases, so it is the route's primary
// provider model id. An alias with no route is returned unchanged.
func ClientModel(c harness.Context, alias string) string {
	if g := c.Gateway; g != nil && g.Engine == policy.EngineExternal {
		if m := g.Models[alias].Primary().Model; m != "" {
			return m
		}
	}
	return alias
}

// OTELResourceAttributes is the OTEL_RESOURCE_ATTRIBUTES value for harness
// name: the profile's telemetry.attributes plus halo.harness, halo.ring,
// halo.release and, for a variant release, halo.experiment/halo.variant.
// halo.* are set last so a profile attribute cannot spoof them.
func OTELResourceAttributes(name string, t policy.Telemetry, c harness.Context) string {
	attrs := map[string]string{}
	for k, v := range t.Attributes {
		attrs[k] = v
	}
	attrs["halo.harness"] = name
	if c.Ring != "" {
		attrs["halo.ring"] = c.Ring
	}
	if c.Release != "" {
		attrs["halo.release"] = c.Release
	}
	// Client-axis variant release: CLI metrics (cost, tokens, tool calls)
	// carry the variant, so client-axis analysis and maxSpendUSD see them.
	// Only a variant release may claim them; a profile attribute cannot.
	delete(attrs, "halo.experiment")
	delete(attrs, "halo.variant")
	if c.Experiment != "" {
		attrs["halo.experiment"], attrs["halo.variant"] = c.Experiment, c.Variant
	}
	var kv []string
	for _, k := range SortedKeys(attrs) {
		kv = append(kv, PctEncode(k)+"="+PctEncode(attrs[k]))
	}
	return strings.Join(kv, ",")
}

// ShQuote single-quotes s for POSIX sh.
func ShQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// OTELShellWrapper is a /etc/profile.d function that runs binary with the
// release's OTEL_RESOURCE_ATTRIBUTES, for CLIs whose config has no
// resource-attribute key (they all honor the env var; test/uat). A function,
// not an export: every harness sets halo.harness, so one global variable would
// mislabel the others. Like other profile.d settings it reaches login shells
// (and, exported, their bash children); an exec that bypasses the shell
// (timeout, env, xargs) runs the CLI unlabeled.
func OTELShellWrapper(binary, attrs string) string {
	return "# Halos: label this CLI's telemetry with the release (login shells).\n" +
		binary + "() { OTEL_RESOURCE_ATTRIBUTES=" + ShQuote(attrs) + " command " + binary + " \"$@\"; }\n" +
		"[ -z \"${BASH_VERSION:-}\" ] || export -f " + binary + "\n"
}
