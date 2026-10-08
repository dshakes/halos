package policy

import (
	"fmt"
	"maps"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Guardrail is an org-wide policy check. ponytail: guardrails are plain Go
// funcs, not OPA (ADR-0007). An org-specific evaluator (Rego later) plugs in
// through ExtraGuardrails; no other code changes.
type Guardrail func(*Org) []Issue

// ExtraGuardrails run after the built-in guardrails. They can only add
// issues: the built-ins have already been judged and recorded, so an extra
// can never remove or downgrade one (ADR-0007). Set once at start-up.
var ExtraGuardrails []Guardrail

// builtinGuardrails always run at the end of Org.Validate. Unexported so no
// caller can drop one.
var builtinGuardrails = []Guardrail{
	guardNoBypass,
	guardTelemetryOn,
	guardMCPServers,
	guardEgressHasGateway,
	guardGARing,
	guardSandboxEgress,
	guardReservedOverrides,
	guardNames,
	guardRingProfiles,
	guardWidening,
	guardClientVariants,
	guardSecrets,
	guardEnvKeys,
	guardToggles,
	guardTrafficOverlap,
	guardHarnessWire,
}

func gi(sev Severity, path, format string, a ...any) Issue {
	return Issue{sev, path, fmt.Sprintf(format, a...)}
}

// guardNoBypass: no profile may use bypassPermissions or an unknown mode;
// "auto" on the default (GA) ring is a warning.
func guardNoBypass(o *Org) []Issue {
	var out []Issue
	for _, name := range sortedKeys(o.Profiles) {
		p, err := o.ResolveProfile(name)
		if err != nil {
			continue // reported by Validate
		}
		if p.Permissions.Mode == "bypassPermissions" {
			out = append(out, gi(SeverityError, "profiles["+name+"].permissions.mode", "bypassPermissions is forbidden by org guardrail"))
		}
		// overrides and env are emitted as config values (same rule as toggles)
		forbidden := forbiddenValue(p.Env)
		for _, h := range sortedKeys(p.Harnesses) {
			forbidden = forbidden || forbiddenValue(p.Harnesses[h].Overrides)
		}
		if forbidden {
			out = append(out, gi(SeverityError, "profiles["+name+"]", "bypassPermissions / danger-full-access in env or harness overrides are forbidden by org guardrail"))
		}
	}
	for _, r := range o.Rings {
		p, err := o.ResolveProfile(r.Profile)
		if err != nil {
			continue
		}
		if p.Permissions.Mode == "auto" && r.Membership.Default {
			out = append(out, gi(SeverityWarning, "rings["+r.Name+"].profile", "permissions.mode=auto on the default (GA) ring"))
		}
	}
	return out
}

func guardTelemetryOn(o *Org) []Issue {
	var out []Issue
	for _, r := range o.Rings {
		if p, err := o.ResolveProfile(r.Profile); err == nil && !p.Telemetry.Enabled {
			out = append(out, gi(SeverityError, "rings["+r.Name+"].profile", "telemetry must be enabled (profile %q)", r.Profile))
		}
	}
	return out
}

// guardMCPServers: servers need exactly one of url (https) or command.
func guardMCPServers(o *Org) []Issue {
	var out []Issue
	for _, name := range sortedKeys(o.Profiles) {
		p, err := o.ResolveProfile(name)
		if err != nil {
			continue
		}
		for i, s := range p.MCP.Servers {
			path := fmt.Sprintf("profiles[%s].mcp.servers[%d]", name, i)
			switch {
			case s.Name == "":
				out = append(out, gi(SeverityError, path+".name", "name is required"))
			case (s.URL == "") == (len(s.Command) == 0):
				out = append(out, gi(SeverityError, path, "server %q needs exactly one of url or command", s.Name))
			case s.URL != "":
				if u, err := url.Parse(s.URL); err != nil || u.Scheme != "https" || u.Host == "" {
					out = append(out, gi(SeverityError, path+".url", "%q must be an https URL", s.URL))
				}
			}
		}
	}
	return out
}

// guardEgressHasGateway: a non-empty egress allowlist must include the gateway host.
func guardEgressHasGateway(o *Org) []Issue {
	if o.Gateway == nil {
		return nil
	}
	u, err := url.Parse(o.Gateway.BaseURL)
	if err != nil || u.Hostname() == "" {
		return nil // reported by Validate
	}
	host := u.Hostname()
	var out []Issue
	for _, name := range sortedKeys(o.Profiles) {
		p, err := o.ResolveProfile(name)
		if err != nil || len(p.Egress.AllowedDomains) == 0 {
			continue
		}
		ok := false
		for _, d := range p.Egress.AllowedDomains {
			if d == host || (strings.HasPrefix(d, "*.") && strings.HasSuffix(host, d[1:])) {
				ok = true
			}
		}
		if !ok {
			out = append(out, gi(SeverityError, "profiles["+name+"].egress.allowedDomains", "must include gateway host %q", host))
		}
	}
	return out
}

// guardGARing (ADR-0007): a default (GA) ring that ships org hooks must make
// them managed-only, so user and project hooks cannot run beside them.
func guardGARing(o *Org) []Issue {
	var out []Issue
	for _, r := range o.Rings {
		if !r.Membership.Default {
			continue
		}
		if p, err := o.ResolveProfile(r.Profile); err == nil && len(p.Hooks.Hooks) > 0 && !p.Hooks.ManagedOnly {
			out = append(out, gi(SeverityError, "rings["+r.Name+"].profile", "the default (GA) ring ships hooks, so hooks.managedOnly must be true (profile %q)", r.Profile))
		}
	}
	return out
}

// guardSandboxEgress (ADR-0007): a profile that requires the sandbox is a
// managed environment, so its egress allowlist must be non-empty; an empty list
// renders a sandbox with the network wide open. Checked on what ships: ring
// profiles (variants may not widen them).
func guardSandboxEgress(o *Org) []Issue {
	var out []Issue
	for _, r := range o.Rings {
		if p, err := o.ResolveProfile(r.Profile); err == nil && p.Permissions.SandboxRequired && len(p.Egress.AllowedDomains) == 0 {
			out = append(out, gi(SeverityError, "rings["+r.Name+"].profile", "permissions.sandboxRequired is true, so egress.allowedDomains must be non-empty (profile %q)", r.Profile))
		}
	}
	return out
}

// allowedOverrides is a per-harness ALLOWLIST of harness-native keys a
// profile's harnesses.<h>.overrides may set. Overrides are deep-merged after
// the renderer runs, so anything not known to be cosmetic/behavioural is
// rejected: a denylist cannot keep up with new security knobs (e.g. Gemini
// admin.secureModeEnabled, Codex sandbox_workspace_write / notify / projects).
// Entries are dotted paths into the override map; an exact entry allows the
// whole subtree under it, a trailing ".*" allows any key below the prefix.
// A harness missing here accepts no overrides at all.
//
// Commands are never allowlisted (Claude statusLine/fileSuggestion, Codex
// notify): they would run arbitrary code outside the hooks.managedOnly lock.
var allowedOverrides = map[string][]string{
	// https://code.claude.com/docs/en/settings-reference (fetched 2026-09-30)
	"claude-code": {
		"cleanupPeriodDays", "companyAnnouncements", "outputStyle", "language", "theme",
		"spinnerTipsEnabled", "spinnerTipsOverride", "spinnerVerbs", "showTurnDuration",
		"includeCoAuthoredBy", "attribution", "prefersReducedMotion", "respectGitignore",
	},
	// https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json (fetched 2026-09-30)
	"codex": {
		"model_reasoning_effort", "model_reasoning_summary", "model_verbosity",
		"hide_agent_reasoning", "show_raw_agent_reasoning", "file_opener", "tui.*",
	},
	// https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md (fetched 2026-09-30)
	// general.* is listed key by key: defaultApprovalMode (yolo), enableAutoUpdate
	// (version pin), debugKeystrokeLogging (privacy) are deliberately absent.
	"gemini-cli": {
		"ui.*",
		"general.preferredEditor", "general.openEditorInNewWindow", "general.vimMode",
		"general.enableNotifications", "general.notificationMethod",
		"general.checkpointing.enabled", "general.sessionRetention.*",
		"context.fileName", "context.importFormat",
	},
}

func allowedOverride(harness, path string) bool {
	for _, a := range allowedOverrides[harness] {
		if a == path || (strings.HasSuffix(a, ".*") && strings.HasPrefix(path, strings.TrimSuffix(a, "*"))) {
			return true
		}
	}
	return false
}

// disallowedOverrides returns the override paths (sorted) not covered by the
// allowlist: descends into nested maps until a path is allowed or a leaf is hit.
func disallowedOverrides(harness, prefix string, m map[string]any) []string {
	var out []string
	for _, k := range sortedKeys(m) {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if allowedOverride(harness, path) {
			continue
		}
		if sub, ok := m[k].(map[string]any); ok && len(sub) > 0 {
			out = append(out, disallowedOverrides(harness, path, sub)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

// guardReservedOverrides: overrides are merged into rendered config AFTER the
// renderer runs, so only allowlisted keys may be set. Checked on each
// profile's own declaration (inherited overrides are reported on the profile
// that declares them).
func guardReservedOverrides(o *Org) []Issue {
	var out []Issue
	for _, name := range sortedKeys(o.Profiles) {
		p := o.Profiles[name]
		for _, h := range sortedKeys(p.Harnesses) {
			_, known := allowedOverrides[h]
			for _, k := range disallowedOverrides(h, "", p.Harnesses[h].Overrides) {
				path := fmt.Sprintf("profiles[%s].harnesses.%s.overrides.%s", name, h, k)
				if !known {
					out = append(out, gi(SeverityError, path, "harness %q accepts no overrides", h))
				} else {
					out = append(out, gi(SeverityError, path, "override key %q is not in the allowlist; request it via adapter support", k))
				}
			}
		}
	}
	return out
}

// guardNames: every identifier that reaches scripts, paths or headers must be ValidName.
func guardNames(o *Org) []Issue {
	var out []Issue
	check := func(path, n string) {
		if !ValidName(n) {
			out = append(out, gi(SeverityError, path, "name %q invalid: must match %s", n, nameRe))
		}
	}
	for _, name := range sortedKeys(o.Profiles) {
		check("profiles["+name+"].name", name)
		for i, s := range o.Profiles[name].MCP.Servers {
			check(fmt.Sprintf("profiles[%s].mcp.servers[%d].name", name, i), s.Name)
		}
	}
	for i, s := range o.SelfService.Catalog {
		check(fmt.Sprintf("selfService.catalog[%d].name", i), s.Name)
	}
	for _, r := range o.Rings {
		check("rings["+r.Name+"].name", r.Name)
	}
	for _, e := range o.Experiments {
		check("experiments["+e.Name+"].name", e.Name)
		for i, v := range e.Variants {
			check(fmt.Sprintf("experiments[%s].variants[%d].name", e.Name, i), v.Name)
		}
	}
	if g := o.Gateway; g != nil {
		for _, a := range sortedKeys(g.Models) {
			check("gateway.models."+a, a)
		}
		for _, u := range sortedKeys(g.Upstreams) {
			check("gateway.upstreams."+u, u)
		}
	}
	return out
}

// guardRingProfiles: every ring must disable bypass mode; prompt logging on
// the default (GA) ring is flagged for review.
func guardRingProfiles(o *Org) []Issue {
	var out []Issue
	for _, r := range o.Rings {
		p, err := o.ResolveProfile(r.Profile)
		if err != nil {
			continue
		}
		if !p.Permissions.DisableBypass {
			out = append(out, gi(SeverityError, "rings["+r.Name+"].profile", "permissions.disableBypass must be true (profile %q)", r.Profile))
		}
		if r.Membership.Default && p.Telemetry.LogPrompts {
			out = append(out, gi(SeverityWarning, "rings["+r.Name+"].profile", "telemetry.logPrompts=true on the default (GA) ring exports every user's prompts (profile %q)", r.Profile))
		}
	}
	return out
}

// guardWidening: a child profile whose allow/ask rules or egress allowlist
// add entries beyond its parent's is widening access; make that visible.
func guardWidening(o *Org) []Issue {
	var out []Issue
	for _, name := range sortedKeys(o.Profiles) {
		parent := o.Profiles[name].Extends
		if parent == "" {
			continue
		}
		c, err1 := o.ResolveProfile(name)
		p, err2 := o.ResolveProfile(parent)
		if err1 != nil || err2 != nil {
			continue
		}
		for _, w := range widenings(c, p) {
			out = append(out, gi(SeverityWarning, "profiles["+name+"]."+w.field, "widens parent %q: adds %v", parent, w.added))
		}
	}
	return out
}

type widening struct {
	field string
	added []string
}

// widenings lists the allow/ask rules and egress domains c adds beyond base.
func widenings(c, base *Profile) []widening {
	var out []widening
	for _, f := range []struct {
		field      string
		child, par []string
	}{
		{"permissions.allow", c.Permissions.Allow, base.Permissions.Allow},
		{"permissions.ask", c.Permissions.Ask, base.Permissions.Ask},
		{"egress.allowedDomains", c.Egress.AllowedDomains, base.Egress.AllowedDomains},
	} {
		// An empty base egress list means "unrestricted", so any child list narrows it.
		if f.field == "egress.allowedDomains" && len(f.par) == 0 {
			continue
		}
		var added []string
		for _, e := range f.child {
			if !slices.Contains(f.par, e) {
				added = append(added, e)
			}
		}
		if len(added) > 0 {
			out = append(out, widening{f.field, added})
		}
	}
	return out
}

// guardClientVariants: a client-axis variant profile is delivered as its own
// release to a slice of each enrolled ring, so it must meet every ring
// requirement (exact version pins, telemetry, disableBypass) and may not grant
// more than the ring's own profile: what the guardWidening warns about between
// parent and child is an ERROR between ring and variant. Only one running
// client-axis experiment may enroll a ring (a device applies one release), and
// no channel name may collide with a ring or another channel.
func guardClientVariants(o *Org) []Issue {
	var out []Issue
	channels := map[string]string{} // channel -> owner (ring or experiment/variant)
	for _, r := range o.Rings {
		channels[r.Name] = "ring " + r.Name
	}
	running := map[string]string{} // ring -> running client-axis experiment
	for _, e := range o.Experiments {
		if e.Axis != AxisClient {
			continue
		}
		path := "experiments[" + e.Name + "]"
		for _, ring := range e.Rings {
			if e.Status == "running" {
				if prev, dup := running[ring]; dup {
					out = append(out, gi(SeverityError, path+".rings", "ring %q is already enrolled in running client-axis experiment %q; a device applies one release, so client-axis experiments on a ring must not overlap", ring, prev))
				}
				running[ring] = e.Name
			}
			var rp *Profile
			for _, r := range o.Rings {
				if r.Name == ring {
					rp, _ = o.ResolveProfile(r.Profile)
				}
			}
			for i, va := range e.Variants {
				vp := fmt.Sprintf("%s.variants[%d]", path, i)
				ch := ChannelName(ring, e.Name, va.Name)
				owner := fmt.Sprintf("experiment %s variant %s", e.Name, va.Name)
				if prev, dup := channels[ch]; dup && prev != owner {
					out = append(out, gi(SeverityError, vp+".name", "delivery channel %q (ring %s) collides with %s; rename the ring, experiment or variant", ch, ring, prev))
				}
				channels[ch] = owner
				p, err := o.ResolveProfile(va.Profile)
				if err != nil || rp == nil {
					continue // reported by Validate
				}
				out = append(out, variantProfileIssues(vp+".profile", va.Profile, ring, p, rp)...)
			}
		}
	}
	return out
}

func variantProfileIssues(path, name, ring string, p, rp *Profile) []Issue {
	var out []Issue
	bad := func(format string, a ...any) {
		out = append(out, gi(SeverityError, path, "profile %q (ring %s): "+format, append([]any{name, ring}, a...)...))
	}
	if len(p.Harnesses) == 0 {
		bad("enables no harnesses")
	}
	for _, h := range sortedKeys(p.Harnesses) {
		if ver := p.Harnesses[h].Version; !semverRe.MatchString(ver) {
			bad("harnesses.%s.version %q must be an exact semver (no ranges, no latest)", h, ver)
		}
	}
	if !p.Telemetry.Enabled {
		bad("telemetry must be enabled")
	}
	if !p.Permissions.DisableBypass {
		bad("permissions.disableBypass must be true")
	}
	for _, w := range widenings(p, rp) {
		bad("%s widens the ring profile: adds %v", w.field, w.added)
	}
	for _, d := range rp.Permissions.Deny {
		if !slices.Contains(p.Permissions.Deny, d) {
			bad("permissions.deny drops ring rule %q", d)
		}
	}
	for _, d := range rp.MCP.Denied {
		if !slices.Contains(p.MCP.Denied, d) {
			bad("mcp.denied drops ring entry %q", d)
		}
	}
	for _, s := range p.MCP.Servers {
		if !slices.ContainsFunc(rp.MCP.Servers, func(r MCPServer) bool {
			return r.Name == s.Name && r.URL == s.URL && slices.Equal(r.Command, s.Command)
		}) {
			bad("mcp.servers adds or changes %q", s.Name)
		}
	}
	for _, f := range []struct {
		field         string
		ring, variant bool
	}{
		{"permissions.sandboxRequired", rp.Permissions.SandboxRequired, p.Permissions.SandboxRequired},
		{"mcp.managedOnly", rp.MCP.ManagedOnly, p.MCP.ManagedOnly},
		{"hooks.managedOnly", rp.Hooks.ManagedOnly, p.Hooks.ManagedOnly},
		{"models.enforce", rp.Models.Enforce, p.Models.Enforce},
	} {
		if f.ring && !f.variant {
			bad("%s is true on the ring profile and must stay true", f.field)
		}
	}
	if rs := rp.Permissions.Sandbox; rs != "" && rs != "off" && (p.Permissions.Sandbox == "" || p.Permissions.Sandbox == "off") {
		bad("permissions.sandbox %q relaxes the ring's %q", p.Permissions.Sandbox, rs)
	}
	if rp.Permissions.Sandbox == "read-only" && p.Permissions.Sandbox == "workspace-write" {
		bad(`permissions.sandbox "workspace-write" relaxes the ring's "read-only"`)
	}
	if permissiveness(p.Permissions.Mode) > permissiveness(rp.Permissions.Mode) {
		bad("permissions.mode %q is more permissive than the ring's %q", p.Permissions.Mode, rp.Permissions.Mode)
	}
	for _, h := range p.Hooks.Hooks {
		if !slices.Contains(rp.Hooks.Hooks, h) {
			bad("hooks.items adds hook %q (%s) not on the ring profile", h.Command, h.Event)
		}
	}
	if p.Telemetry.OTLPEndpoint != rp.Telemetry.OTLPEndpoint {
		bad("telemetry.otlpEndpoint %q must equal the ring's %q", p.Telemetry.OTLPEndpoint, rp.Telemetry.OTLPEndpoint)
	}
	if p.Telemetry.LogPrompts != rp.Telemetry.LogPrompts {
		bad("telemetry.logPrompts %t must equal the ring's %t", p.Telemetry.LogPrompts, rp.Telemetry.LogPrompts)
	}
	if len(rp.Models.Allowed) > 0 { // an empty ring list means unrestricted
		if len(p.Models.Allowed) == 0 {
			bad("models.allowed is empty and lifts the ring's restriction")
		}
		for _, m := range p.Models.Allowed {
			if !slices.Contains(rp.Models.Allowed, m) {
				bad("models.allowed adds %q beyond the ring's list", m)
			}
		}
		if p.Models.Default != "" && !slices.Contains(rp.Models.Allowed, p.Models.Default) {
			bad("models.default %q is not in the ring's models.allowed", p.Models.Default)
		}
	}
	if p.Instructions != rp.Instructions {
		bad("instructions must equal the ring profile's")
	}
	if !maps.Equal(p.Env, rp.Env) {
		bad("env must equal the ring profile's")
	}
	return out
}

// permissiveness ranks permissions.mode: plan < default < acceptEdits < auto.
// Empty means default; an unknown mode ranks above auto so it is never accepted.
func permissiveness(mode string) int {
	switch mode {
	case "plan":
		return 0
	case "", "default":
		return 1
	case "acceptEdits":
		return 2
	case "auto":
		return 3
	}
	return 4
}

var (
	varRef     = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}`)
	awsKeyRe   = regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)
	tokenSplit = regexp.MustCompile(`[^A-Za-z0-9+/=_-]+`)
	hexRe      = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	tokPrefix  = []string{"sk-", "ghp_", "gho_", "ghs_", "ghu_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-"}
	pemKeyRe   = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	// vendor tokens are [A-Za-z0-9_-]: split on anything else so "?t=ghp_..." and "/sk-..." are seen
	prefixSplit = regexp.MustCompile(`[^A-Za-z0-9_-]+`)
)

// LooksSecret reports whether v looks like a literal credential (see looksSecret).
func LooksSecret(v string) bool { return looksSecret(v) }

// HasTokenShape reports whether s contains a well-known credential shape
// (vendor token prefixes such as sk-ant-, ghp_, xoxb-; AWS access key ids;
// PEM private key blocks) outside ${VAR} references. It is the low-false-
// positive subset of looksSecret, safe to run over whole rendered files.
func HasTokenShape(s string) bool {
	s = varRef.ReplaceAllString(s, "")
	if awsKeyRe.MatchString(s) || pemKeyRe.MatchString(s) {
		return true
	}
	for _, t := range prefixSplit.Split(s, -1) {
		for _, p := range tokPrefix {
			if strings.HasPrefix(t, p) && len(t) >= len(p)+10 {
				return true
			}
		}
	}
	return false
}

// looksSecret flags literal credentials. ${VAR} / ${VAR:-default} references
// are removed first, so "Bearer ${TOKEN}" is fine.
// ponytail: heuristic (prefixes + >=32-char high-entropy token); a real
// scanner (gitleaks rules) is the upgrade if false negatives matter.
func looksSecret(v string) bool {
	if HasTokenShape(v) {
		return true
	}
	s := varRef.ReplaceAllString(v, "")
	low := strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{"bearer ", "basic ", "token "} {
		if strings.HasPrefix(low, p) && strings.TrimSpace(low[len(p):]) != "" {
			return true
		}
	}
	for _, t := range tokenSplit.Split(s, -1) {
		if len(t) < 32 {
			continue
		}
		if hexRe.MatchString(t) && strings.ContainsAny(t, "0123456789") && strings.ContainsAny(strings.ToLower(t), "abcdef") {
			return true
		}
		if strings.ContainsAny(t, "0123456789") && strings.ToLower(t) != t && strings.ToUpper(t) != t && entropy(t) >= 4.0 {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	var n [256]int
	for i := 0; i < len(s); i++ {
		n[s[i]]++
	}
	var h float64
	for _, c := range n {
		if c > 0 {
			p := float64(c) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// guardSecrets: bundles are world-readable on every machine; credentials must
// be ${VAR} references resolved on the client, never literals.
func guardSecrets(o *Org) []Issue {
	var out []Issue
	checkHeaders := func(path string, s MCPServer) {
		for _, h := range sortedKeys(s.Headers) {
			if looksSecret(s.Headers[h]) {
				out = append(out, gi(SeverityError, path+".headers."+h, "value looks like a literal secret; use a ${VAR} reference"))
			}
		}
	}
	for _, name := range sortedKeys(o.Profiles) {
		p := o.Profiles[name]
		for i, s := range p.MCP.Servers {
			checkHeaders(fmt.Sprintf("profiles[%s].mcp.servers[%d]", name, i), s)
		}
		for _, k := range sortedKeys(p.Env) {
			if looksSecret(p.Env[k]) {
				out = append(out, gi(SeverityError, "profiles["+name+"].env."+k, "value looks like a literal secret; use a ${VAR} reference"))
			}
		}
	}
	for i, s := range o.SelfService.Catalog {
		checkHeaders(fmt.Sprintf("selfService.catalog[%d]", i), s)
	}
	return out
}

// reservedEnvPrefixes are owned by the renderers (gateway routing, auth,
// telemetry, updater); a profile env var could otherwise silently undo them.
var reservedEnvPrefixes = []string{"OTEL_", "ANTHROPIC_", "CLAUDE_CODE_", "DISABLE_", "CODEX_", "GEMINI_", "GOOGLE_GEMINI_"}

// envMergedByRenderer are reserved names a profile may still set: the renderer
// merges them with its own value instead of replacing it (Claude Code keeps a
// company gateway's headers and appends x-halo-ring/x-halo-release, rejecting
// CR and x-halo-* lines in the profile's part).
var envMergedByRenderer = []string{"ANTHROPIC_CUSTOM_HEADERS"}

// CheckCustomHeaders validates a profile's newline-separated
// ANTHROPIC_CUSTOM_HEADERS: no CR (header injection) and no x-halo-* header,
// which only Halos sets.
func CheckCustomHeaders(v string) error {
	for _, l := range strings.Split(strings.TrimRight(v, "\n"), "\n") {
		if strings.Contains(l, "\r") {
			return fmt.Errorf("a header line contains CR")
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "x-halo-") {
			return fmt.Errorf("%q is set by Halos only", strings.TrimSpace(strings.SplitN(l, ":", 2)[0]))
		}
	}
	return nil
}

func guardEnvKeys(o *Org) []Issue {
	var out []Issue
	for _, name := range sortedKeys(o.Profiles) {
		for _, k := range sortedKeys(o.Profiles[name].Env) {
			if slices.Contains(envMergedByRenderer, k) { // exact name: a different case would not be merged
				if err := CheckCustomHeaders(o.Profiles[name].Env[k]); err != nil {
					out = append(out, gi(SeverityError, "profiles["+name+"].env."+k, "%v", err))
				}
				continue
			}
			for _, pre := range reservedEnvPrefixes {
				if strings.HasPrefix(strings.ToUpper(k), pre) {
					out = append(out, gi(SeverityError, "profiles["+name+"].env."+k, "env prefix %s is reserved for the renderer", pre))
					break
				}
			}
		}
	}
	return out
}
