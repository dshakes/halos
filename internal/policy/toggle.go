package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// KindToggle is a feature toggle document: one capability a platform team can
// turn on for a targeted cohort, and kill instantly, without a new release.
const KindToggle Kind = "Toggle"

// ToggleDateLayout is the layout of Toggle.Expires.
const ToggleDateLayout = "2006-01-02"

// ToggleSaltPrefix namespaces percent-rollout hashing per toggle, so a toggle's
// cohort is independent of the ring and of every experiment (see internal/assign).
const ToggleSaltPrefix = "halos/toggles/"

// Toggle effects for ToggleRule.Effect.
const (
	EffectOn  = "on"
	EffectOff = "off"
)

// Toggle is a named switch with ordered targeting rules.
type Toggle struct {
	Meta        `yaml:",inline"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Owner is the team or person who answers for this toggle (required).
	Owner string `yaml:"owner" json:"owner"`
	// Expires (YYYY-MM-DD) is when the toggle should be removed; past it, validate warns.
	Expires string `yaml:"expires,omitempty" json:"expires,omitempty"`
	// Default is the state when no rule matches.
	Default bool `yaml:"default" json:"default"`
	// Axis: client = a settings fragment delivered in the signed release;
	// traffic = a model route switch applied by the gateway.
	Axis Axis `yaml:"axis" json:"axis"`
	// Rules are evaluated in order; the first rule that matches decides.
	Rules []ToggleRule `yaml:"rules,omitempty" json:"rules,omitempty"`
	// Client is the payload of a client-axis toggle.
	Client *ToggleClient `yaml:"client,omitempty" json:"client,omitempty"`
	// Traffic is the payload of a traffic-axis toggle.
	Traffic *ToggleTraffic `yaml:"traffic,omitempty" json:"traffic,omitempty"`
}

// ToggleRule matches a subject when EVERY condition it sets holds (rings, groups
// and users each match if the subject is in any listed value). A rule with no
// condition matches everyone.
type ToggleRule struct {
	Name   string   `yaml:"name,omitempty" json:"name,omitempty"`
	Rings  []string `yaml:"rings,omitempty" json:"rings,omitempty"`
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	Users  []string `yaml:"users,omitempty" json:"users,omitempty"`
	// Percent (0-100) of the matching subjects, hashed with the toggle's own
	// salt. Omitted = no percent condition; an explicit 0 matches nobody.
	Percent *float64 `yaml:"percent,omitempty" json:"percent,omitempty"`
	// Effect is the state when the rule matches: "on" (default) or "off".
	Effect string `yaml:"effect,omitempty" json:"effect,omitempty"`
}

// ToggleClient maps harness name to the fragment applied when the toggle is on.
type ToggleClient struct {
	Harnesses map[string]TogglePatch `yaml:"harnesses" json:"harnesses"`
}

// TogglePatch is what an "on" client toggle adds to one harness's resolved
// profile. It goes through the same adapter and guardrails as a profile, so an
// unsupported part produces the adapter's warning, never a silent drop.
type TogglePatch struct {
	MCPServers []MCPServer       `yaml:"mcpServers,omitempty" json:"mcpServers,omitempty"`
	Hooks      []Hook            `yaml:"hooks,omitempty" json:"hooks,omitempty"`
	Env        map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	// Overrides are harness-native keys, restricted to the same allowlist as profile overrides.
	Overrides map[string]any `yaml:"overrides,omitempty" json:"overrides,omitempty"`
}

// ToggleTraffic maps a gateway model alias to the route used while the toggle is on.
type ToggleTraffic struct {
	Routes map[string]ModelRoute `yaml:"routes" json:"routes"`
}

// Expired reports whether the toggle's expiry date has passed (a toggle with
// no or an unparsable expiry never expires; validate reports those).
func (t *Toggle) Expired(now time.Time) bool {
	d, err := time.Parse(ToggleDateLayout, t.Expires)
	return err == nil && now.UTC().After(d.AddDate(0, 0, 1))
}

// Apply returns a copy of p with the patch merged in for harness h: servers and
// hooks are appended (deduped), env and overrides merged key by key.
func (tp TogglePatch) Apply(p *Profile, h string) *Profile {
	out := *p
	out.MCP.Servers = slices.Clone(p.MCP.Servers)
	for _, s := range tp.MCPServers {
		if !slices.ContainsFunc(out.MCP.Servers, func(e MCPServer) bool { return e.Name == s.Name }) {
			out.MCP.Servers = append(out.MCP.Servers, s)
		}
	}
	out.Hooks.Hooks = unionAppend(slices.Clone(p.Hooks.Hooks), tp.Hooks)
	out.Env = map[string]string{}
	for k, v := range p.Env {
		out.Env[k] = v
	}
	for k, v := range tp.Env {
		out.Env[k] = v
	}
	out.Harnesses = map[string]HarnessSpec{}
	for k, v := range p.Harnesses {
		out.Harnesses[k] = v
	}
	spec := out.Harnesses[h]
	spec.Overrides = mergeAny(spec.Overrides, tp.Overrides)
	out.Harnesses[h] = spec
	return &out
}

// mergeAny deep-merges src into a copy of dst (maps merge, anything else is replaced).
func mergeAny(dst, src map[string]any) map[string]any {
	out := make(map[string]any, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			dm, _ := out[k].(map[string]any)
			out[k] = mergeAny(dm, sm)
			continue
		}
		out[k] = v
	}
	return out
}

// nowFn is the clock guardToggles uses; tests replace it.
var nowFn = time.Now

// guardToggles validates toggles. Client payloads are held to the same rules as
// profiles: the override allowlist, MCP server shape, secret and reserved-env
// checks, and the permanent ban on bypassPermissions / danger-full-access.
func guardToggles(o *Org) []Issue {
	var out []Issue
	rings := map[string]bool{}
	for _, r := range o.Rings {
		rings[r.Name] = true
	}
	for _, t := range o.Toggles {
		path := "toggles[" + t.Name + "]"
		if !ValidName(t.Name) {
			out = append(out, gi(SeverityError, path+".name", "name %q invalid: must match %s", t.Name, nameRe))
		}
		if t.Owner == "" {
			out = append(out, gi(SeverityError, path+".owner", "owner is required"))
		}
		switch d, err := time.Parse(ToggleDateLayout, t.Expires); {
		case t.Expires == "":
			out = append(out, gi(SeverityWarning, path+".expires", "no expiry date; toggles are temporary, set expires (YYYY-MM-DD)"))
		case err != nil || d.Format(ToggleDateLayout) != t.Expires:
			out = append(out, gi(SeverityError, path+".expires", "%q must be a YYYY-MM-DD date", t.Expires))
		case t.Expired(nowFn()):
			out = append(out, gi(SeverityWarning, path+".expires", "stale: expired %s (owner %s); remove the toggle or extend it", t.Expires, t.Owner))
		}
		for i, r := range t.Rules {
			rp := fmt.Sprintf("%s.rules[%d]", path, i)
			if r.Effect != "" && r.Effect != EffectOn && r.Effect != EffectOff {
				out = append(out, gi(SeverityError, rp+".effect", "%q must be %q or %q", r.Effect, EffectOn, EffectOff))
			}
			if p := r.Percent; p != nil && (*p < 0 || *p > 100) {
				out = append(out, gi(SeverityError, rp+".percent", "%v must be within 0-100", *p))
			} else if p != nil && *p == 0 {
				out = append(out, gi(SeverityWarning, rp+".percent", "percent 0 matches nobody: this rule can never fire"))
			}
			for _, ring := range r.Rings {
				if !rings[ring] {
					out = append(out, gi(SeverityError, rp+".rings", "unknown ring %q", ring))
				}
			}
		}
		switch t.Axis {
		case AxisClient:
			if t.Traffic != nil {
				out = append(out, gi(SeverityError, path+".traffic", "a client-axis toggle cannot carry a traffic payload"))
			}
			out = append(out, guardTogglePayload(path, t.Client)...)
		case AxisTraffic:
			if t.Client != nil {
				out = append(out, gi(SeverityError, path+".client", "a traffic-axis toggle cannot carry a client payload"))
			}
			out = append(out, guardToggleRoutes(o, path, t.Traffic)...)
		default:
			out = append(out, gi(SeverityError, path+".axis", "%q must be %q or %q", t.Axis, AxisClient, AxisTraffic))
		}
	}
	return out
}

func guardTogglePayload(path string, c *ToggleClient) []Issue {
	if c == nil || len(c.Harnesses) == 0 {
		return []Issue{gi(SeverityError, path+".client", "a client-axis toggle needs client.harnesses with at least one harness")}
	}
	var out []Issue
	for _, h := range sortedKeys(c.Harnesses) {
		hp := path + ".client.harnesses." + h
		p := c.Harnesses[h]
		if len(p.MCPServers)+len(p.Hooks)+len(p.Env)+len(p.Overrides) == 0 {
			out = append(out, gi(SeverityError, hp, "empty fragment"))
		}
		for _, k := range disallowedOverrides(h, "", p.Overrides) {
			if _, known := allowedOverrides[h]; !known {
				out = append(out, gi(SeverityError, hp+".overrides."+k, "harness %q accepts no overrides", h))
			} else {
				out = append(out, gi(SeverityError, hp+".overrides."+k, "override key %q is not in the allowlist; request it via adapter support", k))
			}
		}
		for i, s := range p.MCPServers {
			sp := fmt.Sprintf("%s.mcpServers[%d]", hp, i)
			switch {
			case !ValidName(s.Name):
				out = append(out, gi(SeverityError, sp+".name", "name %q invalid: must match %s", s.Name, nameRe))
			case (s.URL == "") == (len(s.Command) == 0):
				out = append(out, gi(SeverityError, sp, "server %q needs exactly one of url or command", s.Name))
			case s.URL != "" && !strings.HasPrefix(s.URL, "https://"):
				out = append(out, gi(SeverityError, sp+".url", "%q must be an https URL", s.URL))
			}
			for _, k := range sortedKeys(s.Headers) {
				if looksSecret(s.Headers[k]) {
					out = append(out, gi(SeverityError, sp+".headers."+k, "value looks like a literal secret; use a ${VAR} reference"))
				}
			}
		}
		for i, hk := range p.Hooks {
			if hk.Event == "" || hk.Command == "" {
				out = append(out, gi(SeverityError, fmt.Sprintf("%s.hooks[%d]", hp, i), "event and command are required"))
			}
		}
		for _, k := range sortedKeys(p.Env) {
			if looksSecret(p.Env[k]) {
				out = append(out, gi(SeverityError, hp+".env."+k, "value looks like a literal secret; use a ${VAR} reference"))
			}
			for _, pre := range reservedEnvPrefixes {
				if strings.HasPrefix(strings.ToUpper(k), pre) {
					out = append(out, gi(SeverityError, hp+".env."+k, "env prefix %s is reserved for the renderer", pre))
					break
				}
			}
		}
		if forbiddenValue(p.Overrides) || forbiddenValue(p.Env) {
			out = append(out, gi(SeverityError, hp, "bypassPermissions / danger-full-access are forbidden by org guardrail"))
		}
	}
	return out
}

// forbiddenValue reports whether any string inside v (a decoded YAML tree)
// names a permission-bypass mode.
func forbiddenValue(v any) bool {
	switch x := v.(type) {
	case string:
		l := strings.ToLower(x)
		return strings.Contains(l, "bypasspermissions") || strings.Contains(l, "danger-full-access")
	case map[string]any:
		for k, e := range x {
			if forbiddenValue(k) || forbiddenValue(e) {
				return true
			}
		}
	case map[string]string:
		for k, e := range x {
			if forbiddenValue(k) || forbiddenValue(e) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(x, forbiddenValue)
	}
	return false
}

func guardToggleRoutes(o *Org, path string, tr *ToggleTraffic) []Issue {
	if tr == nil || len(tr.Routes) == 0 {
		return []Issue{gi(SeverityError, path+".traffic", "a traffic-axis toggle needs traffic.routes")}
	}
	var out []Issue
	for _, alias := range sortedKeys(tr.Routes) {
		rp := path + ".traffic.routes." + alias
		r := tr.Routes[alias]
		if o.Gateway == nil {
			out = append(out, gi(SeverityError, rp, "no Gateway document to route through"))
			continue
		}
		if _, ok := o.Gateway.Models[alias]; !ok {
			out = append(out, gi(SeverityError, rp, "alias %q is not in gateway.models", alias))
		}
		cands := r.Candidates()
		if len(cands) == 0 {
			out = append(out, gi(SeverityError, rp, "route needs upstream+model or targets"))
		}
		for i, c := range cands {
			if _, ok := o.Gateway.Upstreams[c.Upstream]; !ok {
				out = append(out, gi(SeverityError, fmt.Sprintf("%s.targets[%d].upstream", rp, i), "unknown upstream %q", c.Upstream))
			}
			if c.Model == "" {
				out = append(out, gi(SeverityError, fmt.Sprintf("%s.targets[%d].model", rp, i), "model is required"))
			}
		}
	}
	return out
}
