package policy

import (
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Simple is halos.yaml's simple mode: a handful of intent-level fields that
// Load expands, deterministically and in memory, into the Gateway, the
// "default" Profile and the preset Rings. Explicit documents of the same
// kind/name are overlaid on the expansion field by field (see overlay), so a
// repo can drop to full power one document at a time; `halo explain` prints
// the result and `halo eject` writes it out.
type Simple struct {
	// Tools enables harnesses, each pinned to an exact CLI version: a bare
	// version, or {version, model} where model is one of the Models aliases
	// that tool starts on instead of "default" (e.g. codex on an OpenAI model).
	Tools map[string]ToolSpec `yaml:"tools,omitempty" json:"tools,omitempty"`
	// Provider is where models run: a name (anthropic | bedrock | vertex |
	// openai | gemini | multi) or {name, region, project, url}.
	Provider *Provider `yaml:"provider,omitempty" json:"provider,omitempty"`
	// Models maps an alias (what clients ask for; "default" is required) to a
	// provider model id, or to a list of ids tried in failover order. An id may
	// be prefixed "<provider>/" to pick another provider (required with multi).
	Models map[string]ModelChoice `yaml:"models,omitempty" json:"models,omitempty"`
	// Gateway is the base URL clients are pointed at (halo-proxy).
	Gateway string `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	// Telemetry is the OTLP/HTTP endpoint (telemetry is always on).
	Telemetry string `yaml:"telemetry,omitempty" json:"telemetry,omitempty"`
	// Team is ring0: IdP groups, or user ids containing "@". Default:
	// identity.adminGroups, else "<org>-ai-platform".
	Team []string `yaml:"team,omitempty" json:"team,omitempty"`
	// Safety preset: strict | standard (default) | relaxed. None bypasses permissions.
	Safety string `yaml:"safety,omitempty" json:"safety,omitempty"`
	// Rollout preset: fast | standard (default) | careful. Sets the rings and
	// the step template `halo upgrade start` and `halo model switch --canary` use.
	Rollout string `yaml:"rollout,omitempty" json:"rollout,omitempty"`
}

// Enabled reports whether any simple-mode field is set.
func (s *Simple) Enabled() bool { return !reflect.ValueOf(*s).IsZero() }

// ToolSpec is one tool's pin and, optionally, its own default model alias.
type ToolSpec struct {
	Version string `yaml:"version" json:"version"`
	Model   string `yaml:"model,omitempty" json:"model,omitempty"`
}

// UnmarshalYAML accepts a bare version or {version, model}, strictly.
func (t *ToolSpec) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		t.Version = n.Value
		return nil
	}
	if err := strictKeys(n, "tool", "version", "model"); err != nil {
		return err
	}
	type plain ToolSpec
	return n.Decode((*plain)(t))
}

// strictKeys rejects a non-mapping or any key outside keys (custom
// unmarshalers do not inherit the decoder's KnownFields).
func strictKeys(n *yaml.Node, what string, keys ...string) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: %s must be a scalar or a mapping", n.Line, what)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; !slices.Contains(keys, k.Value) {
			return fmt.Errorf("line %d: field %s not found in %s (want %v)", k.Line, k.Value, what, keys)
		}
	}
	return nil
}

// Provider names a model provider and its settings.
type Provider struct {
	Name    string `yaml:"name" json:"name"`
	Region  string `yaml:"region,omitempty" json:"region,omitempty"`
	Project string `yaml:"project,omitempty" json:"project,omitempty"`
	URL     string `yaml:"url,omitempty" json:"url,omitempty"`
}

// UnmarshalYAML accepts a bare name or a mapping, strictly (unknown keys are errors).
func (p *Provider) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		p.Name = n.Value
		return nil
	}
	if err := strictKeys(n, "provider", "name", "region", "project", "url"); err != nil {
		return err
	}
	type plain Provider
	return n.Decode((*plain)(p))
}

// ModelChoice is one model id, or several in failover order.
type ModelChoice []string

// UnmarshalYAML accepts a scalar or a list of scalars.
func (m *ModelChoice) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*m = ModelChoice{n.Value}
		return nil
	case yaml.SequenceNode:
		var s []string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*m = s
		return nil
	}
	return fmt.Errorf("line %d: a model is an id or a list of ids (failover order)", n.Line)
}

// Simple-mode names. The profile every generated ring uses is SimpleProfile.
const (
	SimpleProfile  = "default"
	ProviderMulti  = "multi"
	SafetyStrict   = "strict"
	SafetyStandard = "standard"
	SafetyRelaxed  = "relaxed"
)

// SimpleGatewayName is the generated Gateway document's name.
func SimpleGatewayName(org string) string { return org + "-gateway" }

// providerDefaults are the upstreams a provider name expands to.
var providerDefaults = map[string]Upstream{
	"anthropic": {URL: "https://api.anthropic.com", Kind: "anthropic"},
	"bedrock":   {Kind: "bedrock", Region: "us-east-1"},
	"vertex":    {Kind: "vertex", Region: "global"},
	"openai":    {URL: "https://api.openai.com", Kind: "openai", Credential: &Credential{Env: "OPENAI_API_KEY"}},
	"gemini":    {URL: "https://generativelanguage.googleapis.com", Kind: "gemini"},
}

// toolProtocols is the wire each harness speaks to the gateway.
var toolProtocols = map[string]string{"claude-code": "anthropic-messages", "codex": "openai-responses", "gemini-cli": "gemini"}

// providerWires are the client wires each provider answers natively.
// KindServes is what halo-proxy can forward, and a pass-through upstream
// forwards any wire, but e.g. api.anthropic.com cannot answer OpenAI Responses.
var providerWires = map[string][]string{
	"anthropic": {"anthropic-messages"},
	"bedrock":   {"anthropic-messages", "bedrock-invoke"},
	"vertex":    {"anthropic-messages"},
	"openai":    {"openai-responses"},
	"gemini":    {"gemini"},
}

// ponytail: one table of vendor defaults for `halo init`; bump the ids here
// when a vendor ships a new default model.
var (
	// toolVendor is the provider/model a tool starts on when the org's
	// provider cannot answer its wire.
	toolVendor = map[string]string{"claude-code": "anthropic/claude-sonnet-4-5", "codex": "openai/gpt-5-codex", "gemini-cli": "gemini/gemini-2.5-pro"}
	// providerModel is the default alias's model per provider.
	providerModel = map[string]string{"anthropic": "claude-sonnet-4-5", "bedrock": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"vertex": "claude-sonnet-4-5@20250929", "openai": "gpt-5", "gemini": "gemini-2.5-pro", ProviderMulti: "anthropic/claude-sonnet-4-5"}
)

// DefaultModelFor is the model `halo init` gives the default alias on provider.
func DefaultModelFor(provider string) string { return providerModel[provider] }

// ToolModelFor reports whether tool needs its own start model because
// defaultID (the default alias's model, on provider) runs on a provider that
// cannot answer the tool's wire, and if so the vendor model to use
// ("<provider>/<model>"). Tools the gateway does not route (copilot-cli)
// never need one.
func ToolModelFor(tool, provider, defaultID string) (string, bool) {
	wire, routed := toolProtocols[tool]
	if !routed {
		return "", false
	}
	up, _ := SplitModel(defaultID, provider)
	if slices.Contains(providerWires[up], wire) {
		return "", false
	}
	return toolVendor[tool], true
}

// ServesNatively reports whether upstream provider kind answers tool's wire
// (true for tools the gateway does not route).
func ServesNatively(tool, kind string) bool {
	wire, routed := toolProtocols[tool]
	return !routed || slices.Contains(providerWires[kind], wire)
}

// secretDenies keep every preset away from common credential files.
var secretDenies = []string{"Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)", "Read(~/.aws/**)", "Read(~/.ssh/**)"}

// SafetyPreset returns the permission, MCP and hook settings of preset name
// ("" = standard). No preset ever sets bypassPermissions, and all set disableBypass.
func SafetyPreset(name string) (Permissions, bool, error) {
	p := Permissions{Mode: "default", DisableBypass: true, Sandbox: "workspace-write", Deny: slices.Clone(secretDenies)}
	switch name {
	case SafetyStrict:
		p.SandboxRequired = true
		p.Deny = append(p.Deny, "Read(~/.kube/**)", "Read(~/.config/gcloud/**)", "Read(**/*.pem)", "Read(**/*.key)")
		return p, true, nil
	case "", SafetyStandard:
		return p, true, nil
	case SafetyRelaxed:
		p.Mode = "acceptEdits"
		return p, false, nil
	}
	return Permissions{}, false, fmt.Errorf("safety %q: want strict, standard or relaxed", name)
}

// strictEgress is the strict preset's allowlist beyond the gateway and telemetry hosts.
var strictEgress = []string{"github.com", "*.githubusercontent.com", "registry.npmjs.org", "proxy.golang.org", "pypi.org", "files.pythonhosted.org"}

// RolloutPreset is a named ring layout plus the step template intent commands
// stamp into Rollouts. Rings carry no team members (Expand fills ring0).
type RolloutPreset struct {
	Name  string
	Rings []Ring
	// Canary is the treatment ramp on the backing experiment, in order.
	Canary []RolloutStep
	// TeamBake is the bake on ring0; RingBake on each later ring before GA.
	TeamBake, RingBake string
}

func presetRing(name string, order int, m Membership) Ring {
	return Ring{Meta: Meta{APIVersion: APIVersion, Kind: KindRing, Name: name}, Order: order, Profile: SimpleProfile, Membership: m}
}

func canary(pct float64, bake string, n int) RolloutStep {
	return RolloutStep{Name: fmt.Sprintf("canary-%g", pct), Strategy: StrategyCanary, Percent: pct, Bake: bake, MinSamples: n}
}

// RolloutPresets are fast, standard and careful.
var RolloutPresets = map[string]RolloutPreset{
	"fast": {Name: "fast", TeamBake: "4h", RingBake: "1d",
		Rings:  []Ring{presetRing("ring0-team", 0, Membership{}), presetRing("ring1-ga", 1, Membership{Default: true})},
		Canary: []RolloutStep{canary(25, "4h", 100)}},
	"standard": {Name: "standard", TeamBake: "1d", RingBake: "2d",
		Rings: []Ring{presetRing("ring0-team", 0, Membership{}), presetRing("ring1-canary", 1, Membership{Percent: 5}),
			presetRing("ring2-early", 2, Membership{Percent: 25}), presetRing("ring3-ga", 3, Membership{Default: true})},
		Canary: []RolloutStep{canary(5, "12h", 200), canary(25, "1d", 500), canary(50, "1d", 1000)}},
	"careful": {Name: "careful", TeamBake: "2d", RingBake: "3d",
		Rings: []Ring{presetRing("ring0-team", 0, Membership{}), presetRing("ring1-canary", 1, Membership{Percent: 1}),
			presetRing("ring2-early", 2, Membership{Percent: 5}), presetRing("ring3-broad", 3, Membership{Percent: 25}),
			presetRing("ring4-ga", 4, Membership{Default: true})},
		Canary: []RolloutStep{canary(1, "1d", 200), canary(5, "2d", 500), canary(25, "2d", 2000), canary(50, "3d", 4000)}},
}

// LookupRolloutPreset returns preset name ("" = standard).
func LookupRolloutPreset(name string) (RolloutPreset, error) {
	if name == "" {
		name = "standard"
	}
	p, ok := RolloutPresets[name]
	if !ok {
		return RolloutPreset{}, fmt.Errorf("rollout %q: want fast, standard or careful", name)
	}
	return p, nil
}

// Expand returns the documents simple mode generates for root: the Gateway,
// the "default" Profile and the preset Rings. It is pure and deterministic;
// the result still has to pass Validate (Load overlays explicit documents first).
func (r *Root) Expand() (*Org, error) {
	s := r.Simple
	perms, managed, err := SafetyPreset(s.Safety)
	if err != nil {
		return nil, err
	}
	rp, err := LookupRolloutPreset(s.Rollout)
	if err != nil {
		return nil, err
	}
	g, err := r.expandGateway()
	if err != nil {
		return nil, err
	}

	p := &Profile{Meta: Meta{APIVersion: APIVersion, Kind: KindProfile, Name: SimpleProfile},
		Harnesses: map[string]HarnessSpec{}, Permissions: perms,
		MCP: MCP{ManagedOnly: managed}, Hooks: Hooks{ManagedOnly: managed},
		Telemetry: Telemetry{Enabled: true, OTLPEndpoint: s.Telemetry}}
	for _, t := range sortedKeys(s.Tools) {
		ts := s.Tools[t]
		if _, ok := s.Models[ts.Model]; ts.Model != "" && !ok {
			return nil, fmt.Errorf("tools.%s.model: %q is not one of the models aliases %v", t, ts.Model, sortedKeys(s.Models))
		}
		p.Harnesses[t] = HarnessSpec{Version: ts.Version, Model: ts.Model}
	}
	if s.Telemetry != "" {
		p.Telemetry.Protocol = "http/protobuf"
	}
	if len(s.Models) > 0 {
		p.Models = Models{Default: "default", Allowed: sortedKeys(s.Models), Enforce: true}
	}
	if s.Safety == SafetyStrict {
		for _, u := range []string{s.Gateway, s.Telemetry} {
			if h := host(u); h != "" && !slices.Contains(p.Egress.AllowedDomains, h) {
				p.Egress.AllowedDomains = append(p.Egress.AllowedDomains, h)
			}
		}
		p.Egress.AllowedDomains = append(p.Egress.AllowedDomains, strictEgress...)
	}

	team := Membership{}
	members := s.Team
	if len(members) == 0 {
		members = r.Identity.AdminGroups
	}
	if len(members) == 0 {
		members = []string{r.Org + "-ai-platform"}
	}
	for _, m := range members {
		if strings.Contains(m, "@") {
			team.Users = append(team.Users, m)
		} else {
			team.Groups = append(team.Groups, m)
		}
	}
	org := &Org{Name: r.Org, Gateway: g, Profiles: map[string]*Profile{SimpleProfile: p}}
	for i, ring := range rp.Rings {
		if i == 0 {
			ring.Membership = team
		}
		org.Rings = append(org.Rings, &ring)
	}
	return org, nil
}

func host(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Hostname()
	}
	return ""
}

func (r *Root) expandGateway() (*Gateway, error) {
	s := r.Simple
	g := &Gateway{Meta: Meta{APIVersion: APIVersion, Kind: KindGateway, Name: SimpleGatewayName(r.Org)},
		BaseURL: s.Gateway, Protocols: map[string]string{}, Models: map[string]ModelRoute{}, Upstreams: map[string]Upstream{}}
	for t := range s.Tools {
		if pr, ok := toolProtocols[t]; ok {
			g.Protocols[t] = pr
		}
	}
	def := ""
	if s.Provider != nil {
		def = s.Provider.Name
		if _, ok := providerDefaults[def]; !ok && def != ProviderMulti {
			return nil, fmt.Errorf("provider %q: want anthropic, bedrock, vertex, openai, gemini or multi", def)
		}
	}
	upstream := func(name string) error {
		if _, done := g.Upstreams[name]; done {
			return nil
		}
		u := providerDefaults[name]
		if s.Provider != nil && s.Provider.Name == name {
			if s.Provider.Region != "" {
				u.Region = s.Provider.Region
			}
			u.Project, u.URL = s.Provider.Project, cmpOr(s.Provider.URL, u.URL)
		}
		if u.Kind == "bedrock" && u.URL == "" {
			u.URL = "https://bedrock-runtime." + u.Region + ".amazonaws.com"
		}
		if u.Kind == "vertex" && u.Project == "" {
			return fmt.Errorf("provider vertex needs a project: provider: {name: vertex, project: <gcp-project>, region: <region>}")
		}
		g.Upstreams[name] = u
		return nil
	}
	if len(s.Models) > 0 {
		if _, ok := s.Models["default"]; !ok {
			return nil, fmt.Errorf("models: a %q alias is required (the model every tool starts on)", "default")
		}
	}
	for _, alias := range sortedKeys(s.Models) {
		ids := s.Models[alias]
		if len(ids) == 0 {
			return nil, fmt.Errorf("models.%s: no model id", alias)
		}
		var ts []RouteTarget
		for i, id := range ids {
			up, model := SplitModel(id, def)
			if up == "" || up == ProviderMulti {
				return nil, fmt.Errorf("models.%s: %q names no provider: set provider, or prefix the id as <provider>/<model>", alias, id)
			}
			if err := upstream(up); err != nil {
				return nil, err
			}
			ts = append(ts, RouteTarget{Upstream: up, Model: model, Priority: i})
		}
		if len(ts) == 1 {
			g.Models[alias] = ModelRoute{Upstream: ts[0].Upstream, Model: ts[0].Model}
		} else {
			g.Models[alias] = ModelRoute{Targets: ts}
		}
	}
	return g, nil
}

// SplitModel splits "<provider>/<model>" when the prefix is a known provider
// (Bedrock ARNs keep their slashes); otherwise the model runs on def.
func SplitModel(id, def string) (provider, model string) {
	if p, m, ok := strings.Cut(id, "/"); ok {
		if _, known := providerDefaults[p]; known {
			return p, m
		}
	}
	return def, id
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// overlaySimple puts the simple-mode expansion of root under org's explicit
// documents: an explicit Gateway, Profile or Ring with a generated name is
// merged over the generated one (explicit wins field by field; gateway models
// and upstreams are replaced per key; profile deny lists and hooks only
// accumulate, as with extends). Anything else is added alongside.
func overlaySimple(root *Root, org *Org) error {
	gen, err := root.Expand()
	if err != nil {
		return err
	}
	if e := org.Gateway; e != nil {
		g := gen.Gateway
		mergeValue(reflect.ValueOf(g).Elem(), reflect.ValueOf(e).Elem())
		for k, v := range e.Models {
			g.Models[k] = v
		}
		for k, v := range e.Upstreams {
			g.Upstreams[k] = v
		}
	}
	org.Gateway = gen.Gateway
	for name, p := range gen.Profiles {
		if e, ok := org.Profiles[name]; ok {
			deny, denied, hooks := p.Permissions.Deny, p.MCP.Denied, p.Hooks.Hooks
			mergeValue(reflect.ValueOf(p).Elem(), reflect.ValueOf(e).Elem())
			p.Permissions.Deny = unionAppend(deny, e.Permissions.Deny)
			p.MCP.Denied = unionAppend(denied, e.MCP.Denied)
			p.Hooks.Hooks = unionAppend(hooks, e.Hooks.Hooks)
		}
		org.Profiles[name] = p
	}
	for _, r := range gen.Rings {
		if i := slices.IndexFunc(org.Rings, func(e *Ring) bool { return e.Name == r.Name }); i >= 0 {
			mergeValue(reflect.ValueOf(r).Elem(), reflect.ValueOf(org.Rings[i]).Elem())
			org.Rings[i] = r
		} else {
			org.Rings = append(org.Rings, r)
		}
	}
	return nil
}
