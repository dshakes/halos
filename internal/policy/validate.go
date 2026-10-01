package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
)

// Severity of a validation Issue.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Issue is one validation finding. Path is like "rings[ring1].membership.percent".
type Issue struct {
	Severity Severity
	Path     string
	Message  string
}

func (i Issue) String() string { return fmt.Sprintf("%s: %s: %s", i.Severity, i.Path, i.Message) }

// HasErrors reports whether any issue is an error.
func HasErrors(issues []Issue) bool {
	return slices.ContainsFunc(issues, func(i Issue) bool { return i.Severity == SeverityError })
}

var (
	// Exact semver only: no ranges, no "latest", no leading "v".
	semverRe  = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	awsRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

	knownHarnesses   = []string{"claude-code", "codex", "gemini-cli", "copilot-cli"}
	permissionModes  = []string{"default", "acceptEdits", "plan", "auto"}
	sandboxModes     = []string{"off", "workspace-write", "read-only"}
	protocolNames    = []string{"anthropic-messages", "bedrock-invoke", "openai-responses", "gemini"}
	upstreamKinds    = []string{"orchestrator", "anthropic", "bedrock", "openai", "gemini"}
	hookEvents       = []string{"PreToolUse", "PostToolUse", "SessionStart", "Stop", "UserPromptSubmit"}
	otlpProtocols    = []string{"grpc", "http/protobuf"}
	experimentStatus = []string{"draft", "running", "paused", "concluded"}
	directions       = []string{"increase", "decrease"}
	stoppingMethods  = []string{"msprt", "fixed"}
)

// Validate runs semantic checks over the whole Org, then the default
// guardrails. It never returns nil-vs-empty ambiguity: no issues = empty slice.
func (o *Org) Validate() []Issue {
	v := &validator{org: o, issues: []Issue{}}
	v.gateway()
	v.profiles()
	v.rings()
	v.experiments()
	for _, g := range DefaultGuardrails {
		v.issues = append(v.issues, g(o)...)
	}
	return v.issues
}

type validator struct {
	org    *Org
	issues []Issue
}

func (v *validator) errf(path, format string, a ...any) {
	v.issues = append(v.issues, Issue{SeverityError, path, fmt.Sprintf(format, a...)})
}

func (v *validator) oneOf(path, field, val string, set []string) {
	if !slices.Contains(set, val) {
		v.errf(path, "%s %q invalid, want one of %v", field, val, set)
	}
}

func (v *validator) gateway() {
	g := v.org.Gateway
	if g == nil {
		v.errf("gateway", "no Gateway document defined")
		return
	}
	if u, err := url.Parse(g.BaseURL); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		v.errf("gateway.baseURL", "%q must be an absolute http(s) URL", g.BaseURL)
	}
	for h, p := range g.Protocols {
		v.oneOf("gateway.protocols."+h, "protocol", p, protocolNames)
		if !slices.Contains(knownHarnesses, h) {
			v.errf("gateway.protocols."+h, "unknown harness %q", h)
		}
	}
	for _, name := range sortedKeys(g.Upstreams) {
		up := g.Upstreams[name]
		p := "gateway.upstreams." + name
		if u, err := url.Parse(up.URL); err != nil || u.Host == "" {
			v.errf(p+".url", "%q must be an absolute URL", up.URL)
		}
		v.oneOf(p+".kind", "kind", up.Kind, upstreamKinds)
		if up.Region != "" && (up.Kind != "bedrock" || !awsRegion.MatchString(up.Region)) {
			v.errf(p+".region", "%q: region is only valid on kind bedrock and must look like us-east-1", up.Region)
		}
	}
	for _, alias := range sortedKeys(g.Models) {
		v.route("gateway.models."+alias, g.Models[alias])
	}
}

func (v *validator) route(path string, r ModelRoute) {
	if r.Model == "" {
		v.errf(path+".model", "model is required")
	}
	if v.org.Gateway != nil {
		if _, ok := v.org.Gateway.Upstreams[r.Upstream]; !ok {
			v.errf(path+".upstream", "upstream %q not defined in gateway.upstreams", r.Upstream)
		}
	}
}

func (v *validator) profiles() {
	for _, name := range sortedKeys(v.org.Profiles) {
		path := "profiles[" + name + "]"
		if v.org.Profiles[name].Name != name {
			v.errf(path, "name mismatch")
		}
		p, err := v.org.ResolveProfile(name)
		if err != nil {
			v.errf(path+".extends", "%v", err)
			continue
		}
		for _, h := range sortedKeys(p.Harnesses) {
			if !slices.Contains(knownHarnesses, h) {
				v.errf(path+".harnesses."+h, "unknown harness %q, want one of %v", h, knownHarnesses)
			}
		}
		if p.Models.Enforce && !slices.Contains(p.Models.Allowed, p.Models.Default) {
			v.errf(path+".models.default", "default %q must be in models.allowed when enforce is set", p.Models.Default)
		}
		if g := v.org.Gateway; g != nil {
			for _, m := range append([]string{p.Models.Default}, p.Models.Allowed...) {
				if _, ok := g.Models[m]; !ok && m != "" {
					v.errf(path+".models", "model %q is not a gateway.models alias", m)
				}
			}
		}
		// bypassPermissions is a valid harness mode but forbidden by the
		// no-bypass guardrail, which reports it with a clearer message.
		if m := p.Permissions.Mode; m != "" && m != "bypassPermissions" {
			v.oneOf(path+".permissions.mode", "mode", m, permissionModes)
		}
		if s := p.Permissions.Sandbox; s != "" {
			v.oneOf(path+".permissions.sandbox", "sandbox", s, sandboxModes)
		}
		if p.Permissions.SandboxRequired && p.Permissions.Sandbox == "off" {
			v.errf(path+".permissions.sandboxRequired", `sandboxRequired contradicts permissions.sandbox "off"`)
		}
		for i, h := range p.Hooks.Hooks {
			v.oneOf(fmt.Sprintf("%s.hooks.items[%d].event", path, i), "event", h.Event, hookEvents)
			if h.Command == "" {
				v.errf(fmt.Sprintf("%s.hooks.items[%d].command", path, i), "command is required")
			}
		}
		if pr := p.Telemetry.Protocol; pr != "" {
			v.oneOf(path+".telemetry.protocol", "protocol", pr, otlpProtocols)
		}
	}
}

func (v *validator) rings() {
	orders := map[int]string{}
	userRing := map[string]string{}
	names := map[string]bool{}
	var defaults []string
	var total float64
	for _, r := range v.org.Rings {
		path := "rings[" + r.Name + "]"
		if names[r.Name] {
			v.errf(path, "duplicate ring name")
		}
		names[r.Name] = true
		if prev, dup := orders[r.Order]; dup {
			v.errf(path+".order", "order %d already used by ring %q", r.Order, prev)
		}
		orders[r.Order] = r.Name
		m := r.Membership
		for _, u := range m.Users {
			if prev, dup := userRing[u]; dup {
				v.errf(path+".membership.users", "user %q already listed in ring %q", u, prev)
			}
			userRing[u] = r.Name
		}
		if m.Percent < 0 || m.Percent > 100 {
			v.errf(path+".membership.percent", "%v out of range [0,100]", m.Percent)
		}
		if m.Default {
			defaults = append(defaults, r.Name)
			if m.Percent != 0 {
				v.errf(path+".membership.percent", "default ring takes the remainder; percent must be unset")
			}
		}
		total += m.Percent
		p, err := v.org.ResolveProfile(r.Profile)
		if err != nil {
			v.errf(path+".profile", "%v", err)
			continue
		}
		if len(p.Harnesses) == 0 {
			v.errf(path+".profile", "profile %q enables no harnesses", r.Profile)
		}
		for _, h := range sortedKeys(p.Harnesses) {
			if ver := p.Harnesses[h].Version; !semverRe.MatchString(ver) {
				v.errf(path+".profile.harnesses."+h+".version", "%q must be an exact semver (no ranges, no latest)", ver)
			}
		}
	}
	if total > 100 {
		v.errf("rings", "cumulative percent %v exceeds 100", total)
	}
	if len(defaults) != 1 {
		v.errf("rings", "exactly one ring must be membership.default, found %d %v", len(defaults), defaults)
	}
}

func (v *validator) experiments() {
	names := map[string]bool{}
	rings := map[string]bool{}
	for _, r := range v.org.Rings {
		rings[r.Name] = true
	}
	for _, e := range v.org.Experiments {
		path := "experiments[" + e.Name + "]"
		if names[e.Name] {
			v.errf(path, "duplicate experiment name")
		}
		names[e.Name] = true
		v.oneOf(path+".type", "type", string(e.Type), []string{"ab", "canary", "shadow"})
		v.oneOf(path+".axis", "axis", string(e.Axis), []string{"client", "traffic"})
		if e.Status != "" {
			v.oneOf(path+".status", "status", e.Status, experimentStatus)
		}
		if len(e.Rings) == 0 {
			v.errf(path+".rings", "at least one ring required")
		}
		for _, r := range e.Rings {
			if !rings[r] {
				v.errf(path+".rings", "ring %q not defined", r)
			}
		}
		if e.Type == ExperimentShadow {
			if e.Axis != AxisTraffic {
				v.errf(path+".axis", "shadow experiments must use the traffic axis")
			}
			if e.SampleRate <= 0 || e.SampleRate > 1 {
				v.errf(path+".sampleRate", "%v must be in (0,1]", e.SampleRate)
			}
		}
		v.variants(path, e)
		v.metric(path+".metrics.primary", e.Metrics.Primary)
		for i, g := range e.Metrics.Guardrails {
			v.metric(fmt.Sprintf("%s.metrics.guardrails[%d]", path, i), g)
			if g.MaxRegression < 0 {
				v.errf(fmt.Sprintf("%s.metrics.guardrails[%d].maxRegression", path, i), "must be >= 0")
			}
		}
		v.onlineMetrics(path, e)
		v.oneOf(path+".stopping.method", "method", e.Stopping.Method, stoppingMethods)
		if a := e.Stopping.Alpha; a != 0 && (a <= 0 || a >= 1) {
			v.errf(path+".stopping.alpha", "%v must be in (0,1)", a)
		}
	}
}

func (v *validator) variants(path string, e *Experiment) {
	if len(e.Variants) < 2 && e.Type != ExperimentShadow {
		v.errf(path+".variants", "need at least 2 variants, found %d", len(e.Variants))
	}
	if len(e.Variants) == 0 {
		v.errf(path+".variants", "at least one variant required")
	}
	seen := map[string]bool{}
	controls, withRoutes := 0, 0
	for i, va := range e.Variants {
		vp := fmt.Sprintf("%s.variants[%d]", path, i)
		if va.Name == "" || seen[va.Name] {
			v.errf(vp+".name", "variant name %q empty or duplicate", va.Name)
		}
		seen[va.Name] = true
		if va.Weight <= 0 {
			v.errf(vp+".weight", "%v must be > 0", va.Weight)
		}
		if va.Control {
			controls++
		}
		switch e.Axis {
		case AxisTraffic:
			if len(va.Routes) > 0 {
				withRoutes++
			}
			if va.Profile != "" {
				v.errf(vp+".profile", "traffic-axis variants route models, not profiles")
			}
			for _, alias := range sortedKeys(va.Routes) {
				rp := vp + ".routes." + alias
				if v.org.Gateway != nil {
					if _, ok := v.org.Gateway.Models[alias]; !ok {
						v.errf(rp, "alias %q not defined in gateway.models", alias)
					}
				}
				v.route(rp, va.Routes[alias])
			}
		case AxisClient:
			if len(va.Routes) > 0 {
				v.errf(vp+".routes", "client-axis variants apply profiles, not routes")
			}
			if _, ok := v.org.Profiles[va.Profile]; !ok {
				v.errf(vp+".profile", "profile %q not defined", va.Profile)
			}
		}
	}
	if e.Axis == AxisTraffic && withRoutes == 0 {
		v.errf(path+".variants", "traffic-axis experiment needs at least one variant with routes")
	}
	if (e.Type == ExperimentAB || e.Type == ExperimentCanary) && controls != 1 {
		v.errf(path+".variants", "%s experiments need exactly one control variant, found %d", e.Type, controls)
	}
}

func (v *validator) metric(path string, m MetricGoal) {
	if !KnownMetric(m.Metric) {
		v.errf(path+".metric", "unknown metric %q (see MetricRegistry)", m.Metric)
	}
	v.oneOf(path+".direction", "direction", m.Direction, directions)
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}
