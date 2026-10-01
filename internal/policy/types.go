// Package policy defines Halos's harness-neutral policy model: the
// YAML documents an org keeps in its policy repo, and the in-memory form
// every other package (compiler, gateway, delivery, eval) consumes.
package policy

// APIVersion is the only document version this build understands.
const APIVersion = "halos.dev/v1alpha1"

// Kind names a policy document type.
type Kind string

const (
	KindProfile    Kind = "Profile"
	KindRing       Kind = "Ring"
	KindExperiment Kind = "Experiment"
	KindGateway    Kind = "Gateway"
)

// Meta is common to every document.
type Meta struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       Kind              `yaml:"kind" json:"kind"`
	Name       string            `yaml:"name" json:"name"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Org is the fully loaded policy repo.
type Org struct {
	Name        string
	Identity    Identity
	SelfService SelfService
	Gateway     *Gateway
	Profiles    map[string]*Profile
	Rings       []*Ring // ordered, earliest ring first
	Experiments []*Experiment
	Toggles     []*Toggle `json:",omitempty"` // omitted when empty: existing snapshots keep their digest

	// Rollouts are omitted when empty, like Toggles.
	Rollouts []*Rollout `json:",omitempty"`
}

// Identity is the org's OIDC provider. Any compliant IdP works (Okta, Entra ID,
// Google, Keycloak, Ping, Auth0...). Used by halo-server (portal login),
// halo-proxy / halo-kong (verifying the caller) and halod enrollment.
type Identity struct {
	Issuer   string `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	ClientID string `yaml:"clientID,omitempty" json:"clientID,omitempty"`
	// Audience expected in gateway bearer tokens; defaults to ClientID.
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`
	// UserClaim / GroupsClaim name the JWT claims for subject id and groups.
	UserClaim   string `yaml:"userClaim,omitempty" json:"userClaim,omitempty"`     // default "email"
	GroupsClaim string `yaml:"groupsClaim,omitempty" json:"groupsClaim,omitempty"` // default "groups"
	// AdminGroups may approve requests and manage experiments in the portal.
	AdminGroups []string `yaml:"adminGroups,omitempty" json:"adminGroups,omitempty"`
}

// SelfService configures the developer portal ("kiosk").
type SelfService struct {
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Launchers offered to developers: devcontainer | codespaces | coder | laptop.
	Launchers []string `yaml:"launchers,omitempty" json:"launchers,omitempty"`
	// Requestable items: kinds of access developers may request (approval opens a policy PR).
	Requestable []string `yaml:"requestable,omitempty" json:"requestable,omitempty"` // mcp-server | model | ring-opt-in | harness
	// Catalog lists MCP servers developers may request that aren't in their profile yet.
	Catalog []MCPServer `yaml:"catalog,omitempty" json:"catalog,omitempty"`
	// EnrollmentTTLSeconds bounds one-time laptop bootstrap tokens (default 900).
	EnrollmentTTLSeconds int `yaml:"enrollmentTTLSeconds,omitempty" json:"enrollmentTTLSeconds,omitempty"`
}

// Gateway describes how harness traffic reaches models.
type Gateway struct {
	Meta `yaml:",inline"`
	// BaseURL is what clients are pointed at (Kong's public listener).
	BaseURL string `yaml:"baseURL" json:"baseURL"`
	// Protocol per harness: anthropic-messages | bedrock-invoke | openai-responses | gemini.
	Protocols map[string]string `yaml:"protocols,omitempty" json:"protocols,omitempty"`
	// Auth: how clients obtain a credential for the auth gateway.
	Auth GatewayAuth `yaml:"auth" json:"auth"`
	// Models maps a stable alias (what clients request) to upstream targets.
	Models map[string]ModelRoute `yaml:"models" json:"models"`
	// Upstreams are named backends (e.g. the orchestrator, direct Anthropic).
	Upstreams map[string]Upstream `yaml:"upstreams" json:"upstreams"`
	// Engine is the data plane that enforces this policy: halo-proxy (default)
	// or kong. Multi-target routes (weights, failover) are halo-proxy-only; Kong
	// uses each route's first target.
	Engine string `yaml:"engine,omitempty" json:"engine,omitempty"`
}

type GatewayAuth struct {
	// HelperCommand prints a short-lived token (used as Claude apiKeyHelper, Codex env_key source, ...).
	HelperCommand string `yaml:"helperCommand,omitempty" json:"helperCommand,omitempty"`
	TTLSeconds    int    `yaml:"ttlSeconds,omitempty" json:"ttlSeconds,omitempty"`
	// IdentityHeader is the header the auth gateway sets with the verified user id.
	IdentityHeader string `yaml:"identityHeader,omitempty" json:"identityHeader,omitempty"`
}

// ModelRoute is one alias's routing: either a single upstream+model, or an
// ordered/weighted list of Targets (mutually exclusive).
type ModelRoute struct {
	Upstream string `yaml:"upstream,omitempty" json:"upstream,omitempty"`
	// Model is the provider model id / Bedrock inference profile ARN.
	Model   string        `yaml:"model,omitempty" json:"model,omitempty"`
	Targets []RouteTarget `yaml:"targets,omitempty" json:"targets,omitempty"`
}

// RouteTarget is one provider target of a route. Targets sharing a Priority
// (lower first; default 0) form a tier: within a tier Weight splits traffic
// (sticky per identity+session) and the rest of the tier is the failover order;
// later tiers are tried only after earlier ones fail.
type RouteTarget struct {
	Upstream string  `yaml:"upstream" json:"upstream"`
	Model    string  `yaml:"model" json:"model"`
	Weight   float64 `yaml:"weight,omitempty" json:"weight,omitempty"`
	Priority int     `yaml:"priority,omitempty" json:"priority,omitempty"`
	// TimeoutSeconds bounds connect + wait for response headers (default: the
	// proxy's upstreamHeaderTimeout). Streams are not time-limited afterwards.
	TimeoutSeconds int `yaml:"timeoutSeconds,omitempty" json:"timeoutSeconds,omitempty"`
}

// Candidates returns the route's targets (a single-target route is one).
func (r ModelRoute) Candidates() []RouteTarget {
	if len(r.Targets) > 0 {
		return r.Targets
	}
	if r.Upstream == "" && r.Model == "" {
		return nil
	}
	return []RouteTarget{{Upstream: r.Upstream, Model: r.Model}}
}

// Primary is the route reduced to its first-priority target, for consumers
// that cannot fail over (halo-kong, halo-shadow).
func (r ModelRoute) Primary() ModelRoute {
	best, ok := RouteTarget{}, false
	for _, t := range r.Candidates() {
		if !ok || t.Priority < best.Priority {
			best, ok = t, true
		}
	}
	return ModelRoute{Upstream: best.Upstream, Model: best.Model}
}

type Upstream struct {
	// URL is the base URL. Optional for kind vertex (derived from region).
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
	// Kind: orchestrator | anthropic | bedrock | vertex | openai | azure-openai | gemini
	Kind string `yaml:"kind" json:"kind"`
	// Project is the Google Cloud project id for kind vertex.
	Project string `yaml:"project,omitempty" json:"project,omitempty"`
	// APIVersion is the api-version query for kind azure-openai; empty uses the
	// versionless /openai/v1 surface.
	APIVersion string `yaml:"apiVersion,omitempty" json:"apiVersion,omitempty"`
	// Credential names where halo-proxy reads the provider key (kinds openai,
	// azure-openai). Policy never holds the secret itself.
	Credential *Credential `yaml:"credential,omitempty" json:"credential,omitempty"`
	// Region is the AWS SigV4 region for kind bedrock. halo-proxy signs a
	// bedrock upstream only if its host ends in an AWS suffix (.amazonaws.com,
	// .amazonaws.com.cn, .api.aws) or is listed in the proxy's signHosts; it
	// never signs for other hosts. The region is this value when set, else
	// parsed from the host (e.g. bedrock-runtime.<region>.amazonaws.com).
	Region string `yaml:"region,omitempty" json:"region,omitempty"`
}

// Credential locates a secret on the halo-proxy host: an environment variable
// name or a file path (exactly one). Scheme is api-key (default for
// azure-openai) or bearer (default for openai).
type Credential struct {
	Env    string `yaml:"env,omitempty" json:"env,omitempty"`
	File   string `yaml:"file,omitempty" json:"file,omitempty"`
	Scheme string `yaml:"scheme,omitempty" json:"scheme,omitempty"`
}

// Endpoint is the upstream base URL, deriving the Vertex AI host from Region
// when URL is unset ("global" has no region prefix).
func (u Upstream) Endpoint() string {
	if u.URL == "" && u.Kind == "vertex" && u.Region != "" {
		if u.Region == "global" {
			return "https://aiplatform.googleapis.com"
		}
		return "https://" + u.Region + "-aiplatform.googleapis.com"
	}
	return u.URL
}

// KindServes reports whether an upstream of kind can serve a client speaking
// proto. Pass-through kinds (orchestrator, anthropic, openai, gemini) keep the
// client's wire as-is. bedrock additionally serves anthropic-messages clients
// (the request is translated and the event stream converted back); vertex
// serves only anthropic-messages; azure-openai only openai-responses.
func KindServes(kind, proto string) bool {
	switch kind {
	case "vertex":
		return proto == "anthropic-messages"
	case "bedrock":
		return proto == "bedrock-invoke" || proto == "anthropic-messages"
	case "azure-openai":
		return proto == "openai-responses"
	}
	return true
}

// Profile is desired harness behaviour, independent of any one CLI.
type Profile struct {
	Meta    `yaml:",inline"`
	Extends string `yaml:"extends,omitempty" json:"extends,omitempty"`

	// Harnesses enabled by this profile, keyed by adapter name.
	Harnesses map[string]HarnessSpec `yaml:"harnesses" json:"harnesses"`

	Models      Models      `yaml:"models" json:"models"`
	Permissions Permissions `yaml:"permissions" json:"permissions"`
	MCP         MCP         `yaml:"mcp" json:"mcp"`
	Hooks       Hooks       `yaml:"hooks" json:"hooks"`
	Telemetry   Telemetry   `yaml:"telemetry" json:"telemetry"`
	Egress      Egress      `yaml:"egress" json:"egress"`
	// Instructions is org-wide memory (managed CLAUDE.md / AGENTS.md / GEMINI.md).
	Instructions string `yaml:"instructions,omitempty" json:"instructions,omitempty"`
	// Env is extra environment applied to every harness.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

type HarnessSpec struct {
	// Version is an exact CLI version pin (e.g. "2.1.280"). Required for rings.
	Version string `yaml:"version" json:"version"`
	// Overrides are raw, harness-native keys merged last. Escape hatch; OPA still checks them.
	Overrides map[string]any `yaml:"overrides,omitempty" json:"overrides,omitempty"`
}

type Models struct {
	Default string   `yaml:"default" json:"default"`
	Allowed []string `yaml:"allowed,omitempty" json:"allowed,omitempty"`
	// Enforce rejects models outside Allowed rather than just hiding them.
	Enforce bool `yaml:"enforce,omitempty" json:"enforce,omitempty"`
}

type Permissions struct {
	// Mode: default | acceptEdits | plan | auto
	Mode          string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Allow         []string `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny          []string `yaml:"deny,omitempty" json:"deny,omitempty"`
	Ask           []string `yaml:"ask,omitempty" json:"ask,omitempty"`
	DisableBypass bool     `yaml:"disableBypass,omitempty" json:"disableBypass,omitempty"`
	// Sandbox: harness sandbox policy — off | workspace-write | read-only
	Sandbox string `yaml:"sandbox,omitempty" json:"sandbox,omitempty"`
	// SandboxRequired fails closed: the harness must refuse to run (Claude:
	// sandbox.failIfUnavailable) rather than fall back to unsandboxed
	// execution when its sandbox dependencies are missing.
	SandboxRequired bool `yaml:"sandboxRequired,omitempty" json:"sandboxRequired,omitempty"`
}

type MCP struct {
	// ManagedOnly blocks every server not listed here.
	ManagedOnly bool        `yaml:"managedOnly,omitempty" json:"managedOnly,omitempty"`
	Servers     []MCPServer `yaml:"servers,omitempty" json:"servers,omitempty"`
	Denied      []string    `yaml:"denied,omitempty" json:"denied,omitempty"`
}

type MCPServer struct {
	Name    string            `yaml:"name" json:"name"`
	URL     string            `yaml:"url,omitempty" json:"url,omitempty"`
	Command []string          `yaml:"command,omitempty" json:"command,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type Hooks struct {
	ManagedOnly bool   `yaml:"managedOnly,omitempty" json:"managedOnly,omitempty"`
	Hooks       []Hook `yaml:"items,omitempty" json:"items,omitempty"`
}

type Hook struct {
	// Event: PreToolUse | PostToolUse | SessionStart | Stop | UserPromptSubmit
	Event   string `yaml:"event" json:"event"`
	Matcher string `yaml:"matcher,omitempty" json:"matcher,omitempty"`
	Command string `yaml:"command" json:"command"`
}

type Telemetry struct {
	Enabled      bool              `yaml:"enabled" json:"enabled"`
	OTLPEndpoint string            `yaml:"otlpEndpoint,omitempty" json:"otlpEndpoint,omitempty"`
	Protocol     string            `yaml:"protocol,omitempty" json:"protocol,omitempty"` // grpc | http/protobuf
	LogPrompts   bool              `yaml:"logPrompts,omitempty" json:"logPrompts,omitempty"`
	Attributes   map[string]string `yaml:"attributes,omitempty" json:"attributes,omitempty"`
}

type Egress struct {
	// AllowedDomains is the only egress permitted from managed environments (firewall + harness sandbox).
	AllowedDomains []string `yaml:"allowedDomains,omitempty" json:"allowedDomains,omitempty"`
}

// Ring is an ordered rollout cohort pointing at a profile.
type Ring struct {
	Meta    `yaml:",inline"`
	Order   int    `yaml:"order" json:"order"`
	Profile string `yaml:"profile" json:"profile"`
	// Release pins the ring to an immutable published release digest; empty = build from Profile.
	Release    string     `yaml:"release,omitempty" json:"release,omitempty"`
	Membership Membership `yaml:"membership" json:"membership"`
}

type Membership struct {
	// Users are explicit user ids always in this ring (checked before Groups).
	Users []string `yaml:"users,omitempty" json:"users,omitempty"`
	// Groups are IdP groups always in this ring.
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	// Percent of remaining users hashed into this ring (0-100, basis points precision).
	Percent float64 `yaml:"percent,omitempty" json:"percent,omitempty"`
	// Default marks the catch-all ring (GA).
	Default bool `yaml:"default,omitempty" json:"default,omitempty"`
	// OptIn lets developers join this ring themselves from the portal
	// (recorded as a group membership request; admins may auto-approve).
	OptIn bool `yaml:"optIn,omitempty" json:"optIn,omitempty"`
}

// ExperimentType is how an experiment exposes users.
type ExperimentType string

const (
	ExperimentAB     ExperimentType = "ab"
	ExperimentCanary ExperimentType = "canary"
	ExperimentShadow ExperimentType = "shadow"
)

// Axis is where an experiment's variants differ.
type Axis string

const (
	AxisClient  Axis = "client"  // variants are different profiles/releases on the machine
	AxisTraffic Axis = "traffic" // variants are different model routes at the gateway
)

type Experiment struct {
	Meta   `yaml:",inline"`
	Type   ExperimentType `yaml:"type" json:"type"`
	Axis   Axis           `yaml:"axis" json:"axis"`
	Status string         `yaml:"status,omitempty" json:"status,omitempty"` // draft | running | paused | concluded
	// Rings the experiment draws users from.
	Rings    []string  `yaml:"rings" json:"rings"`
	Variants []Variant `yaml:"variants" json:"variants"`
	// Shadow only: fraction of eligible requests mirrored (0-1).
	SampleRate float64  `yaml:"sampleRate,omitempty" json:"sampleRate,omitempty"`
	Metrics    Metrics  `yaml:"metrics" json:"metrics"`
	Stopping   Stopping `yaml:"stopping" json:"stopping"`
	// Salt keeps assignment independent across experiments; defaults to Name.
	Salt string `yaml:"salt,omitempty" json:"salt,omitempty"`
}

type Variant struct {
	Name string `yaml:"name" json:"name"`
	// Weight is the share of the experiment's users (weights are normalised).
	Weight float64 `yaml:"weight" json:"weight"`
	// Traffic axis: model alias -> route override.
	Routes map[string]ModelRoute `yaml:"routes,omitempty" json:"routes,omitempty"`
	// Client axis: profile to apply.
	Profile string `yaml:"profile,omitempty" json:"profile,omitempty"`
	Control bool   `yaml:"control,omitempty" json:"control,omitempty"`
}

type Metrics struct {
	Primary    MetricGoal   `yaml:"primary" json:"primary"`
	Guardrails []MetricGoal `yaml:"guardrails,omitempty" json:"guardrails,omitempty"`
}

type MetricGoal struct {
	// Metric is a normalised halo.* metric name, e.g. halo.task.success, halo.cost.usd_per_session.
	Metric string `yaml:"metric" json:"metric"`
	// Direction: increase | decrease
	Direction string `yaml:"direction" json:"direction"`
	// MaxRegression (guardrails): relative worsening that aborts, e.g. 0.05 = 5%.
	MaxRegression float64 `yaml:"maxRegression,omitempty" json:"maxRegression,omitempty"`
}

type Stopping struct {
	// Method: msprt | fixed
	Method      string  `yaml:"method" json:"method"`
	Alpha       float64 `yaml:"alpha,omitempty" json:"alpha,omitempty"`
	MinSamples  int     `yaml:"minSamples,omitempty" json:"minSamples,omitempty"`
	MaxDays     int     `yaml:"maxDays,omitempty" json:"maxDays,omitempty"`
	MaxSpendUSD float64 `yaml:"maxSpendUSD,omitempty" json:"maxSpendUSD,omitempty"`
}
