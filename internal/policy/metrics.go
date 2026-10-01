package policy

// SignalSource is where a registry metric's values come from.
type SignalSource string

const (
	// SourceOnlineCLI: the harness's own OTEL export (metrics and log events),
	// attributed to a cohort by the halo.* resource attributes the profile sets.
	SourceOnlineCLI SignalSource = "online-cli"
	// SourceOnlineGateway: halo-proxy's per-request OTLP metrics. The gateway
	// assigns ring/variant itself, so it is the only online source for
	// traffic-axis experiments (the CLI never learns a gateway-assigned variant).
	SourceOnlineGateway SignalSource = "online-gateway"
	// SourceEval: offline replay (`halo eval`) only; never observed on live traffic.
	SourceEval SignalSource = "eval"
)

// MetricDef is a normalised halo.* metric. The telemetry collector maps each
// harness's native signal (Sources, keyed by adapter name) onto Name.
type MetricDef struct {
	Name        string
	Unit        string // unit of the value, e.g. ratio, ms, usd
	Description string
	Sources     map[string]string
	// Source lists where values come from. When a metric has both online
	// sources, internal/promote prefers the gateway for an experiment that has
	// gateway data (exact cohort attribution), else the CLI events.
	Source []SignalSource
	// PerUnit defines one analysis sample: experiments compare the per-unit
	// values of the two arms. CLI unit = user.id (Codex: user.account_id, else
	// conversation.id; Gemini: installation.id); gateway unit = salted hash
	// of the session id (else of the verified subject).
	PerUnit string
}

// MetricRegistry lists every metric experiments may reference; Validate
// rejects names not in this list.
var MetricRegistry = []MetricDef{
	{Name: "halo.task.success", Unit: "ratio", Description: "Fraction of tasks that ended successfully (eval verdict).",
		Sources: map[string]string{"claude-code": "halo eval trial verdict", "codex": "halo eval trial verdict", "gemini-cli": "halo eval trial verdict"},
		Source:  []SignalSource{SourceEval}, PerUnit: "one eval trial (pass = 1)"},
	{Name: "halo.cost.usd_per_session", Unit: "usd", Description: "Model spend per session.",
		Sources: map[string]string{"claude-code": "claude_code.cost.usage", "codex": "codex.api_request events (tokens x price)", "gemini-cli": "gemini_cli.api_response (tokens x price)"},
		Source:  []SignalSource{SourceOnlineCLI}, PerUnit: "unit's total halo.cost.usd / its distinct sessions"},
	{Name: "halo.tokens.per_session", Unit: "tokens", Description: "Input+output tokens per session.",
		Sources: map[string]string{"claude-code": "claude_code.token.usage", "codex": "codex.api_request events", "gemini-cli": "gemini_cli.token.usage"},
		Source:  []SignalSource{SourceOnlineCLI}, PerUnit: "unit's input+output halo.tokens / its distinct sessions"},
	{Name: "halo.api.error_rate", Unit: "ratio", Description: "Fraction of model API requests that failed (non-2xx or stream error).",
		Sources: map[string]string{"claude-code": "claude_code.api_error / (claude_code.api_request + claude_code.api_error) events", "codex": "codex.api_request events (http.response.status_code, error.message)", "gemini-cli": "gemini_cli.api_error / (gemini_cli.api_response + gemini_cli.api_error)", "gateway": "halo.gateway.requests{status_class!=2xx} / halo.gateway.requests"},
		Source:  []SignalSource{SourceOnlineGateway, SourceOnlineCLI}, PerUnit: "unit's failed / total model API requests"},
	{Name: "halo.edit.accept_rate", Unit: "ratio", Description: "Fraction of proposed code edits the user accepted.",
		Sources: map[string]string{"claude-code": "claude_code.code_edit_tool.decision", "codex": "codex.tool_decision events", "gemini-cli": "gemini_cli.tool_call (decision)"},
		Source:  []SignalSource{SourceOnlineCLI}, PerUnit: "unit's accepted / total edit decisions"},
	{Name: "halo.latency.p50_ms", Unit: "ms", Description: "Median latency of successful model requests.",
		Sources: map[string]string{"claude-code": "claude_code.api_request duration_ms", "codex": "codex.api_request duration_ms (2xx)", "gemini-cli": "gemini_cli.api_response duration_ms", "gateway": "halo.gateway.latency_ms{status_class=2xx} histogram"},
		Source:  []SignalSource{SourceOnlineGateway, SourceOnlineCLI}, PerUnit: "median over the unit's successful requests (gateway: interpolated from histogram buckets)"},
	{Name: "halo.latency.p95_ms", Unit: "ms", Description: "95th percentile latency of successful model requests.",
		Sources: map[string]string{"claude-code": "claude_code.api_request duration_ms", "codex": "codex.api_request duration_ms (2xx)", "gemini-cli": "gemini_cli.api_response duration_ms", "gateway": "halo.gateway.latency_ms{status_class=2xx} histogram"},
		Source:  []SignalSource{SourceOnlineGateway, SourceOnlineCLI}, PerUnit: "p95 over the unit's successful requests (gateway: interpolated from histogram buckets)"},
	{Name: "halo.session.duration_s", Unit: "s", Description: "Wall-clock session length.",
		Sources: map[string]string{"claude-code": "claude_code.active_time.total", "codex": "codex.session events", "gemini-cli": "gemini_cli.session events"},
		PerUnit: "not yet derived: no online source"},
	{Name: "halo.tool.error_rate", Unit: "ratio", Description: "Fraction of tool calls that errored.",
		Sources: map[string]string{"claude-code": "claude_code.tool_result events (success)", "codex": "codex.tool_result events (success)", "gemini-cli": "gemini_cli.tool_call (success)"},
		Source:  []SignalSource{SourceOnlineCLI}, PerUnit: "unit's failed / total tool calls"},
}

// KnownMetric reports whether name is in MetricRegistry.
func KnownMetric(name string) bool {
	_, ok := LookupMetric(name)
	return ok
}

// LookupMetric returns the registry entry for name.
func LookupMetric(name string) (MetricDef, bool) {
	for _, m := range MetricRegistry {
		if m.Name == name {
			return m, true
		}
	}
	return MetricDef{}, false
}

// HasSource reports whether the metric can be measured by s.
func (m MetricDef) HasSource(s SignalSource) bool {
	for _, x := range m.Source {
		if x == s {
			return true
		}
	}
	return false
}
