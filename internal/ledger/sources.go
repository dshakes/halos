package ledger

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/vendoradmin"
)

// Window bounds a fetch: Since inclusive, Until exclusive.
type Window struct{ Since, Until time.Time }

// Source is one evidence adapter. Fetch returns raw records (unredacted,
// unvalidated): pass them through Normalize before anything else sees them.
type Source interface {
	Name() string
	Fetch(ctx context.Context, w Window) ([]Record, error)
}

// maxRows bounds what one fetch reads from any source.
const maxRows = 100_000

// chTime formats t for ClickHouse's default DateTime64 input; the zero time
// is the epoch (DateTime64 cannot hold year 1).
func chTime(t time.Time) string {
	if t.IsZero() {
		t = time.Unix(0, 0)
	}
	return t.UTC().Format("2006-01-02 15:04:05.000")
}

func ms(v float64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(v)).UTC()
}

func compact(l []string) []string {
	var out []string
	for _, s := range l {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---- halo-proxy (gateway) ----

// Gateway reads halo-proxy's GenAI spans (telemetry.genai.traces) from the
// collector's otel_traces table, one record per trace. Only spans stamped
// halo.source=gateway count: the collector sets that on the authenticated
// gateway receiver, never from a client. halo-proxy exports no user or session
// id, so the session is the W3C trace (the caller's traceparent, or one call
// when it sent none) and Who carries the halo.unit pseudonym only.
type Gateway struct{ CH *promote.ClickHouse }

func (Gateway) Name() string { return SourceGateway }

const gatewaySQL = `SELECT TraceId AS trace,
  any(SpanAttributes['halo.unit']) AS unit,
  any(SpanAttributes['halo.harness']) AS harness,
  any(SpanAttributes['halo.ring']) AS ring,
  any(SpanAttributes['halo.release']) AS release,
  any(SpanAttributes['halo.experiment']) AS experiment,
  any(SpanAttributes['halo.variant']) AS variant,
  any(SpanAttributes['halo.actor.chain']) AS chain,
  groupUniqArray(SpanAttributes['gen_ai.request.model']) AS models,
  sum(toFloat64OrZero(SpanAttributes['gen_ai.usage.input_tokens'])) AS input_tokens,
  sum(toFloat64OrZero(SpanAttributes['gen_ai.usage.output_tokens'])) AS output_tokens,
  toFloat64(countIf(SpanAttributes['error.type'] != '')) AS errors,
  toFloat64(count()) AS calls,
  toFloat64(toUnixTimestamp64Milli(min(Timestamp))) AS start_ms,
  toFloat64(max(toUnixTimestamp64Milli(Timestamp) + intDiv(Duration, 1000000))) AS end_ms
FROM otel_traces
WHERE Timestamp >= toDateTime64({since:String}, 3) AND Timestamp < toDateTime64({until:String}, 3)
  AND SpanAttributes['halo.source'] = 'gateway' AND SpanAttributes['gen_ai.operation.name'] != ''
GROUP BY trace
LIMIT 100000`

type gatewayRow struct {
	Trace, Unit, Harness, Ring, Release, Experiment, Variant, Chain string
	Models                                                          []string
	InputTokens                                                     float64 `json:"input_tokens"`
	OutputTokens                                                    float64 `json:"output_tokens"`
	Errors, Calls                                                   float64
	StartMS                                                         float64 `json:"start_ms"`
	EndMS                                                           float64 `json:"end_ms"`
}

func (g Gateway) Fetch(ctx context.Context, w Window) ([]Record, error) {
	var out []Record
	err := g.CH.Query(ctx, gatewaySQL, map[string]string{"since": chTime(w.Since), "until": chTime(w.Until)}, func(raw json.RawMessage) error {
		var r gatewayRow
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("gateway row: %w", err)
		}
		out = append(out, gatewayRecord(r))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("gateway source: %w", err)
	}
	return out, nil
}

func gatewayRecord(r gatewayRow) Record {
	rec := Record{
		SessionID: r.Trace, Harness: r.Harness, Ring: r.Ring, Release: r.Release, Experiment: r.Experiment, Variant: r.Variant,
		Who:    Who{Unit: r.Unit},
		Models: compact(r.Models), InputTokens: int64(r.InputTokens), OutputTokens: int64(r.OutputTokens),
		Start: ms(r.StartMS), End: ms(r.EndMS), Outcome: OutcomeCompleted, Sources: []string{SourceGateway},
	}
	if rec.Harness == "" {
		rec.Harness = "unknown"
	}
	if r.Chain != "" {
		rec.Who.Agents = strings.Split(r.Chain, ">")
	}
	if r.Errors > 0 && r.Errors == r.Calls {
		rec.Outcome = OutcomeError
	}
	return rec
}

// ---- Claude Code OTel events ----

// ClaudeOTel reads Claude Code's log events (claude_code.*) from the
// collector's otel_logs table, one record per session.id. It selects named
// attributes only: never prompt, tool_input, error text or the raw
// tool_parameters (which holds Bash commands); the MCP server name is
// extracted from tool_parameters inside the query. Repositories come from
// vcs.repository.url.full (OTEL_METRICS_INCLUDE_REPOSITORY=1). These events
// arrive on the client-reachable receiver, so the confidence is medium.
type ClaudeOTel struct{ CH *promote.ClickHouse }

func (ClaudeOTel) Name() string { return SourceOTel }

const claudeOTelSQL = `WITH if(position(LogAttributes['event.name'], '.') > 0, LogAttributes['event.name'], Body) AS ev
SELECT LogAttributes['session.id'] AS session,
  anyIf(LogAttributes['user.email'], LogAttributes['user.email'] != '') AS email,
  anyIf(LogAttributes['user.account_id'], LogAttributes['user.account_id'] != '') AS account,
  anyIf(coalesce(nullif(LogAttributes['app.version'], ''), ResourceAttributes['service.version']), coalesce(nullif(LogAttributes['app.version'], ''), ResourceAttributes['service.version']) != '') AS version,
  any(ResourceAttributes['halo.ring']) AS ring,
  any(ResourceAttributes['halo.release']) AS release,
  any(ResourceAttributes['halo.experiment']) AS experiment,
  any(ResourceAttributes['halo.variant']) AS variant,
  groupUniqArrayIf(LogAttributes['model'], ev = 'claude_code.api_request') AS models,
  groupUniqArrayIf(LogAttributes['tool_name'], ev = 'claude_code.tool_result') AS tools,
  groupUniqArrayIf(JSONExtractString(LogAttributes['tool_parameters'], 'mcp_server_name'), ev = 'claude_code.tool_result') AS mcp,
  groupUniqArray(LogAttributes['vcs.repository.url.full']) AS repos,
  sumIf(toFloat64OrZero(LogAttributes['input_tokens']), ev = 'claude_code.api_request') AS input_tokens,
  sumIf(toFloat64OrZero(LogAttributes['output_tokens']), ev = 'claude_code.api_request') AS output_tokens,
  sumIf(toFloat64OrZero(LogAttributes['cost_usd']), ev = 'claude_code.api_request') AS cost_usd,
  toFloat64(countIf(ev = 'claude_code.api_request')) AS requests,
  toFloat64(countIf(ev = 'claude_code.api_error')) AS api_errors,
  toFloat64(toUnixTimestamp64Milli(min(Timestamp))) AS start_ms,
  toFloat64(toUnixTimestamp64Milli(max(Timestamp))) AS end_ms
FROM otel_logs
WHERE Timestamp >= toDateTime64({since:String}, 9) AND Timestamp < toDateTime64({until:String}, 9)
  AND startsWith(ev, 'claude_code.') AND session != ''
GROUP BY session
LIMIT 100000`

type claudeRow struct {
	Session, Email, Account, Version, Ring, Release, Experiment, Variant string
	Models, Tools, MCP, Repos                                            []string
	InputTokens                                                          float64 `json:"input_tokens"`
	OutputTokens                                                         float64 `json:"output_tokens"`
	CostUSD                                                              float64 `json:"cost_usd"`
	Requests                                                             float64
	APIErrors                                                            float64 `json:"api_errors"`
	StartMS                                                              float64 `json:"start_ms"`
	EndMS                                                                float64 `json:"end_ms"`
}

func (c ClaudeOTel) Fetch(ctx context.Context, w Window) ([]Record, error) {
	var out []Record
	err := c.CH.Query(ctx, claudeOTelSQL, map[string]string{"since": chTime(w.Since), "until": chTime(w.Until)}, func(raw json.RawMessage) error {
		var r claudeRow
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("otel row: %w", err)
		}
		out = append(out, claudeRecord(r))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("otel source: %w", err)
	}
	return out, nil
}

func claudeRecord(r claudeRow) Record {
	rec := Record{
		SessionID: r.Session, Harness: "claude-code", HarnessVersion: r.Version,
		Who:  Who{VendorUser: cmpOr(r.Email, r.Account)},
		Ring: r.Ring, Release: r.Release, Experiment: r.Experiment, Variant: r.Variant,
		Models: compact(r.Models), Tools: compact(r.Tools), MCPServers: compact(r.MCP), Repos: compact(r.Repos),
		InputTokens: int64(r.InputTokens), OutputTokens: int64(r.OutputTokens), CostUSD: r.CostUSD,
		Start: ms(r.StartMS), End: ms(r.EndMS), Outcome: OutcomeUnknown, Sources: []string{SourceOTel},
	}
	// Claude Code names MCP tools mcp__<server>__<tool>; the server is known
	// even without OTEL_LOG_TOOL_DETAILS.
	for _, t := range rec.Tools {
		if rest, ok := strings.CutPrefix(t, "mcp__"); ok {
			if srv, _, ok := strings.Cut(rest, "__"); ok && srv != "" {
				rec.MCPServers = append(rec.MCPServers, srv)
			}
		}
	}
	if r.Requests == 0 && r.APIErrors > 0 {
		rec.Outcome = OutcomeError
	}
	return rec
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- Anthropic Compliance API ----

// AnthropicVersion is the anthropic-version header the Compliance API
// examples send (checked 2026-10-27).
const AnthropicVersion = "2023-06-01"

// AnthropicBaseURL is the Compliance API's host.
const AnthropicBaseURL = "https://api.anthropic.com"

// Anthropic reads Claude Code cloud sessions from the Compliance API
// activity feed (GET /v1/compliance/activities, type ccr_session_created),
// one record per activity. The activity names the actor and the agent but
// carries no session id, model, tool or usage field, so the record's session
// id is the activity id and nothing else is filled in: it proves who started
// a cloud session when, not what it did. The client is vendoradmin's, so the
// key is only ever in the Authorization header and scrubbed from errors.
type Anthropic struct{ Client *vendoradmin.Client }

func (Anthropic) Name() string { return SourceAnthropic }

type anthropicPage struct {
	Data []struct {
		ID        string    `json:"id"`
		Type      string    `json:"type"`
		CreatedAt time.Time `json:"created_at"`
		AgentID   string    `json:"agent_id"`
		Actor     struct {
			Type     string `json:"type"`
			Email    string `json:"email_address"`
			UserID   string `json:"user_id"`
			APIKeyID string `json:"api_key_id"`
		} `json:"actor"`
	} `json:"data"`
	HasMore bool   `json:"has_more"`
	LastID  string `json:"last_id"`
}

// maxPages bounds pagination on the vendor APIs.
const maxPages = 200

func (a Anthropic) Fetch(ctx context.Context, w Window) ([]Record, error) {
	var out []Record
	after := ""
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("activity_types[]", "ccr_session_created")
		q.Set("created_at.gte", w.Since.UTC().Format(time.RFC3339))
		q.Set("created_at.lt", w.Until.UTC().Format(time.RFC3339))
		q.Set("order", "asc")
		q.Set("limit", "500")
		if after != "" {
			q.Set("after_id", after)
		}
		var p anthropicPage
		if _, err := a.Client.Get(ctx, "/v1/compliance/activities?"+q.Encode(), &p, "anthropic-version", AnthropicVersion); err != nil {
			return nil, fmt.Errorf("anthropic source: %w", err)
		}
		for _, d := range p.Data {
			if d.Type != "ccr_session_created" || d.ID == "" {
				continue
			}
			who := Who{VendorUser: d.Actor.Email}
			switch {
			case who.VendorUser == "" && d.Actor.UserID != "":
				who.VendorUser = d.Actor.UserID
			case who.VendorUser == "" && d.Actor.APIKeyID != "":
				who.VendorUser = "api_key:" + d.Actor.APIKeyID
			}
			if d.AgentID != "" {
				who.Agents = []string{d.AgentID}
			}
			out = append(out, Record{SessionID: d.ID, Harness: "claude-code", Who: who, Start: d.CreatedAt.UTC(),
				Outcome: OutcomeUnknown, Sources: []string{SourceAnthropic}})
			if len(out) >= maxRows {
				return out, nil
			}
		}
		if !p.HasMore || p.LastID == "" || p.LastID == after {
			return out, nil
		}
		after = p.LastID
	}
	return nil, fmt.Errorf("anthropic source: more than %d pages; narrow --since/--until", maxPages)
}

// ---- GitHub enterprise audit log ----

// GitHubAPIVersion is the X-GitHub-Api-Version sent to the audit log API.
const GitHubAPIVersion = "2026-03-10"

// GitHubAudit reads cloud agent sessions from GET
// /enterprises/{enterprise}/audit-log (read:audit_log). Events that carry
// agent_session_id (documented on pull_request.create, checked 2026-10-27) are
// grouped by that id; every other event is ignored. Phrase narrows the search server-side; the default asks
// for agent_session.* events in the window.
type GitHubAudit struct {
	Client     *vendoradmin.Client
	Enterprise string
	Phrase     string // "" = "action:agent_session"
}

func (GitHubAudit) Name() string { return SourceGitHub }

var (
	enterpriseRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,99}$`)
	linkAfterRE  = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)
)

type githubEvent struct {
	Timestamp      float64 `json:"@timestamp"` // epoch ms
	Action         string  `json:"action"`
	Actor          string  `json:"actor"`
	User           string  `json:"user"`
	Repo           string  `json:"repo"`
	ActorIsAgent   bool    `json:"actor_is_agent"`
	AgentSessionID string  `json:"agent_session_id"`
}

func (g GitHubAudit) Fetch(ctx context.Context, w Window) ([]Record, error) {
	if !enterpriseRE.MatchString(g.Enterprise) {
		return nil, fmt.Errorf("github source: enterprise %q is not a slug", g.Enterprise)
	}
	phrase := g.Phrase
	if phrase == "" {
		phrase = "action:agent_session"
	}
	// The search qualifier is by day; the exact window is applied per event below.
	phrase += fmt.Sprintf(" created:%s..%s", w.Since.UTC().Format(time.DateOnly), w.Until.UTC().Format(time.DateOnly))
	sessions := map[string]*Record{}
	var order []string
	after, n := "", 0
	for page := 0; page < maxPages; page++ {
		q := url.Values{"phrase": {phrase}, "include": {"web"}, "order": {"asc"}, "per_page": {"100"}}
		if after != "" {
			q.Set("after", after)
		}
		var evs []githubEvent
		hdr, err := g.Client.Get(ctx, "/enterprises/"+url.PathEscape(g.Enterprise)+"/audit-log?"+q.Encode(), &evs,
			"Accept", "application/vnd.github+json", "X-GitHub-Api-Version", GitHubAPIVersion)
		if err != nil {
			return nil, fmt.Errorf("github source: %w", err)
		}
		for _, e := range evs {
			if n++; n > maxRows {
				break
			}
			id, t := e.AgentSessionID, ms(e.Timestamp)
			if id == "" || t.Before(w.Since) || !t.Before(w.Until) {
				continue // only events with a session id can be grouped
			}
			r := sessions[id]
			if r == nil {
				r = &Record{SessionID: id, Harness: "copilot-agent", Outcome: OutcomeUnknown, Sources: []string{SourceGitHub}}
				sessions[id] = r
				order = append(order, id)
			}
			if r.Start.IsZero() || t.Before(r.Start) {
				r.Start = t
			}
			if t.After(r.End) {
				r.End = t
			}
			human, agent := e.Actor, ""
			if e.ActorIsAgent {
				human, agent = e.User, e.Actor
			}
			if r.Who.VendorUser == "" {
				r.Who.VendorUser = human
			}
			if agent != "" && len(r.Who.Agents) == 0 {
				r.Who.Agents = []string{agent}
			}
			if e.Repo != "" {
				r.Repos = append(r.Repos, e.Repo)
			}
		}
		next := nextCursor(hdr.Get("Link"))
		if next == "" || next == after || n > maxRows {
			break
		}
		after = next
	}
	out := make([]Record, 0, len(order))
	for _, id := range order {
		out = append(out, *sessions[id])
	}
	return out, nil
}

// nextCursor takes only the after= cursor from a Link rel="next" URL; the
// URL itself is never requested, so a Link header cannot redirect the token.
func nextCursor(link string) string {
	m := linkAfterRE.FindStringSubmatch(link)
	if m == nil {
		return ""
	}
	u, err := url.Parse(m[1])
	if err != nil {
		return ""
	}
	return u.Query().Get("after")
}

// ---- JSONL import ----

// JSONL reads one Record per line. Decoding is strict: a field the ledger
// does not define (a "prompt", say) fails the import rather than being
// silently dropped, and Normalize then rejects any value that is not a token.
// Sources, confidence and id are set by the ledger, not the file.
type JSONL struct{ R io.Reader }

func (JSONL) Name() string { return SourceJSONL }

func (j JSONL) Fetch(_ context.Context, w Window) ([]Record, error) {
	sc := bufio.NewScanner(j.R)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []Record
	for line := 1; sc.Scan(); line++ {
		b := strings.TrimSpace(sc.Text())
		if b == "" {
			continue
		}
		d := json.NewDecoder(strings.NewReader(b))
		d.DisallowUnknownFields()
		var r Record
		if err := d.Decode(&r); err != nil {
			return nil, fmt.Errorf("jsonl line %d: %w", line, err)
		}
		if d.More() {
			return nil, fmt.Errorf("jsonl line %d: trailing data", line)
		}
		if (!w.Since.IsZero() && r.Start.Before(w.Since)) || (!w.Until.IsZero() && !r.Start.Before(w.Until)) {
			continue
		}
		r.ID, r.Sources, r.Confidence = "", []string{SourceJSONL}, ""
		out = append(out, r)
		if len(out) > maxRows {
			return nil, fmt.Errorf("jsonl: more than %d records", maxRows)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("jsonl: %w", err)
	}
	return out, nil
}

// ParseTime accepts RFC 3339 or a duration back from now ("24h").
func ParseTime(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil && strings.HasSuffix(s, "d") && n > 0 {
		return now.AddDate(0, 0, -n), nil
	}
	return time.Time{}, errors.New("want RFC 3339, a duration such as 24h, or days such as 7d")
}
