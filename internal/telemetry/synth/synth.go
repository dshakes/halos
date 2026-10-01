// Package synth emits synthetic OTLP/HTTP (JSON) telemetry shaped like the real
// harnesses, for control vs treatment cohorts with a known injected effect. It
// exists to prove the collector -> ClickHouse -> analyze path (test/e2e/obs_test.go)
// and is a test helper, not a production dependency.
//
// Shapes follow the vendors' docs: Claude Code sends claude_code.* delta sums
// with user.id/session.id/model/type/decision attributes; Codex and Gemini send
// the gen_ai.client.token.usage histogram. halo.harness is left unset for Claude
// Code and Gemini so the collector's transform must stamp it; Codex sets it.
//
// Log events follow the vendors' documented names and attributes: Claude Code
// claude_code.api_request / api_error / tool_result (unprefixed event.name, full
// name in the body), Gemini gemini_cli.api_response / api_error / tool_call and
// Codex codex.api_request / tool_result (full name in event.name). Each session
// makes CallsPerSession API calls and tool calls with the cohort's latency and
// error-rate effects. Events draw from their own RNG stream so adding them did
// not change the metric data of a given seed.
package synth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// Cohort is one experiment arm.
type Cohort struct {
	Experiment, Variant, Ring, Release string
	CostMult                           float64 // multiplies per-session cost (1.3 = +30%)
	AcceptRate                         float64 // P(edit accepted)
	LatencyMult                        float64 // multiplies API call latency; 0 = 1
	APIErrorRate                       float64 // P(API call fails)
	ToolErrorRate                      float64 // P(tool call fails)
}

// CallsPerSession is the number of API calls (and of tool calls) per session in the log events.
const CallsPerSession = 10

// Config controls the volume and determinism of a run.
type Config struct {
	Seed            int64
	Now             time.Time
	UsersPerArm     int
	SessionsPerUser int // sessions per user
	BaseCostUSD     float64
}

type kv = map[string]any

func attrs(p ...string) []kv {
	out := make([]kv, 0, len(p)/2)
	for i := 0; i+1 < len(p); i += 2 {
		out = append(out, kv{"key": p[i], "value": kv{"stringValue": p[i+1]}})
	}
	return out
}

func nano(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

// ev is one log record; a holds string, int or bool attribute values.
func ev(t time.Time, body string, a map[string]any) kv {
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]kv, 0, len(a))
	for _, k := range keys {
		var v kv
		switch x := a[k].(type) {
		case int:
			v = kv{"intValue": strconv.Itoa(x)}
		case bool:
			v = kv{"boolValue": x}
		default:
			v = kv{"stringValue": fmt.Sprint(x)}
		}
		out = append(out, kv{"key": k, "value": v})
	}
	return kv{"timeUnixNano": nano(t), "body": kv{"stringValue": body}, "attributes": out}
}

func logsReq(res kv, recs []kv) kv {
	return kv{"resourceLogs": []kv{{"resource": res, "scopeLogs": []kv{{"scope": kv{"name": "synth"}, "logRecords": recs}}}}}
}

// sessionEvents renders one session's API and tool events in harness h's dialect.
func sessionEvents(rng *rand.Rand, c Cohort, h string, t time.Time, ids map[string]any) []kv {
	mult := c.LatencyMult
	if mult == 0 {
		mult = 1
	}
	base := map[string]float64{"claude-code": 1200, "gemini-cli": 900, "codex": 1500}[h]
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range ids {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	var out []kv
	for i := 0; i < CallsPerSession; i++ {
		ms := int(base * mult * math.Exp(0.35*rng.NormFloat64()))
		fail := rng.Float64() < c.APIErrorRate
		switch {
		case h == "claude-code" && fail:
			out = append(out, ev(t, "claude_code.api_error", with(map[string]any{"event.name": "api_error", "model": "claude-sonnet-4-5",
				"status_code": 529, "duration_ms": ms / 4, "error": "Overloaded", "attempt": 1})))
		case h == "claude-code":
			out = append(out, ev(t, "claude_code.api_request", with(map[string]any{"event.name": "api_request", "model": "claude-sonnet-4-5",
				"duration_ms": ms, "cost_usd": "0.01"})))
		case h == "gemini-cli" && fail:
			out = append(out, ev(t, "API error", with(map[string]any{"event.name": "gemini_cli.api_error", "model_name": "gemini-2.5-pro",
				"status_code": 503, "duration": ms / 4, "error.message": "unavailable"})))
		case h == "gemini-cli":
			out = append(out, ev(t, "API response", with(map[string]any{"event.name": "gemini_cli.api_response", "model": "gemini-2.5-pro",
				"status_code": 200, "duration_ms": ms})))
		case fail: // codex
			out = append(out, ev(t, "", with(map[string]any{"event.name": "codex.api_request", "model": "gpt-5-codex",
				"http.response.status_code": 500, "duration_ms": ms / 4, "error.message": "server error"})))
		default:
			out = append(out, ev(t, "", with(map[string]any{"event.name": "codex.api_request", "model": "gpt-5-codex",
				"http.response.status_code": 200, "duration_ms": ms})))
		}
		ok := rng.Float64() >= c.ToolErrorRate
		switch h {
		case "claude-code":
			out = append(out, ev(t, "claude_code.tool_result", with(map[string]any{"event.name": "tool_result", "tool_name": "Bash",
				"success": strconv.FormatBool(ok), "duration_ms": 80})))
		case "gemini-cli":
			out = append(out, ev(t, "Tool call", with(map[string]any{"event.name": "gemini_cli.tool_call", "function_name": "run_shell_command",
				"success": ok, "duration_ms": 80})))
		default:
			out = append(out, ev(t, "", with(map[string]any{"event.name": "codex.tool_result", "tool_name": "shell",
				"success": strconv.FormatBool(ok), "duration_ms": 80})))
		}
	}
	return out
}

func sumPoint(m, unit string, v float64, t time.Time, a []kv) kv {
	return kv{"name": m, "unit": unit, "sum": kv{
		"aggregationTemporality": 1, // DELTA, Claude Code's default
		"isMonotonic":            true,
		"dataPoints": []kv{{"attributes": a, "startTimeUnixNano": nano(t.Add(-time.Second)),
			"timeUnixNano": nano(t), "asDouble": v}},
	}}
}

func histPoint(m, unit string, sum float64, t time.Time, a []kv) kv {
	return kv{"name": m, "unit": unit, "histogram": kv{
		"aggregationTemporality": 1,
		"dataPoints": []kv{{"attributes": a, "startTimeUnixNano": nano(t.Add(-time.Second)),
			"timeUnixNano": nano(t), "count": "1", "sum": sum,
			"bucketCounts": []string{"0", "1"}, "explicitBounds": []float64{1000}}},
	}}
}

func resource(service string, c Cohort, harness string) kv {
	r := attrs("service.name", service, "halo.ring", c.Ring, "halo.release", c.Release,
		"halo.experiment", c.Experiment, "halo.variant", c.Variant)
	if harness != "" {
		r = append(r, attrs("halo.harness", harness)...)
	}
	return kv{"attributes": r}
}

func metricsReq(res kv, ms []kv) kv {
	return kv{"resourceMetrics": []kv{{"resource": res, "scopeMetrics": []kv{{
		"scope": kv{"name": "synth"}, "metrics": ms}}}}}
}

// Generate returns one OTLP metrics request body per user-session for every
// cohort and harness, plus one logs body per session per harness.
func Generate(cfg Config, cohorts []Cohort) (metrics, logs []kv) {
	rng := rand.New(rand.NewSource(cfg.Seed))      //nolint:gosec // deterministic test data, not security
	erng := rand.New(rand.NewSource(cfg.Seed + 1)) //nolint:gosec // event stream, independent of rng
	for _, c := range cohorts {
		for u := 0; u < cfg.UsersPerArm; u++ {
			user := fmt.Sprintf("%s-user-%03d", c.Variant, u)
			for s := 0; s < cfg.SessionsPerUser; s++ {
				sid := fmt.Sprintf("%s-s%d", user, s)
				t := cfg.Now.Add(-time.Duration(rng.Intn(3000)) * time.Second)
				base := []string{"user.id", user, "session.id", sid, "organization.id", "acme", "terminal.type", "xterm"}
				cost := cfg.BaseCostUSD * c.CostMult * (0.8 + 0.4*rng.Float64())
				ms := []kv{sumPoint("claude_code.session.count", "count", 1, t, attrs(base...))}
				// A session is several API requests; cost.usage is per request.
				for i := 0; i < 3; i++ {
					ms = append(ms, sumPoint("claude_code.cost.usage", "USD", cost/3, t, attrs(append(base, "model", "claude-sonnet-4-5")...)))
				}
				for _, tt := range []struct {
					typ string
					n   float64
				}{{"input", 1200}, {"output", 400}, {"cacheRead", 8000}, {"cacheCreation", 300}} {
					ms = append(ms, sumPoint("claude_code.token.usage", "tokens", tt.n, t, attrs(append(base, "type", tt.typ, "model", "claude-sonnet-4-5")...)))
				}
				for i := 0; i < 10; i++ {
					d := "reject"
					if rng.Float64() < c.AcceptRate {
						d = "accept"
					}
					ms = append(ms, sumPoint("claude_code.code_edit_tool.decision", "count", 1, t,
						attrs(append(base, "decision", d, "source", "config", "tool_name", "Edit", "language", "go")...)))
				}
				metrics = append(metrics, metricsReq(resource("claude-code", c, ""), ms))
				logs = append(logs,
					logsReq(resource("claude-code", c, ""), sessionEvents(erng, c, "claude-code", t,
						map[string]any{"user.id": user, "session.id": sid, "organization.id": "acme", "terminal.type": "xterm"})),
					logsReq(resource("gemini-cli", c, ""), sessionEvents(erng, c, "gemini-cli", t,
						map[string]any{"installation.id": user + "-gemini-cli", "session.id": sid + "-gemini"})),
					logsReq(resource("codex", c, "codex"), sessionEvents(erng, c, "codex", t,
						map[string]any{"user.account_id": user + "-codex", "conversation.id": sid + "-codex", "terminal.type": "xterm"})))
			}
			// Codex (halo.harness set by client) and Gemini (stamped by collector):
			// one token histogram each, per user.
			t := cfg.Now.Add(-time.Duration(rng.Intn(3000)) * time.Second)
			for _, h := range []struct{ svc, harness, model string }{
				{"codex", "codex", "gpt-5-codex"}, {"gemini-cli", "", "gemini-2.5-pro"},
			} {
				a := attrs("user.id", user+"-"+h.svc, "session.id", user+"-"+h.svc+"-s0", "gen_ai.request.model", h.model)
				metrics = append(metrics, metricsReq(resource(h.svc, c, h.harness), []kv{
					histPoint("gen_ai.client.token.usage", "{token}", 1500, t, append(a, attrs("gen_ai.token.type", "input")...)),
					histPoint("gen_ai.client.token.usage", "{token}", 500, t, append(a, attrs("gen_ai.token.type", "output")...)),
				}))
			}
		}
	}
	return metrics, logs
}

// Send POSTs every body to the collector's OTLP/HTTP endpoint (e.g. http://127.0.0.1:14318).
func Send(ctx context.Context, endpoint string, metrics, logs []kv) error {
	post := func(path string, body kv) error {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+path, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			return fmt.Errorf("synth: POST %s: HTTP %d: %s", path, resp.StatusCode, msg)
		}
		return nil
	}
	for _, m := range metrics {
		if err := post("/v1/metrics", m); err != nil {
			return err
		}
	}
	for _, l := range logs {
		if err := post("/v1/logs", l); err != nil {
			return err
		}
	}
	return nil
}
