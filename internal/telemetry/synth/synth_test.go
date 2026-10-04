package synth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/telemetry"
)

var testCfg = Config{Seed: 7, Now: time.Unix(1_800_000_000, 0), UsersPerArm: 2, SessionsPerUser: 2, BaseCostUSD: 1}
var testCohorts = []Cohort{{Experiment: "e", Variant: "control", Ring: "r", Release: "1", CostMult: 1, AcceptRate: 0.5}}

func TestGenerateDeterministic(t *testing.T) {
	m1, l1 := Generate(testCfg, testCohorts)
	m2, l2 := Generate(testCfg, testCohorts)
	if !reflect.DeepEqual(m1, m2) || !reflect.DeepEqual(l1, l2) {
		t.Fatal("same seed must give identical telemetry")
	}
	// per user-session: 1 claude metrics body + 3 log bodies (one per harness); per user: codex + gemini metrics.
	if want := 2 * (2 + 2); len(m1) != want || len(l1) != 12 {
		t.Fatalf("got %d metric bodies / %d log bodies, want %d / 12", len(m1), len(l1), want)
	}
}

// Every vendor metric the generator emits must be one the collector normalises,
// and halo.harness must be left for the collector to stamp (except Codex).
func TestGenerateMatchesCollectorMappings(t *testing.T) {
	m, _ := Generate(testCfg, testCohorts)
	b, _ := json.Marshal(m)
	s := string(b)
	for _, name := range []string{"claude_code.cost.usage", "claude_code.token.usage", "claude_code.code_edit_tool.decision", "claude_code.session.count", "gen_ai.client.token.usage"} {
		if !strings.Contains(s, `"`+name+`"`) {
			t.Errorf("generator does not emit %s", name)
		}
		found := false
		for _, mp := range telemetry.Mappings {
			found = found || mp.From == name
		}
		if !found {
			t.Errorf("%s is emitted but not in telemetry.Mappings", name)
		}
	}
	if n := strings.Count(s, `"halo.harness"`); n != 2 { // codex only, one per user
		t.Errorf("halo.harness set %d times, want 2 (codex only)", n)
	}
}

func TestSend(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !json.Valid(b) || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad", 400)
			return
		}
		paths = append(paths, r.URL.Path)
	}))
	defer srv.Close()
	m, l := Generate(testCfg, testCohorts)
	if err := Send(context.Background(), srv.URL, m, l); err != nil {
		t.Fatal(err)
	}
	if len(paths) != len(m)+len(l) {
		t.Fatalf("sent %d, want %d", len(paths), len(m)+len(l))
	}
	if err := Send(context.Background(), "http://127.0.0.1:1", m, l); err == nil {
		t.Fatal("want connection error")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) }))
	defer bad.Close()
	if err := Send(context.Background(), bad.URL, m, l); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want HTTP 500 error, got %v", err)
	}
}

// The cohort effects are present in the emitted events, in every harness's dialect.
func TestGenerateEventEffects(t *testing.T) {
	cfg := Config{Seed: 1, Now: time.Unix(1_800_000_000, 0), UsersPerArm: 20, SessionsPerUser: 3, BaseCostUSD: 1}
	type stats struct{ calls, apiErr, tools, toolErr, okMS, okN float64 }
	measure := func(c Cohort) map[string]*stats {
		_, logs := Generate(cfg, []Cohort{c})
		out := map[string]*stats{}
		for _, l := range logs {
			for _, rec := range l["resourceLogs"].([]kv)[0]["scopeLogs"].([]kv)[0]["logRecords"].([]kv) {
				a := map[string]any{}
				for _, x := range rec["attributes"].([]kv) {
					for _, v := range x["value"].(kv) {
						a[x["key"].(string)] = v
					}
				}
				name := a["event.name"].(string)
				if !strings.Contains(name, ".") {
					name = rec["body"].(kv)["stringValue"].(string)
				}
				h, _, found := strings.Cut(name, ".")
				if !found {
					t.Fatalf("event name %q has no dot", name)
				}
				if out[h] == nil {
					out[h] = &stats{}
				}
				s := out[h]
				switch name {
				case "claude_code.api_request", "gemini_cli.api_response", "codex.api_request":
					s.calls++
					if a["http.response.status_code"] == "500" {
						s.apiErr++
						continue
					}
					ms, _ := strconv.Atoi(a["duration_ms"].(string))
					s.okMS += float64(ms)
					s.okN++
				case "claude_code.api_error", "gemini_cli.api_error":
					s.calls++
					s.apiErr++
				case "claude_code.tool_result", "gemini_cli.tool_call", "codex.tool_result":
					s.tools++
					if fmt.Sprint(a["success"]) == "false" {
						s.toolErr++
					}
				default:
					t.Fatalf("unexpected event %q", name)
				}
			}
		}
		return out
	}
	ctl := measure(Cohort{Experiment: "e", Variant: "c", APIErrorRate: 0.05, ToolErrorRate: 0.05})
	trt := measure(Cohort{Experiment: "e", Variant: "t", APIErrorRate: 0.30, ToolErrorRate: 0.30, LatencyMult: 1.5})
	for _, h := range []string{"claude_code", "gemini_cli", "codex"} {
		c, x := ctl[h], trt[h]
		if c == nil || x == nil || c.calls != 20*3*CallsPerSession || c.tools != c.calls {
			t.Fatalf("%s: missing or miscounted events: %+v %+v", h, c, x)
		}
		if er := x.apiErr / x.calls; er < 0.2 || er > 0.4 || c.apiErr/c.calls > 0.12 {
			t.Errorf("%s: api error rates ctl=%.2f trt=%.2f", h, c.apiErr/c.calls, er)
		}
		if tr := x.toolErr / x.tools; tr < 0.2 || tr > 0.4 {
			t.Errorf("%s: tool error rate %.2f", h, tr)
		}
		if r := (x.okMS / x.okN) / (c.okMS / c.okN); r < 1.35 || r > 1.65 {
			t.Errorf("%s: latency ratio %.2f, want ~1.5", h, r)
		}
	}
}
