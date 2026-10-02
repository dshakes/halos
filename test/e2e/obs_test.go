//go:build e2e

package e2e

// Evidence-plane e2e: synthetic harness telemetry -> otel-collector-contrib ->
// ClickHouse -> `halo exp analyze` and Grafana. Needs the stack from
// deploy/observability (scripts/obs-e2e.sh / `make obs-e2e` brings it up and
// sets HALO_OBS_E2E=1 plus the HALO_OBS_*_PORT variables); skipped otherwise.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/telemetry/gwmetrics"
	"github.com/dshakes/halos/internal/telemetry/synth"
)

const (
	chUser, chPass = "halo", "halo-dev-only"
	expCost        = "obs-cost-ab"            // treatment costs +30%: cost guardrail must roll it back
	expLat         = "obs-latency-ab"         // CLI API latency +40%: p95 guardrail must roll it back
	expErr         = "obs-errors-ab"          // CLI API error rate 3% -> 15%: error-rate guardrail must roll it back
	expGW          = "obs-gateway-latency"    // CLI identical, gateway latency +40%: gateway source must win
	expNull        = "obs-cost-null"          // identical arms: must not roll back (also the target of forged gateway rows)
	expForged      = "obs-forged-source"      // not in policy: a CLI row claiming halo.source=gateway
	gatewayToken   = "halo-dev-gateway-token" // deploy/observability/docker-compose.yml
	evalToken      = "halo-dev-eval-token"    // deploy/observability/docker-compose.yml
	expEvalForged  = "obs-eval-forged"        // halo.gateway.* sent on the eval receiver: must be dropped
	expJudge       = "obs-judge-shadow"       // shadow experiment decided on halo.eval.judge.score (eval evidence)
	usersPerArm    = 40
	sessionsPerU   = 3
	gwReqsPerSess  = 30
)

var obsExperiments = []string{expCost, expLat, expErr, expGW, expNull}

func obsPort(t *testing.T, name string) string {
	t.Helper()
	p := os.Getenv(name)
	if p == "" {
		t.Skipf("%s unset: run via scripts/obs-e2e.sh", name)
	}
	return p
}

type chClient struct{ url string }

func (c chClient) rows(t *testing.T, sql string) []map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, c.url+"/?database=halo", strings.NewReader(sql+" FORMAT JSONEachRow"))
	req.Header.Set("X-ClickHouse-User", chUser)
	req.Header.Set("X-ClickHouse-Key", chPass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("clickhouse %d: %s\nsql: %s", resp.StatusCode, b, sql)
	}
	var out []map[string]any
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("decode %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func (c chClient) num(t *testing.T, sql string) float64 {
	t.Helper()
	r := c.rows(t, sql)
	if len(r) != 1 {
		t.Fatalf("want one row for %s, got %v", sql, r)
	}
	for _, v := range r[0] {
		switch x := v.(type) {
		case float64:
			return x
		case string: // ClickHouse quotes UInt64 in JSON
			var f float64
			if _, err := fmt.Sscan(x, &f); err != nil {
				t.Fatal(err)
			}
			return f
		}
	}
	t.Fatalf("no number in %v", r[0])
	return 0
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(time.Second) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

const obsExperiment = `apiVersion: halos.dev/v1
kind: Experiment
name: %s
type: ab
axis: client
status: running
rings: [ring1-canary]
variants:
  - {name: control, weight: 50, profile: engineering, control: true}
  - {name: treatment, weight: 50, profile: engineering-next}
metrics:
  primary: {metric: halo.edit.accept_rate, direction: increase}
  guardrails:
    - {metric: halo.cost.usd_per_session, direction: decrease, maxRegression: 0.10}
    - {metric: halo.api.error_rate, direction: decrease, maxRegression: 0.20}
    - {metric: halo.latency.p95_ms, direction: decrease, maxRegression: 0.10}
    - {metric: halo.tool.error_rate, direction: decrease, maxRegression: 0.20}
stopping: {method: msprt, alpha: 0.05, minSamples: 20, maxDays: 21}
`

// obsJudgeExperiment: a running shadow experiment whose primary metric is the
// online LLM-judge score (graded on halo-shadow pairs, eval evidence).
const obsJudgeExperiment = `apiVersion: halos.dev/v1
kind: Experiment
name: ` + expJudge + `
type: shadow
axis: traffic
status: running
rings: [ring2-early]
sampleRate: 0.05
variants:
  - {name: primary, weight: 1, control: true}
  - name: sonnet-next
    weight: 1
    routes:
      sonnet: {upstream: anthropic-direct, model: claude-sonnet-next}
metrics:
  primary: {metric: halo.eval.judge.score, direction: increase}
stopping: {method: msprt, alpha: 0.05, minSamples: 20, maxDays: 21}
`

func TestObsEvidencePlane(t *testing.T) {
	ch := chClient{"http://127.0.0.1:" + obsPort(t, "HALO_OBS_CH_HTTP_PORT")}
	otlp := "http://127.0.0.1:" + obsPort(t, "HALO_OBS_OTLP_HTTP_PORT")
	grafana := "http://127.0.0.1:" + obsPort(t, "HALO_OBS_GRAFANA_PORT")
	gwOTLP := "http://127.0.0.1:" + obsPort(t, "HALO_OBS_OTLP_GATEWAY_PORT")
	evalOTLP := "http://127.0.0.1:" + obsPort(t, "HALO_OBS_OTLP_EVAL_PORT")

	root, _ := filepath.Abs("../..")
	halo := filepath.Join(t.TempDir(), "halo")
	build := exec.Command("go", "build", "-o", halo, "./cmd/halo")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build halo: %v\n%s", err, out)
	}

	// Policy repo: the examples org plus two experiments.
	policy := t.TempDir()
	if out, err := exec.Command("cp", "-R", filepath.Join(root, "examples/acme-corp")+"/.", policy).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v\n%s", err, out)
	}
	for _, n := range obsExperiments {
		if err := os.WriteFile(filepath.Join(policy, "experiments", n+".yaml"), fmt.Appendf(nil, obsExperiment, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(policy, "experiments", expJudge+".yaml"), []byte(obsJudgeExperiment), 0o644); err != nil {
		t.Fatal(err)
	}

	// Synthetic telemetry.
	cohort := func(exp, variant string, mod func(*synth.Cohort)) synth.Cohort {
		c := synth.Cohort{Experiment: exp, Variant: variant, Ring: "ring1-canary", Release: "2.1.300", CostMult: 1, AcceptRate: 0.7,
			LatencyMult: 1, APIErrorRate: 0.03, ToolErrorRate: 0.05}
		if mod != nil {
			mod(&c)
		}
		return c
	}
	cohorts := []synth.Cohort{
		cohort(expCost, "treatment", func(c *synth.Cohort) { c.CostMult = 1.3 }),
		cohort(expLat, "treatment", func(c *synth.Cohort) { c.LatencyMult = 1.4 }),
		cohort(expErr, "treatment", func(c *synth.Cohort) { c.APIErrorRate = 0.15 }),
		cohort(expGW, "treatment", nil), cohort(expNull, "treatment", nil),
	}
	for _, e := range obsExperiments {
		cohorts = append(cohorts, cohort(e, "control", nil))
	}
	cfg := synth.Config{Seed: 42, Now: time.Now().UTC(), UsersPerArm: usersPerArm, SessionsPerUser: sessionsPerU, BaseCostUSD: 0.50}
	m, l := synth.Generate(cfg, cohorts)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := synth.Send(ctx, otlp, m, l); err != nil {
		t.Fatal(err)
	}
	tokFile := filepath.Join(t.TempDir(), "gateway-token")
	if err := os.WriteFile(tokFile, []byte(gatewayToken), 0o600); err != nil {
		t.Fatal(err)
	}
	sendGatewayMetrics(ctx, t, gwOTLP, tokFile, expGW, 1.4, 529, 0.02)
	evalTokFile := filepath.Join(t.TempDir(), "eval-token")
	if err := os.WriteFile(evalTokFile, []byte(evalToken), 0o600); err != nil {
		t.Fatal(err)
	}
	runEvalOnline(t, halo, root, policy, evalOTLP, evalTokFile)
	// The eval receiver has its own token (the gateway token is refused) and
	// carries only halo.eval.*: a forged halo.gateway.* export must not land.
	for _, tok := range []string{"", "wrong", gatewayToken} {
		req, _ := http.NewRequest(http.MethodPost, evalOTLP+"/v1/metrics", strings.NewReader(`{"resourceMetrics":[]}`))
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("eval receiver with token %q: HTTP %d, want 401", tok, resp.StatusCode)
		}
	}
	sendGatewayMetrics(ctx, t, evalOTLP, evalTokFile, expEvalForged, 5, 503, 1)

	// 0. Evidence trust. The gateway receiver rejects missing and wrong tokens.
	for _, tok := range []string{"", "wrong"} {
		req, _ := http.NewRequest(http.MethodPost, gwOTLP+"/v1/metrics", strings.NewReader(`{"resourceMetrics":[]}`))
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("gateway receiver with token %q: HTTP %d, want 401", tok, resp.StatusCode)
		}
	}
	// Anyone can reach the CLI receiver: forge a gateway regression for expNull
	// (5x latency, all 5xx) and a CLI row claiming halo.source=gateway. The
	// collector must drop the former and overwrite the latter.
	sendGatewayMetrics(ctx, t, otlp, "", expNull, 5, 503, 1)
	forged := `{"resourceMetrics":[{"resource":{"attributes":[{"key":"halo.experiment","value":{"stringValue":"` + expForged + `"}},` +
		`{"key":"halo.source","value":{"stringValue":"gateway"}}]},"scopeMetrics":[{"metrics":[{"name":"claude_code.cost.usage","sum":{"aggregationTemporality":1,"isMonotonic":true,` +
		`"dataPoints":[{"asDouble":1,"timeUnixNano":"` + fmt.Sprint(time.Now().UnixNano()) + `","attributes":[{"key":"user.id","value":{"stringValue":"forger"}},{"key":"halo.source","value":{"stringValue":"gateway"}}]}]}}]}]}]}`
	resp, err := http.Post(otlp+"/v1/metrics", "application/json", strings.NewReader(forged))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CLI receiver must accept unauthenticated exports: HTTP %d", resp.StatusCode)
	}

	// Online eval quality: judge-score gauges for both arms, via the eval receiver.
	waitFor(t, 90*time.Second, "online eval judge scores", func() bool {
		return ch.num(t, "SELECT count() FROM halo_metrics WHERE metric='halo.eval.judge.score' AND experiment='"+expCost+"'") == 8 &&
			ch.num(t, "SELECT count() FROM halo_metrics WHERE metric='halo.eval.judge.score' AND experiment='"+expJudge+"' AND unit_id != ''") == 2*usersPerArm
	})
	judged := map[string]float64{}
	for _, r := range ch.rows(t, "SELECT variant, source, judge_score, readings FROM halo_eval_quality WHERE experiment='"+expCost+"' AND rubric='code-change-quality@1' AND judge='judge-pinned-1'") {
		if r["source"] != "eval" {
			t.Errorf("judge score row with source %v, want eval", r["source"])
		}
		judged[r["variant"].(string)] = r["judge_score"].(float64)
	}
	if math.Abs(judged["control"]-0.6) > 1e-6 || math.Abs(judged["treatment"]-0.8) > 1e-6 {
		t.Errorf("halo_eval_quality averages %v, want control 0.6 / treatment 0.8", judged)
	}
	if n := ch.num(t, "SELECT count() FROM otel_metrics_sum WHERE Attributes['halo.experiment'] = '"+expEvalForged+"'") +
		ch.num(t, "SELECT count() FROM otel_metrics_histogram WHERE Attributes['halo.experiment'] = '"+expEvalForged+"'"); n != 0 {
		t.Errorf("%v halo.gateway.* rows sent on the eval receiver reached ClickHouse", n)
	}

	// 1. Rows land (collector batches for 5s) and were normalised.
	wantCost := float64(2 * usersPerArm * sessionsPerU * 3)                   // per experiment: arms x users x sessions x 3 requests
	perExp := float64(2 * usersPerArm * sessionsPerU * synth.CallsPerSession) // per harness, per event kind
	gwTotal := float64(2 * usersPerArm * gwReqsPerSess)
	waitFor(t, 90*time.Second, "cost, CLI event and gateway rows", func() bool {
		return ch.num(t, "SELECT count() FROM halo_metrics WHERE metric='halo.cost.usd' AND experiment='"+expForged+"'") == 1 &&
			ch.num(t, "SELECT count() FROM halo_metrics WHERE metric='halo.cost.usd'") >= float64(len(obsExperiments))*wantCost &&
			ch.num(t, "SELECT count() FROM halo_metrics WHERE metric IN ('halo.api.request','halo.tool.call')") >= float64(len(obsExperiments)*3*2)*perExp &&
			ch.num(t, "SELECT sum(value) FROM halo_metrics WHERE metric='halo.gateway.requests'") >= gwTotal
	})
	if n := ch.num(t, "SELECT count() FROM otel_metrics_sum WHERE MetricName LIKE 'claude_code.%'"); n != 0 {
		t.Errorf("%v un-normalised claude_code.* rows reached ClickHouse", n)
	}
	if n := ch.num(t, "SELECT count() FROM otel_metrics_sum WHERE MetricName LIKE 'halo.gateway.%' AND Attributes['halo.experiment'] = '"+expNull+"'") +
		ch.num(t, "SELECT count() FROM otel_metrics_histogram WHERE MetricName LIKE 'halo.gateway.%' AND Attributes['halo.experiment'] = '"+expNull+"'"); n != 0 {
		t.Errorf("%v halo.gateway.* rows forged on the CLI receiver reached ClickHouse", n)
	}
	if n := ch.num(t, "SELECT countIf(attrs['halo.source'] != 'gateway') FROM halo_metrics WHERE metric LIKE 'halo.gateway.%'"); n != 0 {
		t.Errorf("%v halo.gateway.* rows without the collector's gateway stamp", n)
	}
	if n := ch.num(t, "SELECT countIf(attrs['halo.source'] = 'cli') FROM halo_metrics WHERE experiment='"+expForged+"'"); n != 1 {
		t.Errorf("client-supplied halo.source=gateway was not overwritten with cli (%v cli rows)", n)
	}
	if n := ch.num(t, "SELECT countIf(attrs['halo.source'] != 'cli') FROM halo_metrics WHERE metric IN ('halo.cost.usd', 'halo.tokens', 'halo.edit.decision')"); n != 0 {
		t.Errorf("%v CLI metric rows not stamped halo.source=cli", n)
	}
	if n := ch.num(t, "SELECT count() FROM otel_logs"); n < float64(2*2*usersPerArm*sessionsPerU) {
		t.Errorf("logs pipeline: only %v rows in otel_logs", n)
	}

	// 2. halo.harness stamped / kept; ring, release, experiment, variant queryable.
	h := map[string]bool{}
	for _, r := range ch.rows(t, "SELECT DISTINCT harness FROM halo_metrics WHERE metric='halo.tokens'") {
		h[r["harness"].(string)] = true
	}
	for _, want := range []string{"claude-code", "codex", "gemini-cli"} {
		if !h[want] {
			t.Errorf("harness %q missing from halo.tokens: %v", want, h)
		}
	}
	if n := ch.num(t, "SELECT uniqExact(ring, release, experiment, variant) FROM halo_metrics WHERE ring='ring1-canary' AND release='2.1.300' AND experiment != '' AND variant != ''"); n != float64(2*len(obsExperiments)) {
		t.Errorf("want %d (experiment,variant) cohorts queryable by resource attrs, got %v", 2*len(obsExperiments), n)
	}
	// Histogram (Codex/Gemini) tokens: 2000 per user per harness, input+output.
	if got, want := ch.num(t, "SELECT sum(value) FROM halo_metrics WHERE metric='halo.tokens' AND harness='codex' AND experiment='"+expCost+"'"), float64(2*usersPerArm*2000); got != want {
		t.Errorf("codex tokens %v, want %v", got, want)
	}
	// Model attribute mapped for both attribute conventions.
	if n := ch.num(t, "SELECT countIf(model='gemini-2.5-pro') > 0 AND countIf(model='claude-sonnet-4-5') > 0 FROM halo_metrics"); n != 1 {
		t.Error("model not populated for gen_ai.request.model / model")
	}
	// Injected effect is visible in the landed data: cost per session +30% (noise <= 10%).
	rows := ch.rows(t, "SELECT variant, sum(value)/uniqExact(session_id) AS c FROM halo_metrics WHERE experiment='"+expCost+"' AND metric='halo.cost.usd' GROUP BY variant")
	cps := map[string]float64{}
	for _, r := range rows {
		cps[r["variant"].(string)] = r["c"].(float64)
	}
	if ratio := cps["treatment"] / cps["control"]; math.Abs(ratio-1.3) > 0.13 {
		t.Errorf("landed cost ratio %.3f, want ~1.30 (%v)", ratio, cps)
	}

	// CLI log events -> halo.api.request / halo.tool.call, every harness, only whitelisted attrs.
	for _, m := range []string{"halo.api.request", "halo.tool.call"} {
		for _, h := range []string{"claude-code", "gemini-cli", "codex"} {
			q := fmt.Sprintf("SELECT count() FROM halo_metrics WHERE metric='%s' AND harness='%s' AND experiment='%s' AND unit_id != '' AND variant != ''", m, h, expNull)
			if got := ch.num(t, q); got != perExp {
				t.Errorf("%s/%s: %v rows, want %v", m, h, got, perExp)
			}
		}
	}
	if n := ch.num(t, "SELECT countIf(length(mapKeys(attrs)) != 4 OR has(mapKeys(attrs), 'error.message')) FROM halo_metrics WHERE metric IN ('halo.api.request','halo.tool.call')"); n != 0 {
		t.Errorf("%v event rows carry attributes beyond event/status_code/tool_name/error", n)
	}
	errRate := map[string]float64{}
	for _, r := range ch.rows(t, "SELECT variant, countIf(attrs['error']='1')/count() AS e FROM halo_metrics WHERE metric='halo.api.request' AND experiment='"+expErr+"' GROUP BY variant") {
		errRate[r["variant"].(string)] = r["e"].(float64)
	}
	if errRate["control"] > 0.06 || errRate["treatment"] < 0.10 {
		t.Errorf("landed API error rates %v, want ~0.03 / ~0.15", errRate)
	}
	// Gateway: request counts land exactly; histograms keep count (not only sum) and buckets.
	if got := ch.num(t, "SELECT sum(value) FROM halo_metrics WHERE metric='halo.gateway.requests' AND experiment='"+expGW+"'"); got != gwTotal {
		t.Errorf("gateway requests %v, want %v", got, gwTotal)
	}
	if got := ch.num(t, "SELECT sum(count) FROM halo_metrics WHERE metric='halo.gateway.latency_ms' AND experiment='"+expGW+"' AND arraySum(buckets) = count"); got != gwTotal {
		t.Errorf("gateway histogram count %v, want %v", got, gwTotal)
	}
	if n := ch.num(t, "SELECT uniqExact(unit_id) FROM halo_metrics WHERE metric='halo.gateway.requests' AND experiment='"+expGW+"' AND ring='ring1-canary' AND harness='claude-code'"); n != 2*usersPerArm {
		t.Errorf("gateway rows: %v units attributed by data point attributes, want %d", n, 2*usersPerArm)
	}

	// 3. Real CLI verdicts.
	// "verdict: reason [source]"; source is what the controller's auto-kill rule reads.
	analyze := func(exp, verdicts string) (verdict string) {
		cmd := exec.Command(halo, "exp", "analyze", exp, "--policy-dir", policy, "--clickhouse", ch.url,
			"--database", "halo", "--user", chUser, "--verdicts-file", verdicts, "--output", "json")
		cmd.Env = append(os.Environ(), "HALO_CLICKHOUSE_PASSWORD="+chPass)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("halo exp analyze %s: %v\n%s%s", exp, err, out, stderr.String())
		}
		var rep struct {
			Verdict    string `json:"verdict"`
			Reason     string `json:"reason"`
			Source     string `json:"source"`
			NControl   int    `json:"nControl"`
			NTreatment int    `json:"nTreatment"`
		}
		if err := json.Unmarshal(out, &rep); err != nil {
			t.Fatalf("decode %s: %v", out, err)
		}
		t.Logf("%s: %s (%s) source=%q n=%d/%d", exp, rep.Verdict, rep.Reason, rep.Source, rep.NControl, rep.NTreatment)
		if rep.NControl != usersPerArm || rep.NTreatment != usersPerArm {
			t.Errorf("%s: want %d users per arm, got %d/%d", exp, usersPerArm, rep.NControl, rep.NTreatment)
		}
		return rep.Verdict + ": " + rep.Reason + " [" + rep.Source + "]"
	}
	vf := filepath.Join(t.TempDir(), "verdicts.json")
	for _, tc := range []struct{ exp, want, source string }{
		// CLI-decided rollbacks: open a PR / notify, but never auto-kill.
		{expCost, "rollback: guardrail halo.cost.usd_per_session", "[cli]"},
		{expErr, "rollback: guardrail halo.api.error_rate", "[cli]"},
		{expLat, "rollback: guardrail halo.latency.p95_ms", "[cli]"},
		{expGW, "rollback: guardrail halo.latency.p95_ms", "[gateway]"}, // CLI latency is identical: only the gateway source sees it
		{expNull, "continue: ", "[]"},                                   // the forged CLI-receiver gateway regression was dropped
	} {
		if v := analyze(tc.exp, vf); !strings.HasPrefix(v, tc.want) || !strings.HasSuffix(v, tc.source) {
			t.Errorf("%s: verdict %q, want prefix %q and source %s", tc.exp, v, tc.want, tc.source)
		}
	}
	// Judge score is consumable by analyze: eval-sourced evidence decides a verdict.
	if v := analyze(expJudge, filepath.Join(t.TempDir(), "judge-verdicts.json")); !strings.HasPrefix(v, "rollback: primary halo.eval.judge.score significantly worse") || !strings.HasSuffix(v, "[eval]") {
		t.Errorf("%s: verdict %q, want an eval-sourced rollback on halo.eval.judge.score", expJudge, v)
	}
	b, err := os.ReadFile(vf)
	if err != nil {
		t.Fatal(err)
	}
	var vs []map[string]any
	if err := json.Unmarshal(b, &vs); err != nil || len(vs) != len(obsExperiments) {
		t.Fatalf("verdicts file: %v %s", err, b)
	}
	if !strings.Contains(string(b), `"rollback"`) || !strings.Contains(string(b), expCost) {
		t.Errorf("verdicts file lacks the rollback for %s: %s", expCost, b)
	}

	// 4. Grafana: provisioned datasource healthy, dashboard present, every panel query runs and returns data.
	gget := func(path string) []byte { return grafanaDo(t, grafana, http.MethodGet, path, nil) }
	if !strings.Contains(string(gget("/api/health")), `"database": "ok"`) {
		t.Errorf("grafana health: %s", gget("/api/health"))
	}
	var dsh struct{ Status, Message string }
	_ = json.Unmarshal(gget("/api/datasources/uid/halo-clickhouse/health"), &dsh)
	if dsh.Status != "OK" {
		t.Errorf("datasource health: %+v", dsh)
	}
	var dash struct {
		Dashboard struct {
			Title  string
			Panels []struct {
				Title   string
				Targets []map[string]any
			}
		}
	}
	if err := json.Unmarshal(gget("/api/dashboards/uid/halo-fleet"), &dash); err != nil || len(dash.Dashboard.Panels) != 7 {
		t.Fatalf("dashboard: %v %+v", err, dash.Dashboard)
	}
	now := time.Now()
	for _, p := range dash.Dashboard.Panels {
		for _, tg := range p.Targets {
			tg["datasource"] = map[string]any{"type": "grafana-clickhouse-datasource", "uid": "halo-clickhouse"}
			tg["rawSql"] = strings.ReplaceAll(tg["rawSql"].(string), "${experiment}", expCost)
		}
		body, _ := json.Marshal(map[string]any{"queries": p.Targets,
			"from": fmt.Sprint(now.Add(-24 * time.Hour).UnixMilli()), "to": fmt.Sprint(now.Add(time.Hour).UnixMilli())})
		var res struct {
			Results map[string]struct {
				Error  string
				Frames []struct {
					Data struct{ Values [][]any }
				}
			}
		}
		if err := json.Unmarshal(grafanaDo(t, grafana, http.MethodPost, "/api/ds/query", body), &res); err != nil {
			t.Errorf("panel %q: %v", p.Title, err)
			continue
		}
		r := res.Results["A"]
		if r.Error != "" || len(r.Frames) == 0 || len(r.Frames[0].Data.Values) == 0 || len(r.Frames[0].Data.Values[0]) == 0 {
			t.Errorf("panel %q: error=%q frames=%d (want data)", p.Title, r.Error, len(r.Frames))
		}
	}
}

// runEvalOnline drives the real `halo eval online` (with --policy-dir, so
// each control arm carries its experiment's control variant name) over one
// plaintext pair store. The fake gateway judge (Anthropic Messages wire)
// grades a response "score=X" as X on every criterion. Pairs:
//   - expCost: 4 pairs, control 0.6 / treatment 0.8 (dashboard + view averages);
//   - expJudge (shadow): usersPerArm pairs, primary ~0.75 vs sonnet-next ~0.55,
//     so `halo exp analyze` must roll it back on eval evidence.
//
// Readings go to the collector's eval receiver (its own token): halo.source=eval.
func runEvalOnline(t *testing.T, halo, root, policy, evalOTLP, tokFile string) {
	t.Helper()
	scoreRE := regexp.MustCompile(`score=([0-9.]+)`)
	judge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		score := "0"
		if m := scoreRE.FindSubmatch(b); m != nil {
			score = string(m[1])
		}
		reply := `{"scores": {"correctness": ` + score + `, "minimality": ` + score + `, "idiom": ` + score + `}, "rationale": "synthetic"}`
		out, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": reply}}})
		_, _ = w.Write(out)
	}))
	defer judge.Close()
	var pairs bytes.Buffer
	add := func(id, exp, cand string, ctl, trt float64) {
		p := map[string]any{"id": id, "time": time.Now().UTC(), "experiment": exp, "protocol": "anthropic-messages",
			"request":   map[string]any{"messages": []any{}},
			"control":   map[string]any{"target": map[string]any{}, "status": 200, "response": fmt.Sprintf("score=%.4f", ctl)},
			"candidate": map[string]any{"target": map[string]any{"variant": cand}, "status": 200, "response": fmt.Sprintf("score=%.4f", trt)}}
		b, _ := json.Marshal(p)
		pairs.Write(append(b, '\n'))
	}
	for i := range 4 {
		add(fmt.Sprintf("obs-pair-%d", i), expCost, "treatment", 0.6, 0.8)
	}
	rng := rand.New(rand.NewSource(11))
	for i := range usersPerArm {
		add(fmt.Sprintf("obs-judge-%d", i), expJudge, "sonnet-next", 0.75+0.05*rng.NormFloat64(), 0.55+0.05*rng.NormFloat64())
	}
	pf := filepath.Join(t.TempDir(), "pairs.jsonl")
	if err := os.WriteFile(pf, pairs.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(halo, "eval", "online", "--pairs", pf, "--rubric", filepath.Join(root, "evals/rubrics/code-change-quality.yaml"),
		"--judge-url", judge.URL, "--judge-model", "judge-pinned-1", "--sample", "0", "--policy-dir", policy,
		"--otlp", evalOTLP, "--otlp-token-file", tokFile).CombinedOutput()
	if err != nil {
		t.Fatalf("halo eval online: %v\n%s", err, out)
	}
	t.Logf("halo eval online:\n%s", out)
}

// sendGatewayMetrics drives halo-proxy's real emitter (OTLP/protobuf) for exp:
// per arm usersPerArm verified users x gwReqsPerSess requests, errRate of them
// failing with errStatus in both arms, treatment latency x mult.
func sendGatewayMetrics(ctx context.Context, t *testing.T, otlp, tokenFile, exp string, mult float64, errStatus int, errRate float64) {
	t.Helper()
	e, err := gwmetrics.New(gwmetrics.Config{OTLPEndpoint: otlp, Protocol: gwmetrics.ProtoProtobuf, UnitSalt: "obs-e2e", TokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	for _, arm := range []struct {
		variant string
		mult    float64
	}{{"control", 1}, {"treatment", mult}} {
		for u := 0; u < usersPerArm; u++ {
			for i := 0; i < gwReqsPerSess; i++ {
				status := 200
				if rng.Float64() < errRate {
					status = errStatus
				}
				e.Record(gwmetrics.Request{Ring: "ring1-canary", Release: "2.1.300", Experiment: exp, Variant: arm.variant,
					Harness: "claude-code", Model: "claude-sonnet-4-5", Subject: fmt.Sprintf("%s-%d@acme.test", arm.variant, u), Status: status,
					Latency: time.Duration(1000 * arm.mult * math.Exp(0.3*rng.NormFloat64()) * float64(time.Millisecond))})
			}
		}
	}
	if err := e.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func grafanaDo(t *testing.T, base, method, path string, body []byte) []byte {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
	req.SetBasicAuth("admin", chPass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("grafana %s %s: %d %s", method, path, resp.StatusCode, b)
	}
	return b
}
