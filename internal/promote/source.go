package promote

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/telemetry"
)

// MemorySource is an in-memory MetricSource for tests and local analysis.
type MemorySource struct {
	Start    time.Time
	SpendUSD float64
	// Data is metric -> variant -> per-unit observations.
	Data map[string]map[string][]float64
	// Source is reported for every metric ("" = unknown, i.e. untrusted).
	Source string
}

func (m *MemorySource) Window(context.Context, string) (Window, error) {
	return Window{Start: m.Start, SpendUSD: m.SpendUSD}, nil
}

func (m *MemorySource) Samples(_ context.Context, _, metric string) (map[string][]float64, string, error) {
	return m.Data[metric], m.Source, nil
}

var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)

// ClickHouse reads the normalised halo_metrics table
// (see deploy/observability/clickhouse/schema.sql) over ClickHouse's HTTP
// interface. Values are bound with server-side query parameters, never
// interpolated.
type ClickHouse struct {
	URL      string // e.g. http://clickhouse:8123
	Database string
	User     string
	Password string
	Table    string       // default halo_metrics
	Client   *http.Client // default: 30s timeout
}

func (c *ClickHouse) table() (string, error) {
	t := c.Table
	if t == "" {
		t = "halo_metrics"
	}
	if !identRE.MatchString(t) {
		return "", fmt.Errorf("clickhouse: invalid table name %q", t)
	}
	return t, nil
}

// query runs sql and streams JSONEachRow lines to fn.
func (c *ClickHouse) query(ctx context.Context, sql string, params map[string]string, fn func(json.RawMessage) error) error {
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("clickhouse: bad URL: %w", err)
	}
	q := u.Query()
	if c.Database != "" {
		q.Set("database", c.Database)
	}
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(sql+" FORMAT JSONEachRow"))
	if err != nil {
		return fmt.Errorf("clickhouse: %w", err)
	}
	if c.User != "" {
		req.Header.Set("X-ClickHouse-User", c.User)
		req.Header.Set("X-ClickHouse-Key", c.Password)
	}
	hc := c.Client
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("clickhouse: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // best effort
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := fn(append(json.RawMessage(nil), sc.Bytes()...)); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("clickhouse: read response: %w", err)
	}
	return nil
}

// Window: first observation time and total halo.cost.usd for the experiment.
func (c *ClickHouse) Window(ctx context.Context, experiment string) (Window, error) {
	t, err := c.table()
	if err != nil {
		return Window{}, err
	}
	sql := "SELECT toFloat64(count()) AS n, toFloat64(toUnixTimestamp(min(ts))) AS start, " +
		"toFloat64(sumIf(value, metric = 'halo.cost.usd')) AS spend FROM " + t + " WHERE experiment = {exp:String}"
	var w Window
	err = c.query(ctx, sql, map[string]string{"exp": experiment}, func(raw json.RawMessage) error {
		var r struct{ N, Start, Spend float64 }
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if r.N > 0 {
			w = Window{Start: time.Unix(int64(r.Start), 0).UTC(), SpendUSD: r.Spend}
		}
		return nil
	})
	if err != nil {
		return Window{}, fmt.Errorf("clickhouse window: %w", err)
	}
	return w, nil
}

// derivedSamples computes the registry metrics (internal/policy.MetricRegistry)
// that are aggregates over the normalised rows the collector writes; the
// experiment YAML names the former, halo_metrics only holds the latter. The
// value is per (variant, unit); NULL (empty denominator) rows are dropped.
// Anything not listed is read as-is: per-unit mean of the metric of that name.
//
// Each metric lists its sources in precedence order: the first that yields any
// sample for the experiment wins, so an experiment with halo-proxy data is
// judged on the gateway's exact cohort attribution (halo.gateway.*) and falls
// back to CLI events (halo.api.request / halo.tool.call) otherwise. Sources are
// never mixed within one analysis: their units differ (gateway: hashed verified
// subject; CLI: user).
//
// Gateway rows count only with attrs['halo.source'] = 'gateway', which the
// collector stamps on its authenticated gateway receiver alone (the CLI
// receiver drops halo.gateway.* and overwrites halo.source); anything else is
// client-supplied, reported as SourceCLI, and never auto-kills.
var derivedSamples = map[string][]sampleExpr{
	"halo.cost.usd_per_session": {cli("sumIf(value, metric = 'halo.cost.usd') / nullIf(uniqExactIf(session_id, metric = 'halo.cost.usd'), 0)")},
	"halo.tokens.per_session": {cli("sumIf(value, metric = 'halo.tokens' AND coalesce(nullIf(attrs['type'], ''), attrs['gen_ai.token.type']) IN ('input', 'output'))" +
		" / nullIf(uniqExactIf(session_id, metric = 'halo.tokens'), 0)")},
	"halo.edit.accept_rate": {cli("sumIf(value, metric = 'halo.edit.decision' AND attrs['decision'] = 'accept')" +
		" / nullIf(sumIf(value, metric = 'halo.edit.decision'), 0)")},
	"halo.api.error_rate": {
		{SourceGateway, "sumIf(value, " + gatewayRows + " AND metric = 'halo.gateway.requests' AND attrs['status_class'] != '2xx') / nullIf(sumIf(value, " + gatewayRows + " AND metric = 'halo.gateway.requests'), 0)"},
		cli("countIf(metric = 'halo.api.request' AND attrs['error'] = '1') / nullIf(countIf(metric = 'halo.api.request'), 0)"),
	},
	"halo.latency.p50_ms":  {{SourceGateway, histQuantile(0.50, gatewayOK)}, cli(eventQuantile(0.50))},
	"halo.latency.p95_ms":  {{SourceGateway, histQuantile(0.95, gatewayOK)}, cli(eventQuantile(0.95))},
	"halo.tool.error_rate": {cli("countIf(metric = 'halo.tool.call' AND attrs['error'] = '1') / nullIf(countIf(metric = 'halo.tool.call'), 0)")},
	// Judge scores count only from the collector's authenticated eval receiver;
	// there is no CLI fallback (a client-forged quality score is no evidence).
	"halo.eval.judge.score": {{SourceEval, "if(countIf(" + evalScore + ") = 0, NULL, avgIf(value, " + evalScore + "))"}},
}

// Evidence sources (Report.Source): which collector receiver the samples came through.
const (
	SourceGateway = telemetry.SourceGateway // authenticated halo-proxy receiver: may auto-kill
	SourceCLI     = telemetry.SourceCLI     // developer-reachable receiver: client-controlled
	// SourceEval: the authenticated eval receiver (`halo eval online` judge
	// scores). Trusted for verdicts and PRs; never trips the kill switch.
	SourceEval = telemetry.SourceEval
)

// evalScore: per-pair judge scores stamped on the authenticated eval receiver.
const evalScore = "attrs['halo.source'] = '" + SourceEval + "' AND metric = 'halo.eval.judge.score'"

// sampleExpr is one per-unit aggregate and the source its rows come from.
type sampleExpr struct{ source, expr string }

func cli(expr string) sampleExpr { return sampleExpr{SourceCLI, expr} }

// gatewayRows: only rows the collector stamped on its authenticated receiver.
const gatewayRows = "attrs['halo.source'] = '" + SourceGateway + "'"

const gatewayOK = gatewayRows + " AND metric = 'halo.gateway.latency_ms' AND attrs['status_class'] = '2xx'"

// eventQuantile: exact quantile of the unit's successful CLI API call
// durations. Failed calls are excluded: fast 4xx/429s would otherwise make an
// error regression look like a latency improvement.
func eventQuantile(q float64) string {
	c := "metric = 'halo.api.request' AND attrs['error'] = '0'"
	return fmt.Sprintf("if(countIf(%s) = 0, NULL, quantileExactIf(%g)(value, %s))", c, q, c)
}

// histQuantile estimates the q-quantile of the unit's merged histogram
// buckets (rows matching cond, same bounds) by linear interpolation inside the
// bucket where the cumulative count crosses q, as Prometheus'
// histogram_quantile does. The +Inf bucket clamps to the last bound.
func histQuantile(q float64, cond string) string {
	b := "sumForEachIf(buckets, " + cond + ")"
	bnd := "anyIf(bounds, " + cond + ")"
	cum := "arrayCumSum(" + b + ")"
	target := fmt.Sprintf("(%g * arraySum(%s))", q, b)
	i := "arrayFirstIndex(c -> c >= " + target + ", " + cum + ")"
	lower := "if(" + i + " = 1, 0, " + bnd + "[" + i + " - 1])"
	upper := "if(" + i + " > length(" + bnd + "), " + bnd + "[length(" + bnd + ")], " + bnd + "[" + i + "])"
	before := "if(" + i + " = 1, 0, " + cum + "[" + i + " - 1])"
	return "if(arraySum(" + b + ") = 0, NULL, " + lower + " + (" + upper + " - " + lower + ") * (" + target + " - " + before + ") / " + b + "[" + i + "])"
}

// Samples returns one value per (variant, unit) and the evidence source: see
// derivedSamples, else the unit's mean of the metric (client-supplied: SourceCLI).
func (c *ClickHouse) Samples(ctx context.Context, experiment, metric string) (map[string][]float64, string, error) {
	t, err := c.table()
	if err != nil {
		return nil, "", err
	}
	exprs, derived := derivedSamples[metric]
	if !derived {
		exprs = []sampleExpr{cli("avg(value)")}
	}
	for _, se := range exprs {
		sql := "SELECT variant, toFloat64(" + se.expr + ") AS v FROM " + t +
			" WHERE experiment = {exp:String} AND unit_id != '' AND " + metricFilter(derived) + " GROUP BY variant, unit_id HAVING v IS NOT NULL"
		out := map[string][]float64{}
		err = c.query(ctx, sql, map[string]string{"exp": experiment, "metric": metric}, func(raw json.RawMessage) error {
			var r struct {
				Variant string  `json:"variant"`
				V       float64 `json:"v"`
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return err
			}
			out[r.Variant] = append(out[r.Variant], r.V)
			return nil
		})
		if err != nil {
			return nil, "", fmt.Errorf("clickhouse samples %s: %w", metric, err)
		}
		if len(out) > 0 {
			return out, se.source, nil
		}
	}
	return map[string][]float64{}, "", nil
}

// metricFilter: derived metrics scan every halo.* row of the experiment (the
// expression selects its own inputs); plain ones filter on the bound name.
func metricFilter(derived bool) string {
	if derived {
		return "startsWith(metric, 'halo.')"
	}
	return "metric = {metric:String}"
}
