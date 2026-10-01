package promote

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// Registry metrics the experiment YAML may name must not be read as literal
// halo_metrics names: the collector only writes halo.cost.usd, halo.tokens, ...
func TestSamplesDerivedMetrics(t *testing.T) {
	for m := range derivedSamples {
		if !policy.KnownMetric(m) {
			t.Errorf("derived metric %q is not in policy.MetricRegistry", m)
		}
	}
	var q string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q = string(b)
		_, _ = w.Write([]byte(`{"variant":"control","v":0.5}` + "\n"))
	}))
	defer srv.Close()
	ch := &ClickHouse{URL: srv.URL}

	for m, want := range map[string]string{
		"halo.cost.usd_per_session": "'halo.cost.usd'",
		"halo.tokens.per_session":   "'halo.tokens'",
		"halo.edit.accept_rate":     "attrs['decision'] = 'accept'",
	} {
		s, _, err := ch.Samples(context.Background(), "e", m)
		if err != nil || len(s["control"]) != 1 {
			t.Fatalf("%s: %v %v", m, s, err)
		}
		if !strings.Contains(q, want) || strings.Contains(q, "{metric:String}") || !strings.Contains(q, "HAVING v IS NOT NULL") {
			t.Errorf("%s: unexpected query %q", m, q)
		}
	}
	if _, _, err := ch.Samples(context.Background(), "e", "halo.task.success"); err != nil || !strings.Contains(q, "metric = {metric:String}") {
		t.Errorf("plain metric must bind the name: %q (%v)", q, err)
	}
}

// Every metric the registry says is measured online must have a query here,
// or an experiment using it can never decide (the gap `make obs-e2e` found).
func TestRegistryOnlineMetricsAreDerived(t *testing.T) {
	for _, m := range policy.MetricRegistry {
		online := m.HasSource(policy.SourceOnlineCLI) || m.HasSource(policy.SourceOnlineGateway)
		if _, ok := derivedSamples[m.Name]; online != ok {
			t.Errorf("%s: online source=%v but derived query=%v", m.Name, online, ok)
		}
		if m.HasSource(policy.SourceOnlineGateway) && len(derivedSamples[m.Name]) < 2 {
			t.Errorf("%s: gateway-sourced metric needs gateway + CLI alternatives", m.Name)
		}
	}
}

// Gateway rows take precedence; CLI events are the fallback; sources never mix.
func TestSamplesSourcePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		metric     string
		gwRows     bool
		wantQs     int
		lastSubstr string
		wantSource string
	}{
		{"gateway present", "halo.api.error_rate", true, 1, "'halo.gateway.requests'", SourceGateway},
		{"cli fallback", "halo.api.error_rate", false, 2, "'halo.api.request'", SourceCLI},
		{"p95 gateway", "halo.latency.p95_ms", true, 1, "sumForEachIf(buckets", SourceGateway},
		{"p95 cli fallback", "halo.latency.p95_ms", false, 2, "quantileExactIf(0.95)", SourceCLI},
		{"tool errors cli only", "halo.tool.error_rate", false, 1, "'halo.tool.call'", SourceCLI},
		{"plain metric is client-supplied", "halo.task.success", false, 1, "{metric:String}", SourceCLI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var qs []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				qs = append(qs, string(b))
				if strings.Contains(string(b), "halo.gateway.") && !tc.gwRows {
					return // no gateway data for this experiment
				}
				_, _ = w.Write([]byte(`{"variant":"control","v":1}` + "\n" + `{"variant":"treatment","v":2}` + "\n"))
			}))
			defer srv.Close()
			s, src, err := (&ClickHouse{URL: srv.URL}).Samples(context.Background(), "e", tc.metric)
			if err != nil || len(s["control"]) != 1 || len(s["treatment"]) != 1 {
				t.Fatalf("samples %v %v", s, err)
			}
			if src != tc.wantSource {
				t.Errorf("source %q, want %q", src, tc.wantSource)
			}
			if len(qs) != tc.wantQs || !strings.Contains(qs[len(qs)-1], tc.lastSubstr) {
				t.Fatalf("queries %d (want %d), last %q", len(qs), tc.wantQs, qs[len(qs)-1])
			}
			for _, q := range qs {
				if !strings.Contains(q, "unit_id != ''") {
					t.Errorf("unit-less rows must be excluded: %q", q)
				}
				// Every halo.gateway.* read is restricted to collector-stamped gateway rows.
				if strings.Count(q, "metric = 'halo.gateway.") != strings.Count(q, gatewayRows+" AND metric = 'halo.gateway.") {
					t.Errorf("gateway rows read without the halo.source=gateway filter: %q", q)
				}
			}
		})
	}
}

func TestSamplesErrorAndEmpty(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Code: 47. Unknown identifier", http.StatusBadRequest)
	}))
	defer bad.Close()
	if _, _, err := (&ClickHouse{URL: bad.URL}).Samples(context.Background(), "e", "halo.latency.p95_ms"); err == nil || !strings.Contains(err.Error(), "halo.latency.p95_ms") {
		t.Fatalf("want wrapped query error naming the metric, got %v", err)
	}
	empty := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer empty.Close()
	s, _, err := (&ClickHouse{URL: empty.URL}).Samples(context.Background(), "e", "halo.api.error_rate")
	if err != nil || len(s) != 0 {
		t.Fatalf("no data from any source: %v %v", s, err)
	}
}
