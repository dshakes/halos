// Package obsassets keeps the observability assets that exist in more than one form in step.
//
// The alert rules live once, in deploy/helm/halos/files/prometheus-rules.yaml (Prometheus rule-group syntax). The chart renders
// them as a PrometheusRule, and GrafanaAlerts derives the Grafana unified-alerting provisioning file from them so a team on
// Grafana alerting gets the same alerts. The dashboards live once in deploy/observability/grafana/dashboards and the chart
// ships byte-identical copies. `go run ./internal/tools/obsassets` regenerates the derived files; the package test fails when
// a committed copy drifts, when an alert is missing from the operations guide, or when a rule or panel names a metric that no
// binary exports.
package obsassets

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Paths, relative to the repository root.
const (
	RulesPath          = "deploy/helm/halos/files/prometheus-rules.yaml"
	GrafanaAlertsPath  = "deploy/observability/grafana/provisioning/alerting/halos-alerts.yaml"
	DashboardsDir      = "deploy/observability/grafana/dashboards"
	ChartDashboardsDir = "deploy/helm/halos/files/dashboards"
	OperationsGuide    = "docs/src/content/docs/guides/operations.md"
)

// DatasourceUID is the Grafana datasource uid the generated alert queries use. It is the uid kube-prometheus-stack gives its
// Prometheus datasource; change it in the generated file (or provision a datasource with this uid) for another setup.
const DatasourceUID = "prometheus"

// Rule is one Prometheus alerting rule.
type Rule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// Group is a Prometheus rule group.
type Group struct {
	Name  string `yaml:"name"`
	Rules []Rule `yaml:"rules"`
}

// RuleFile is the content of prometheus-rules.yaml.
type RuleFile struct {
	Groups []Group `yaml:"groups"`
}

// ParseRules decodes and validates the rule file: unique alert names, an expression, a severity label and a summary on every rule.
func ParseRules(b []byte) (RuleFile, error) {
	var rf RuleFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&rf); err != nil {
		return RuleFile{}, fmt.Errorf("parse rules: %w", err)
	}
	seen := map[string]bool{}
	for _, g := range rf.Groups {
		if g.Name == "" || len(g.Rules) == 0 {
			return RuleFile{}, fmt.Errorf("rule group %q: name and at least one rule are required", g.Name)
		}
		for _, r := range g.Rules {
			switch {
			case r.Alert == "" || strings.TrimSpace(r.Expr) == "":
				return RuleFile{}, fmt.Errorf("group %s: a rule without alert or expr", g.Name)
			case seen[r.Alert]:
				return RuleFile{}, fmt.Errorf("duplicate alert %s", r.Alert)
			case r.Labels["severity"] == "":
				return RuleFile{}, fmt.Errorf("alert %s: severity label is required", r.Alert)
			case r.Annotations["summary"] == "":
				return RuleFile{}, fmt.Errorf("alert %s: summary annotation is required", r.Alert)
			}
			seen[r.Alert] = true
		}
	}
	return rf, nil
}

// AlertNames lists every alert in file order.
func (rf RuleFile) AlertNames() []string {
	var out []string
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			out = append(out, r.Alert)
		}
	}
	return out
}

var metricRe = regexp.MustCompile(`\bhalo_[a-z0-9_]+`)

// MetricNames returns the distinct halo_* metric names mentioned in s, histogram suffixes (_bucket, _sum, _count) included.
func MetricNames(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range metricRe.FindAllString(s, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// ---- Grafana unified alerting provisioning ----

type grafanaFile struct {
	APIVersion int            `yaml:"apiVersion"`
	Groups     []grafanaGroup `yaml:"groups"`
}

type grafanaGroup struct {
	OrgID    int           `yaml:"orgId"`
	Name     string        `yaml:"name"`
	Folder   string        `yaml:"folder"`
	Interval string        `yaml:"interval"`
	Rules    []grafanaRule `yaml:"rules"`
}

type grafanaRule struct {
	UID          string            `yaml:"uid"`
	Title        string            `yaml:"title"`
	Condition    string            `yaml:"condition"`
	Data         []grafanaQuery    `yaml:"data"`
	NoDataState  string            `yaml:"noDataState"`
	ExecErrState string            `yaml:"execErrState"`
	For          string            `yaml:"for"`
	Annotations  map[string]string `yaml:"annotations,omitempty"`
	Labels       map[string]string `yaml:"labels,omitempty"`
}

type grafanaQuery struct {
	RefID             string         `yaml:"refId"`
	RelativeTimeRange *timeRange     `yaml:"relativeTimeRange,omitempty"`
	DatasourceUID     string         `yaml:"datasourceUid"`
	Model             map[string]any `yaml:"model"`
}

type timeRange struct {
	From int `yaml:"from"`
	To   int `yaml:"to"`
}

// GrafanaAlerts renders rf as a Grafana alert-rule provisioning file.
//
// A Prometheus alert fires for every series its expression returns. Grafana evaluates a rule from a condition instead, so each
// rule becomes: A the expression as an instant query rewritten to `(expr) * 0 + 1` (the same series, with the value 1, labels
// kept so annotations like {{ $labels.sink }} still resolve), B reduce A to its last value, C threshold B > 0. An empty result
// is "no data", which maps to OK, exactly as an alert that returns nothing in Prometheus.
func GrafanaAlerts(rf RuleFile) ([]byte, error) {
	out := grafanaFile{APIVersion: 1}
	for _, g := range rf.Groups {
		gg := grafanaGroup{OrgID: 1, Name: g.Name, Folder: "Halos", Interval: "1m"}
		for _, r := range g.Rules {
			forDur := r.For
			if forDur == "" {
				forDur = "0s"
			}
			expr := "(" + strings.TrimSpace(r.Expr) + ") * 0 + 1"
			gg.Rules = append(gg.Rules, grafanaRule{
				UID:       "halos-" + r.Alert,
				Title:     r.Alert,
				Condition: "C",
				Data: []grafanaQuery{
					{RefID: "A", RelativeTimeRange: &timeRange{From: 600, To: 0}, DatasourceUID: DatasourceUID,
						Model: map[string]any{"refId": "A", "expr": expr, "instant": true, "intervalMs": 1000, "maxDataPoints": 43200}},
					{RefID: "B", DatasourceUID: "__expr__",
						Model: map[string]any{"refId": "B", "type": "reduce", "expression": "A", "reducer": "last", "settings": map[string]any{"mode": "dropNN"}}},
					{RefID: "C", DatasourceUID: "__expr__",
						Model: map[string]any{"refId": "C", "type": "threshold", "expression": "B", "conditions": []any{
							map[string]any{"evaluator": map[string]any{"type": "gt", "params": []any{0}}},
						}}},
				},
				NoDataState:  "OK",
				ExecErrState: "Error",
				For:          forDur,
				Annotations:  r.Annotations,
				Labels:       r.Labels,
			})
		}
		out.Groups = append(out.Groups, gg)
	}
	var buf bytes.Buffer
	buf.WriteString("# GENERATED by `make obs-assets` from deploy/helm/halos/files/prometheus-rules.yaml. Do not edit.\n")
	buf.WriteString("# Grafana unified alerting provisioning (mount under /etc/grafana/provisioning/alerting). Queries use the\n")
	buf.WriteString("# Prometheus datasource with uid `" + DatasourceUID + "`; the alerts need kube-state-metrics for HaloProxyBelowTwoReplicas.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("encode grafana alerts: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode grafana alerts: %w", err)
	}
	return buf.Bytes(), nil
}
