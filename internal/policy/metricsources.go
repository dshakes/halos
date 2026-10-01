package policy

import "fmt"

// onlineMetrics rejects ab/canary metrics that live traffic can never decide:
// eval-only metrics, metrics with no online source, and CLI-only metrics on a
// traffic-axis experiment (the gateway assigns the variant; the CLI's
// telemetry never carries it). Shadow experiments are graded offline.
func (v *validator) onlineMetrics(path string, e *Experiment) {
	if e.Type != ExperimentAB && e.Type != ExperimentCanary {
		return
	}
	goals := map[string]string{path + ".metrics.primary.metric": e.Metrics.Primary.Metric}
	for i, g := range e.Metrics.Guardrails {
		goals[fmt.Sprintf("%s.metrics.guardrails[%d].metric", path, i)] = g.Metric
	}
	for _, p := range sortedKeys(goals) {
		m, ok := LookupMetric(goals[p])
		if !ok {
			continue // reported by v.metric
		}
		cli, gw := m.HasSource(SourceOnlineCLI), m.HasSource(SourceOnlineGateway)
		switch {
		case m.ShadowOnly():
			v.errf(p, "%s is graded on halo-shadow pairs, which only shadow experiments (and rollout dark-launch steps) produce; this %s experiment would never get samples", m.Name, e.Type)
		case m.HasSource(SourceEval) && !cli && !gw:
			v.errf(p, "%s is only measured by `halo eval`; use it in eval gates, not online guardrails", m.Name)
		case !cli && !gw:
			v.errf(p, "%s has no online metric source yet, so this %s experiment can never decide on it", m.Name, e.Type)
		case e.Axis == AxisTraffic && !gw:
			v.errf(p, "%s is measured only by the CLIs, which never see the gateway-assigned variant of a traffic-axis experiment; use a gateway-sourced metric (%s)", m.Name, gatewayMetrics())
		}
	}
}

func gatewayMetrics() string {
	var s string
	for _, m := range MetricRegistry {
		if m.HasSource(SourceOnlineGateway) {
			if s != "" {
				s += ", "
			}
			s += m.Name
		}
	}
	return s
}
