package policy

import (
	"fmt"
	"slices"
	"strings"
)

// guardHarnessWire: every harness a ring (or a client-axis experiment
// variant) delivers starts on a model alias (harnesses.<h>.model, else
// models.default) that some target's upstream can answer in the harness's
// wire. halo-proxy forwards a pass-through wire unchanged, so e.g. Codex's
// OpenAI Responses request sent to api.anthropic.com fails at runtime;
// KindServes alone cannot catch that. No target that can answer is an error;
// only orchestrator targets (which may translate) is a warning.
func guardHarnessWire(o *Org) []Issue {
	g := o.Gateway
	if g == nil {
		return nil
	}
	delivered := map[string]bool{}
	for _, r := range o.Rings {
		delivered[r.Profile] = true
	}
	for _, e := range o.Experiments {
		if e.Axis == AxisClient {
			for _, v := range e.Variants {
				delivered[v.Profile] = true
			}
		}
	}
	var out []Issue
	for _, name := range sortedKeys(delivered) {
		p, err := o.ResolveProfile(name)
		if err != nil {
			continue // reported by Validate
		}
		for _, h := range sortedKeys(p.Harnesses) {
			wire := g.Protocols[h]
			if wire == "" {
				wire = toolProtocols[h]
			}
			alias, path := p.Harnesses[h].Model, fmt.Sprintf("profiles[%s].harnesses.%s.model", name, h)
			if alias == "" {
				alias, path = p.Models.Default, fmt.Sprintf("profiles[%s].models.default", name)
			}
			route, ok := g.Models[alias]
			if wire == "" || alias == "" || !ok {
				continue // not routed, no model, or an unknown alias (reported by Validate)
			}
			var kinds []string
			can, maybe := false, false
			for _, t := range route.Candidates() {
				k := g.Upstreams[t.Upstream].Kind
				kinds = append(kinds, t.Upstream+" ("+k+")")
				switch {
				case slices.Contains(providerWires[k], wire):
					can = true
				case k == "orchestrator" && slices.Contains(g.Upstreams[t.Upstream].Serves, wire):
					can = true // declared by the operator
				case k == "orchestrator":
					maybe = true
				}
			}
			switch {
			case can:
			case maybe:
				out = append(out, gi(SeverityWarning, path, "%s speaks %s; model %q routes to %s, which halos cannot prove answers it (an orchestrator may translate or pass the wire through): if it does, declare it with serves: [%s] on that upstream; else point %s at an alias on a provider that speaks %s",
					h, wire, alias, strings.Join(kinds, ", "), wire, h, wire))
			default:
				out = append(out, gi(SeverityError, path, "%s speaks %s, but model %q routes only to %s, which cannot answer it. %s",
					h, wire, alias, strings.Join(kinds, ", "), wireFix(h, p.Harnesses[h].Version, wire)))
			}
		}
	}
	return out
}

// wireFix says exactly what to add so harness h starts on a model that speaks wire.
func wireFix(h, version, wire string) string {
	vendor := toolVendor[h]
	if vendor == "" {
		return fmt.Sprintf("Set harnesses.%s.model to a gateway alias on an upstream that speaks %s.", h, wire)
	}
	prov, model, _ := strings.Cut(vendor, "/")
	return fmt.Sprintf("Start %s on its own model: in simple mode, tools: {%s: {version: %s, model: %s}} and models: {%s: %s}; "+
		"in a Profile, harnesses.%s.model: %s with gateway.models.%s: {upstream: <a %s upstream>, model: %s}.",
		h, h, version, h, h, vendor, h, h, h, prov, model)
}
