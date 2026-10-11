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
			wire := g.HarnessWire(h)
			alias, path := p.Harnesses[h].Model, fmt.Sprintf("profiles[%s].harnesses.%s.model", name, h)
			if alias == "" {
				alias, path = p.Models.Default, fmt.Sprintf("profiles[%s].models.default", name)
			}
			if _, ok := g.Models[alias]; wire == "" || alias == "" || !ok {
				continue // not routed, no model, or an unknown alias (reported by Validate)
			}
			fit, kinds := g.WireFit(alias, wire)
			can, maybe := fit == WireYes, fit == WireMaybe
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

// WireFitness is how well a model alias's route can answer a client wire.
type WireFitness int

const (
	WireNo    WireFitness = iota // no target can answer it (or the alias is unknown)
	WireMaybe                    // only orchestrators that do not declare it: they may translate
	WireYes                      // a target's provider (or a declaring orchestrator) answers it
)

// HarnessWire is the wire harness h speaks to this gateway ("" = the gateway does not route it).
func (g *Gateway) HarnessWire(h string) string {
	if w := g.Protocols[h]; w != "" {
		return w
	}
	return toolProtocols[h]
}

// WireFit reports whether alias routes to an upstream that answers wire, and
// lists each candidate target as "upstream (kind)". It is the check
// `halo validate` applies to a harness's start model (guardHarnessWire).
func (g *Gateway) WireFit(alias, wire string) (WireFitness, []string) {
	var kinds []string
	fit := WireNo
	if g.Engine == EngineExternal {
		// The external gateway picks the backend and translates; Halos only
		// renders the model id, so any routed alias fits.
		if len(g.Models[alias].Candidates()) == 0 {
			return WireNo, nil
		}
		return WireYes, []string{"external gateway"}
	}
	for _, t := range g.Models[alias].Candidates() {
		up := g.Upstreams[t.Upstream]
		kinds = append(kinds, t.Upstream+" ("+up.Kind+")")
		switch {
		case slices.Contains(providerWires[up.Kind], wire),
			up.Kind == "orchestrator" && slices.Contains(up.Serves, wire): // declared by the operator
			fit = WireYes
		case up.Kind == "orchestrator" && fit == WireNo:
			fit = WireMaybe
		}
	}
	return fit, kinds
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
