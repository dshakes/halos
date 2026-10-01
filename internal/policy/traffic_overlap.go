package policy

import (
	"slices"
	"sort"
)

// guardTrafficOverlap: at the gateway a traffic-axis ab/canary experiment claims
// the requests for the aliases it routes, and per request only the first (by
// name) routes, so two running ones that route the same alias on a shared ring
// would leave the second with no traffic and no evidence, silently. Different
// aliases on one ring are fine. Shadow experiments mirror rather than route.
func guardTrafficOverlap(o *Org) []Issue {
	var out []Issue
	owner := map[[2]string]string{} // (ring, alias) -> experiment
	exps := slices.Clone(o.Experiments)
	sort.SliceStable(exps, func(i, j int) bool { return exps[i].Name < exps[j].Name })
	for _, e := range exps {
		if e.Axis != AxisTraffic || e.Status != "running" || (e.Type != ExperimentAB && e.Type != ExperimentCanary) {
			continue
		}
		aliases := map[string]bool{}
		for _, v := range e.Variants {
			for a := range v.Routes {
				aliases[a] = true
			}
		}
		keys := make([]string, 0, len(aliases))
		for a := range aliases {
			keys = append(keys, a)
		}
		sort.Strings(keys)
		for _, ring := range e.Rings {
			for _, a := range keys {
				k := [2]string{ring, a}
				if prev, dup := owner[k]; dup {
					out = append(out, gi(SeverityError, "experiments["+e.Name+"].rings",
						"running traffic experiments %q and %q both route alias %q on ring %q; the gateway routes only one (%q) and %q would get no traffic: pause one or split the rings",
						prev, e.Name, a, ring, prev, e.Name))
					continue
				}
				owner[k] = e.Name
			}
		}
	}
	return out
}

// TrafficOverlaps is the guard's finding for gateways, which log it when they
// load a snapshot that was never validated (they still route first by name).
func TrafficOverlaps(o *Org) []Issue { return guardTrafficOverlap(o) }
