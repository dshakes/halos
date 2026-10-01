package gateway

import (
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/toggle"
)

// toggleRoute returns the route of the first traffic-axis toggle that is on
// for the verified subject and has a route for alias. Killed toggles are gone
// from org before this runs (KillSwitch.Apply), so they count as off. An
// experiment's variant route still wins over a toggle's.
func toggleRoute(org *policy.Org, sub policy.Subject, ring, alias string) (policy.ModelRoute, bool) {
	for _, t := range org.Toggles {
		if t.Axis != policy.AxisTraffic || t.Traffic == nil {
			continue
		}
		r, ok := t.Traffic.Routes[alias]
		if !ok {
			continue
		}
		if toggle.Eval(t.Name, t.Default, t.Rules, toggle.Subject{ID: sub.ID, Groups: sub.Groups, Ring: ring}, false).On {
			return r, true
		}
	}
	return policy.ModelRoute{}, false
}
