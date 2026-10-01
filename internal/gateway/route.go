package gateway

import (
	"slices"
	"strconv"

	"github.com/dshakes/halos/internal/assign"
	"github.com/dshakes/halos/internal/policy"
)

// StickyKey is what weighted route choice hashes: the verified identity plus
// the harness session, so a session stays on one target. "" (anonymous, no
// session) means no stickiness is possible: the first-priority target is used.
func StickyKey(userID, sessionID string) string {
	if userID == "" && sessionID == "" {
		return ""
	}
	return userID + "\x00" + sessionID
}

// RouteOrder returns the route's targets in attempt order for key. Targets are
// grouped into priority tiers (ascending). Within a tier the weighted pick
// (internal/assign) goes first and the rest follow in policy order; a tier
// without weights keeps policy order. The first element is the target a
// request lands on when everything is healthy.
func RouteOrder(alias string, r policy.ModelRoute, key string) []policy.RouteTarget {
	ts := slices.Clone(r.Candidates())
	if len(ts) < 2 {
		return ts
	}
	slices.SortStableFunc(ts, func(a, b policy.RouteTarget) int { return a.Priority - b.Priority })
	out := make([]policy.RouteTarget, 0, len(ts))
	for i := 0; i < len(ts); {
		j := i + 1
		for j < len(ts) && ts[j].Priority == ts[i].Priority {
			j++
		}
		out = append(out, orderTier(alias, ts[i:j], key)...)
		i = j
	}
	return out
}

func orderTier(alias string, tier []policy.RouteTarget, key string) []policy.RouteTarget {
	if len(tier) < 2 || key == "" {
		return tier
	}
	w := make([]float64, len(tier))
	for i, t := range tier {
		w[i] = t.Weight
	}
	first := assign.Pick("route/"+alias+"/"+strconv.Itoa(tier[0].Priority), key, w)
	if first <= 0 { // no weights, or policy order already leads with the pick
		return tier
	}
	out := append([]policy.RouteTarget{tier[first]}, tier[:first]...)
	return append(out, tier[first+1:]...)
}
