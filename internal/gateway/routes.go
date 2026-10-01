package gateway

import (
	"slices"
	"sort"

	"github.com/dshakes/halos/internal/policy"
)

// RouteRow is the effective route of one alias for a caller.
type RouteRow struct {
	Alias      string      `json:"alias"`
	Ring       string      `json:"ring"`
	Experiment string      `json:"experiment,omitempty"` // traffic-axis experiment that supplied the route
	Variant    string      `json:"variant,omitempty"`
	Targets    []TargetRow `json:"targets"`
}

// TargetRow is one attempt-order entry; Selected marks where a request lands
// when every target is healthy.
type TargetRow struct {
	Order          int      `json:"order"`
	Selected       bool     `json:"selected"`
	Upstream       string   `json:"upstream"`
	Kind           string   `json:"kind"`
	Model          string   `json:"model"`
	Weight         float64  `json:"weight,omitempty"`
	Priority       int      `json:"priority"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	SkippedBy      []string `json:"skippedByHarnesses,omitempty"` // harnesses whose wire protocol this target cannot serve
}

// RouteTable returns every alias's effective routes for req (UserID, Groups and
// SessionID decide the ring, experiment variant and weighted pick; ModelAlias
// is ignored). Anonymous callers (no user, no session) see policy order.
func RouteTable(org *policy.Org, req RequestInfo) []RouteRow {
	if org == nil || org.Gateway == nil {
		return nil
	}
	aliases := make([]string, 0, len(org.Gateway.Models))
	for a := range org.Gateway.Models {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	var rows []RouteRow
	for _, alias := range aliases {
		r := req
		r.ModelAlias = alias
		d := Decide(org, r)
		row := RouteRow{Alias: alias, Ring: d.Ring, Experiment: d.Experiment, Variant: d.Variant}
		for i, t := range d.Route {
			up := org.Gateway.Upstreams[t.Upstream]
			tr := TargetRow{Order: i + 1, Selected: i == 0, Upstream: t.Upstream, Kind: up.Kind, Model: t.Model,
				Weight: t.Weight, Priority: t.Priority, TimeoutSeconds: t.TimeoutSeconds}
			for h, proto := range org.Gateway.Protocols {
				if !policy.KindServes(up.Kind, proto) {
					tr.SkippedBy = append(tr.SkippedBy, h)
				}
			}
			slices.Sort(tr.SkippedBy)
			row.Targets = append(row.Targets, tr)
		}
		rows = append(rows, row)
	}
	return rows
}
