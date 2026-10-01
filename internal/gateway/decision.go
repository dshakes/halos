package gateway

import (
	"slices"

	"github.com/halos-dev/halos/internal/assign"
	"github.com/halos-dev/halos/internal/policy"
)

// Headers the gateway stamps on upstream requests. Everything under HaloPrefix
// is owned by the gateway; client-supplied values are always discarded.
const (
	HaloPrefix       = "x-halo-"
	HeaderRing       = "x-halo-ring"
	HeaderRelease    = "x-halo-release"
	HeaderExperiment = "x-halo-experiment"
	HeaderVariant    = "x-halo-variant"

	RingUnknown = "unknown"
)

// RequestInfo is everything Decide may look at.
type RequestInfo struct {
	UserID     string // from the auth gateway's identity header only
	Groups     []string
	ModelAlias string
	SessionID  string
	Harness    string
	Protocol   string
	FirstTurn  bool
}

// ShadowTarget is one candidate a request should be mirrored to.
type ShadowTarget struct {
	Experiment string
	Variant    string
	Upstream   string // URL
	Model      string
}

// Decision is the routing outcome for one request.
type Decision struct {
	Ring          string
	Release       string
	Experiment    string
	Variant       string
	UpstreamName  string
	Upstream      string // URL; "" = leave Kong's default service
	UpstreamModel string // "" = leave the model untouched
	Headers       map[string]string
	Shadow        []ShadowTarget
}

// Decide is pure and deterministic for a given (org, req).
func Decide(org *policy.Org, req RequestInfo) Decision {
	d := Decision{Ring: RingUnknown, Headers: map[string]string{}}
	if org == nil {
		d.Headers[HeaderRing] = RingUnknown
		return d
	}
	sub := policy.Subject{ID: req.UserID, Groups: req.Groups}
	known := req.UserID != ""
	if known {
		if r := org.ResolveRing(sub); r != nil {
			d.Ring, d.Release = r.Name, r.Release
		}
	}

	route, routed := gwRoute(org.Gateway, req.ModelAlias)
	// No verified identity (or unknown ring) => default routing, no experiments.
	// The first traffic-axis ab/canary experiment the subject is in routes and
	// owns the x-halo-experiment/variant attribution. A client-axis experiment
	// never routes (its variants are releases on the machine); the gateway
	// computes the same variant halod applied (same ResolveVariant, same hash)
	// and attributes the request to it only when no traffic-axis experiment
	// did, so it can never displace a traffic experiment's routing.
	var clientExp, clientVar string
	if known && d.Ring != RingUnknown {
		for _, e := range org.Experiments {
			switch e.Type {
			case policy.ExperimentAB, policy.ExperimentCanary:
				if e.Axis == policy.AxisClient {
					if clientExp == "" {
						if v := e.ResolveVariant(sub, d.Ring); v != nil {
							clientExp, clientVar = e.Name, v.Name
						}
					}
					continue
				}
				if d.Experiment != "" {
					continue
				}
				v := e.ResolveVariant(sub, d.Ring)
				if v == nil {
					continue
				}
				d.Experiment, d.Variant = e.Name, v.Name
				if r, ok := v.Routes[req.ModelAlias]; ok {
					route, routed = r, true
				}
			case policy.ExperimentShadow:
				d.Shadow = append(d.Shadow, shadowTargets(org, e, d.Ring, req)...)
			}
		}
	}
	if d.Experiment == "" && clientExp != "" {
		d.Experiment, d.Variant = clientExp, clientVar
	}

	if routed {
		d.UpstreamName, d.UpstreamModel = route.Upstream, route.Model
		if u, ok := upstreamURL(org.Gateway, route.Upstream); ok {
			d.Upstream = u.URL
		}
	}
	d.Headers[HeaderRing] = d.Ring
	if d.Release != "" {
		d.Headers[HeaderRelease] = d.Release
	}
	if d.Experiment != "" {
		d.Headers[HeaderExperiment] = d.Experiment
		d.Headers[HeaderVariant] = d.Variant
	}
	return d
}

func gwRoute(g *policy.Gateway, alias string) (policy.ModelRoute, bool) {
	if g == nil {
		return policy.ModelRoute{}, false
	}
	r, ok := g.Models[alias]
	return r, ok
}

func upstreamURL(g *policy.Gateway, name string) (policy.Upstream, bool) {
	if g == nil {
		return policy.Upstream{}, false
	}
	u, ok := g.Upstreams[name]
	return u, ok
}

// shadowTargets returns the candidates for a shadow experiment, or nil when
// this request is not sampled. Sampling is keyed on the session so a whole
// session is either mirrored or not; only first-turn requests are eligible.
func shadowTargets(org *policy.Org, e *policy.Experiment, ring string, req RequestInfo) []ShadowTarget {
	if e.Status != "running" || !slices.Contains(e.Rings, ring) || !req.FirstTurn || req.SessionID == "" {
		return nil
	}
	salt := e.Salt
	if salt == "" {
		salt = e.Name
	}
	if assign.Bucket(salt+"/shadow", req.SessionID) >= assign.Share(e.SampleRate) {
		return nil
	}
	var out []ShadowTarget
	for _, v := range e.Variants {
		r, ok := v.Routes[req.ModelAlias]
		if v.Control || !ok {
			continue
		}
		t := ShadowTarget{Experiment: e.Name, Variant: v.Name, Model: r.Model}
		if u, ok := upstreamURL(org.Gateway, r.Upstream); ok {
			t.Upstream = u.URL
		}
		out = append(out, t)
	}
	return out
}
