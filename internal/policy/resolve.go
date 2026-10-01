package policy

import (
	"slices"

	"github.com/dshakes/halos/internal/assign"
)

// Subject is a user as seen by the control plane (from the IdP / auth gateway).
type Subject struct {
	ID     string
	Groups []string
}

// ringSalt keeps ring hashing independent from experiment hashing.
const ringSalt = "halos/rings"

// ResolveRing returns the ring a subject belongs to. Rings are walked in order:
// explicit user ids win, then explicit group membership, then each ring claims its Percent of the
// hash space (cumulatively, so ring1 5% + ring2 25% = buckets [0,500) and
// [500,3000)), then the Default ring catches everyone else.
func (o *Org) ResolveRing(s Subject) *Ring {
	for _, r := range o.Rings {
		if slices.Contains(r.Membership.Users, s.ID) {
			return r
		}
	}
	for _, r := range o.Rings {
		for _, g := range r.Membership.Groups {
			if slices.Contains(s.Groups, g) {
				return r
			}
		}
	}
	b := assign.Bucket(ringSalt, s.ID)
	var lo int
	for _, r := range o.Rings {
		if r.Membership.Percent <= 0 {
			continue
		}
		hi := lo + assign.Share(r.Membership.Percent/100)
		if b >= lo && b < hi {
			return r
		}
		lo = hi
	}
	for _, r := range o.Rings {
		if r.Membership.Default {
			return r
		}
	}
	return nil
}

// ResolveVariant returns the experiment variant for a subject, or nil if the
// subject's ring is not enrolled or the experiment isn't running.
func (e *Experiment) ResolveVariant(s Subject, ring string) *Variant {
	if e.Status != "running" || !slices.Contains(e.Rings, ring) {
		return nil
	}
	w := make([]float64, len(e.Variants))
	for i, v := range e.Variants {
		w[i] = v.Weight
	}
	salt := e.Salt
	if salt == "" {
		salt = e.Name
	}
	i := assign.Pick(salt, s.ID, w)
	if i < 0 {
		return nil
	}
	return &e.Variants[i]
}
