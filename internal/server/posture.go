package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// DefaultPostureMaxAge is how old a device's last report may be before its
// posture is stale: three default halod intervals (15m).
const DefaultPostureMaxAge = 45 * time.Minute

// getGatewayPosture: GET /api/v1/gateway/posture?subject=<id> (gateway token).
// The verdict covers every enrolled device of the subject; see posture.
func (s *Server) getGatewayPosture(w http.ResponseWriter, r *http.Request) {
	if !s.gatewayEnabled(capPosture) {
		apiErr(w, http.StatusNotFound, "posture not configured")
		return
	}
	if !s.gatewayAuth(w, r, capPosture) {
		return
	}
	sub := r.URL.Query().Get("subject")
	if sub == "" || len(sub) > 256 {
		apiErr(w, http.StatusBadRequest, "subject required (<=256 chars)")
		return
	}
	v := s.posture(r.Context(), sub)
	outcome := "noncompliant"
	if v.Compliant {
		outcome = "compliant"
	}
	s.metrics.lookup("posture", outcome)
	writeJSON(w, http.StatusOK, v)
}

// posture is compliant when the subject has at least one enrolled device and
// every one of them (not revoked, not expired) reported within PostureMaxAge,
// with no drift, on its ring's current release or one of that release's
// experiment channels. Every device counts: stopping halod on one machine
// cannot be hidden behind a second, healthy one. The release check is skipped
// when no registry is configured or nothing is published for the ring; a
// release that cannot be checked (registry unreachable with no verified
// pointer cached, or the release's channels unreadable) is unknown, never
// current. Devices are read after catching up with the shared registry, so a
// device enrolled on another replica counts; if that fails the verdict is
// unknown (not compliant), never a pass on a partial view.
func (s *Server) posture(ctx context.Context, subject string) gateway.PostureVerdict {
	now := s.cfg.Now()
	if err := s.devices.sharedCatchup(); err != nil {
		s.cfg.Log.Error("posture: device registry unavailable", "err", err)
		return gateway.PostureVerdict{Reason: "device registry unavailable: posture unknown; retry shortly"}
	}
	devs := s.devices.active(subject, now)
	if len(devs) == 0 {
		return gateway.PostureVerdict{Reason: "no enrolled device for this user; enroll this machine with halod"}
	}
	maxAge := s.cfg.PostureMaxAge
	if maxAge <= 0 {
		maxAge = DefaultPostureMaxAge
	}
	hosts := map[string]Host{}
	for _, h := range s.cfg.Store.All() { // ponytail: O(fleet) per lookup; gateways cache verdicts per subject
		if h.Device != "" {
			hosts[h.Device] = h
		}
	}
	org, _, _ := s.pol.Get()
	for _, d := range devs {
		h, ok := hosts[d.ID]
		if !ok {
			return gateway.PostureVerdict{Reason: fmt.Sprintf("device %s has never reported (is halod running?)", d.ID)}
		}
		name := h.Hostname
		if age := now.Sub(h.LastSeen); age > maxAge {
			return gateway.PostureVerdict{Reason: fmt.Sprintf("device %s last reported %s ago (is halod running?)", name, age.Round(time.Minute))}
		}
		if len(h.Drift) > 0 {
			return gateway.PostureVerdict{Reason: fmt.Sprintf("device %s reported drift in %s", name, h.Drift[0])}
		}
		ring := ""
		if org != nil {
			if rg := org.ResolveRing(policy.Subject{ID: d.UserID, Groups: d.Groups}); rg != nil {
				ring = rg.Name
			}
		}
		switch on, known := s.onRingRelease(ctx, org, ring, h.Digest, now); {
		case !known:
			return gateway.PostureVerdict{Reason: fmt.Sprintf("device %s runs release %s, which cannot be checked against ring %s now (registry unreachable): posture unknown", name, short(h.Digest), ring)}
		case !on:
			return gateway.PostureVerdict{Reason: fmt.Sprintf("device %s runs release %s, not ring %s's current release", name, short(h.Digest), ring)}
		}
	}
	return gateway.PostureVerdict{Compliant: true}
}

// onRingRelease reports whether digest is ring's current verified release or
// one of its experiment channels'. Nothing to check against (no registry
// configured, nothing published, no ring) counts as on it. known=false when
// the check could not be made: the registry failed with no verified pointer
// cached, or the release's channel list is unreadable.
func (s *Server) onRingRelease(ctx context.Context, org *policy.Org, ring, digest string, now time.Time) (on, known bool) {
	if org == nil || ring == "" || s.cfg.Portal.Registry == "" || s.cfg.Portal.PubKeyPEM == "" {
		return true, true
	}
	s.relCache.mu.Lock()
	defer s.relCache.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, releaseFetchLimit)
	defer cancel()
	pv := s.lookup(ctx, ring, org.Name, now)
	if !pv.found {
		ok := pv.err == "" // nothing published: on it; the registry failed: unknown
		return ok, ok
	}
	if digest == pv.p.Digest {
		return true, true
	}
	chans, err := s.channels(ctx, pv.p)
	if err != nil {
		return false, false
	}
	for _, ch := range chans {
		if cv := s.lookup(ctx, ch, org.Name, now); cv.found && cv.p.Digest == digest {
			return true, true
		}
	}
	return false, true
}

func short(digest string) string {
	if len(digest) > 19 {
		return digest[:19]
	}
	return digest
}

// active returns userID's devices that are not revoked or expired, by id.
func (d *deviceStore) active(userID string, now time.Time) []Device {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Device
	for _, v := range d.byID {
		exp := v.ExpiresAt
		if exp.IsZero() {
			exp = v.CreatedAt.Add(d.ttl)
		}
		if sameUser(v.UserID, userID) && !v.Revoked && now.Before(exp) { // canonicalUser, as everywhere (SCIM, revocation)
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
