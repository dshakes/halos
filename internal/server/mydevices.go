package server

import (
	"net/http"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

// MyDevice is one of the caller's own enrolled devices with its latest report.
type MyDevice struct {
	Device  Device `json:"device"`
	Last    *Host  `json:"last,omitempty"`
	Expired bool   `json:"expired"` // the token no longer works: re-enroll
}

// MyDevices is GET /api/v1/me/devices: the caller's devices and the posture
// verdict the gateway would give them right now (the same check that answers
// a 403 "device posture check failed").
type MyDevices struct {
	Devices []MyDevice             `json:"devices"`
	Posture gateway.PostureVerdict `json:"posture"`
}

// myDevices lets a developer confirm that the machine they just enrolled checked
// in and is compliant, without an admin. Scoped to the principal: the device
// store is filtered by its bound user id, never by a client-supplied one.
func (s *Server) myDevices(w http.ResponseWriter, r *http.Request, p Principal) {
	now := s.cfg.Now()
	hosts := map[string]Host{}
	for _, h := range s.cfg.Store.All() {
		if h.Device != "" {
			hosts[h.Device] = h
		}
	}
	out := MyDevices{Devices: []MyDevice{}, Posture: s.posture(r.Context(), p.ID)}
	for _, d := range s.devices.list() {
		if d.UserID != p.ID {
			continue
		}
		md := MyDevice{Device: d, Expired: !now.Before(expiry(d, s.devices.ttl))}
		if h, ok := hosts[d.ID]; ok {
			md.Last = &h
		}
		out.Devices = append(out.Devices, md)
	}
	writeJSON(w, http.StatusOK, out)
}

// expiry is when d's token stops working (devices persisted before ExpiresAt existed use the store TTL).
func expiry(d Device, ttl time.Duration) time.Time {
	if d.ExpiresAt.IsZero() {
		return d.CreatedAt.Add(ttl)
	}
	return d.ExpiresAt
}
