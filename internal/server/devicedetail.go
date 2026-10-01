package server

import (
	"net/http"
)

// DeviceDetail is GET /api/v1/devices/{id}: the binding, its latest report and recent history.
type DeviceDetail struct {
	Device  Device `json:"device"`
	Last    *Host  `json:"last,omitempty"`
	History []Host `json:"history"` // newest first, at most MaxHistory
}

func (d *deviceStore) get(id string) (Device, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.byID[id]
	if v == nil {
		return Device{}, false
	}
	c := *v
	c.Hash = "" // never expose, even hashed
	return c, true
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request, _ Principal) {
	dev, ok := s.devices.get(r.PathValue("id"))
	if !ok {
		apiErr(w, http.StatusNotFound, errNoDevice.Error())
		return
	}
	out := DeviceDetail{Device: dev, History: s.cfg.Store.History(Host{Report: Report{Device: dev.ID}}.key())}
	if len(out.History) > 0 {
		out.Last = &out.History[0]
	}
	writeJSON(w, http.StatusOK, out)
}
