package server

import (
	"net/http"
	"path/filepath"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/rollout"
)

// RolloutView is one entry of GET /api/v1/rollouts: the definition, its
// plan, and the controller's state (last decision, gate values, hash-chained
// history) when this server's data dir holds it (halo-server --controller).
type RolloutView struct {
	Rollout    *policy.Rollout  `json:"rollout"`
	Timeline   rollout.Timeline `json:"timeline"`
	State      *rollout.State   `json:"state,omitempty"`
	StateError string           `json:"stateError,omitempty"`
}

func (s *Server) rollouts(w http.ResponseWriter) ([]RolloutView, bool) {
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return nil, false
	}
	out := make([]RolloutView, 0, len(org.Rollouts))
	for _, r := range org.Rollouts {
		v := RolloutView{Rollout: r, Timeline: rollout.BuildTimeline(org, r)}
		if s.cfg.DataDir != "" {
			if st, err := rollout.LoadState(filepath.Join(s.cfg.DataDir, "rollouts"), r.Name); err != nil {
				s.cfg.Log.Warn("rollout state unreadable", "rollout", r.Name, "err", err)
				v.StateError = err.Error()
			} else if len(st.History) > 0 {
				v.State = &st
			}
		}
		out = append(out, v)
	}
	return out, true
}

func (s *Server) listRollouts(w http.ResponseWriter, _ *http.Request, _ Principal) {
	if out, ok := s.rollouts(w); ok {
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) getRollout(w http.ResponseWriter, r *http.Request, _ Principal) {
	out, ok := s.rollouts(w)
	if !ok {
		return
	}
	for _, v := range out {
		if v.Rollout.Name == r.PathValue("name") {
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	apiErr(w, http.StatusNotFound, "rollout not found")
}
