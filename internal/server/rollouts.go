package server

import (
	"context"
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

// rolloutStates is where the controller keeps rollout state: the Backend, else
// <DataDir>/rollouts, else nowhere (nil).
func (s *Server) rolloutStates() rollout.StateStore {
	switch {
	case s.cfg.Backend != nil:
		return s.cfg.Backend.RolloutStates()
	case s.cfg.DataDir != "":
		return rollout.DirStore(filepath.Join(s.cfg.DataDir, "rollouts"))
	}
	return nil
}

func (s *Server) rollouts(ctx context.Context, w http.ResponseWriter) ([]RolloutView, bool) {
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return nil, false
	}
	out := make([]RolloutView, 0, len(org.Rollouts))
	for _, r := range org.Rollouts {
		v := RolloutView{Rollout: r, Timeline: rollout.BuildTimeline(org, r)}
		if store := s.rolloutStates(); store != nil {
			if st, err := store.Load(ctx, r.Name); err != nil {
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

func (s *Server) listRollouts(w http.ResponseWriter, r *http.Request, _ Principal) {
	if out, ok := s.rollouts(r.Context(), w); ok {
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) getRollout(w http.ResponseWriter, r *http.Request, _ Principal) {
	out, ok := s.rollouts(r.Context(), w)
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
