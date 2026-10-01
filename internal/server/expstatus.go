package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
)

// experimentStatusKind is the Request.Kind GitPolicyWriter uses to flip an experiment's status (Item = name, Note = status).
const experimentStatusKind = "experiment-status"

// settableStatuses are what the console may request; draft is authored, not toggled.
var settableStatuses = []string{"running", "paused", "concluded"}

// postExperimentStatus (admin): POST /api/v1/experiments/{name}/status {"status":"paused"}
// opens a policy-repo PR; nothing changes until a human merges it.
func (s *Server) postExperimentStatus(w http.ResponseWriter, r *http.Request, p Principal) {
	var in struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil || !slices.Contains(settableStatuses, in.Status) {
		apiErr(w, http.StatusUnprocessableEntity, "status must be one of running, paused, concluded")
		return
	}
	name := r.PathValue("name")
	exps, ok := s.experiments(w)
	if !ok {
		return
	}
	i := slices.IndexFunc(exps, func(e ExperimentDetail) bool { return e.Name == name })
	if i < 0 {
		apiErr(w, http.StatusNotFound, "experiment not found")
		return
	}
	if exps[i].Status == in.Status {
		apiErr(w, http.StatusConflict, "experiment is already "+in.Status)
		return
	}
	org, _, _ := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded")
		return
	}
	if s.cfg.Writer == nil {
		apiErr(w, http.StatusNotImplemented, "no policy writer configured (portal policyRepoDir)")
		return
	}
	// Not r.Context(): a client disconnect must not abort a half-made PR.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), proposeTimeout)
	defer cancel()
	pr, err := s.cfg.Writer.Propose(ctx, org, Request{ID: randB64(9), User: p.ID, Kind: experimentStatusKind, Item: name, Note: in.Status, CreatedAt: s.cfg.Now().UTC()}, p.ID)
	if err != nil {
		s.cfg.Log.Error("experiment status PR failed", "experiment", name, "err", err)
		code := http.StatusBadGateway
		if errors.Is(err, ErrManual) {
			code = http.StatusNotImplemented
		}
		apiErr(w, code, "could not open policy PR: "+err.Error())
		return
	}
	if err := s.AuditStrict(r.Context(), p.ID, "experiment.status", name, map[string]string{"status": in.Status, "prUrl": pr}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed+" (PR "+pr+" was opened)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"prURL": pr})
}
