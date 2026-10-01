package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/halos-dev/halos/internal/gateway"
	"github.com/halos-dev/halos/internal/policy"
)

// KillExperiment trips the kill switch as actor (the in-process controller)
// and audit-logs it. changed is false when it was already killed.
func (s *Server) KillExperiment(ctx context.Context, actor, name, reason string) (bool, error) {
	changed, err := s.kills.Kill(ctx, name, actor, reason)
	if err == nil && changed {
		// The kill stays applied (fail safe) but the gap is surfaced to the caller.
		if aerr := s.AuditStrict(ctx, actor, "experiment.kill", name, map[string]string{"reason": reason}); aerr != nil {
			return changed, fmt.Errorf("kill of %q applied but audit append failed: %w", name, aerr)
		}
	}
	return changed, err
}

// postKill (admin): POST /api/v1/experiments/{name}/kill|unkill {"reason":"..."}
// (reason required to kill). 501 without KillKey. Takes effect on gateways at their next poll; no PR, no merge.
func (s *Server) postKill(kill bool) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		// Without a signing key no kill list is served: a kill would enforce nothing.
		if s.cfg.KillKey == nil {
			apiErr(w, http.StatusNotImplemented, "kill switch not configured (--killswitch-key-file)")
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			apiErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		in.Reason = strings.TrimSpace(in.Reason)
		if (kill && in.Reason == "") || len(in.Reason) > 500 {
			apiErr(w, http.StatusUnprocessableEntity, "reason is required for a kill (<=500 chars)")
			return
		}
		name := r.PathValue("name")
		org, _, err := s.pol.Get()
		if org == nil {
			apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
			return
		}
		// Unkill is allowed for names no longer in policy, so stale kills can be cleared.
		if kill && !slices.ContainsFunc(org.Experiments, func(e *policy.Experiment) bool { return e.Name == name }) {
			apiErr(w, http.StatusNotFound, "experiment not found")
			return
		}
		set, action := s.kills.Unkill, "experiment.unkill"
		if kill {
			set, action = s.kills.Kill, "experiment.kill"
		}
		changed, err := set(r.Context(), name, p.ID, in.Reason)
		if err != nil {
			s.cfg.Log.Error("killswitch update failed", "experiment", name, "kill", kill, "err", err)
			apiErr(w, http.StatusInternalServerError, "store failed")
			return
		}
		if changed {
			if err := s.AuditStrict(r.Context(), p.ID, action, name, map[string]string{"reason": in.Reason}); err != nil {
				if !kill { // an unrecorded unkill must not stay in force: re-kill (fail safe)
					if _, rerr := s.kills.Kill(r.Context(), name, p.ID, "audit failure: unkill reverted"); rerr != nil {
						s.cfg.Log.Error("revert unkill after audit failure", "experiment", name, "err", rerr)
					}
				}
				apiErr(w, http.StatusInternalServerError, errAuditFailed)
				return
			}
			s.cfg.Log.Warn("killswitch changed", "experiment", name, "killed", kill, "by", p.ID)
		}
		writeJSON(w, http.StatusOK, map[string]any{"experiment": name, "killed": kill, "changed": changed})
	}
}

// getKills (admin): active kills with who/when/why.
func (s *Server) getKills(w http.ResponseWriter, _ *http.Request, _ Principal) {
	recs, version, err := s.kills.Killed()
	if err != nil {
		s.cfg.Log.Error("read killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "killswitch unreadable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version, "killed": recs})
}

// getGatewayKillswitch: the signed kill list for halo-proxy / halo-kong.
func (s *Server) getGatewayKillswitch(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GatewayToken == "" || s.cfg.KillKey == nil {
		apiErr(w, http.StatusNotFound, "killswitch not configured")
		return
	}
	ip := s.clientIP(r)
	if s.authFails.blocked(ip) {
		apiErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	sum := sha256.Sum256([]byte(tok)) // hash first: constant-time regardless of length
	if !ok || subtle.ConstantTimeCompare(sum[:], s.gwSum[:]) != 1 {
		s.authFails.fail(ip)
		apiErr(w, http.StatusUnauthorized, "gateway token required")
		return
	}
	s.writeKillList(w)
}

// getFleetKillswitch: the same signed kill list for enrolled halod devices
// (device-token auth), so a killed client-axis experiment reverts devices to
// the ring release without waiting for pause + republish.
func (s *Server) getFleetKillswitch(w http.ResponseWriter, r *http.Request) {
	if s.cfg.KillKey == nil {
		apiErr(w, http.StatusNotFound, "killswitch not configured")
		return
	}
	if _, ok := s.deviceAuth(w, r); !ok {
		return
	}
	s.writeKillList(w)
}

// writeKillList signs and writes the current kill list.
func (s *Server) writeKillList(w http.ResponseWriter) {
	recs, version, err := s.kills.Killed()
	if err != nil {
		s.cfg.Log.Error("read killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "killswitch unreadable")
		return
	}
	l := gateway.KillList{Version: version, Experiments: []string{}, IssuedAt: s.cfg.Now().UTC()}
	for _, rec := range recs {
		l.Experiments = append(l.Experiments, rec.Experiment)
	}
	env, err := gateway.SignKillList(s.cfg.KillKey, l)
	if err != nil {
		s.cfg.Log.Error("sign killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "sign failed")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// killPubPEM is the PKIX PEM of the kill-list verification key ("" if none).
func (s *Server) killPubPEM() string {
	if s.cfg.KillKey == nil {
		return ""
	}
	b, err := x509.MarshalPKIXPublicKey(s.cfg.KillKey.Public())
	if err != nil { // an ed25519 key always marshals
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// killswitchPub serves the kill-list public key for enrollment (public, like release.pub).
func (s *Server) killswitchPub(w http.ResponseWriter, _ *http.Request) {
	k := s.killPubPEM()
	if k == "" {
		apiErr(w, http.StatusNotFound, "killswitch not configured")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = fmt.Fprint(w, k)
}
