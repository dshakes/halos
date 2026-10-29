package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

// MCP access tokens (ADR-0029): POST /api/v1/token/exchange with a Halos
// credential as subject_token and resource=<registry server URL> mints a
// token for that one server (aud = its canonical URL, RFC 8707), when the
// server's auth mode is halos and the caller's ring or unit gets it. The
// caller's credential never leaves for the server: no token passthrough.

// paramResource is the RFC 8707 resource indicator.
const paramResource = "resource"

// isMCPToken: the request names a resource, which only the MCP exchange takes.
func isMCPToken(f url.Values) bool { return f.Has(paramResource) }

// mcpToken shares the delegation exchange's failed-attempt budget
// (agentFails): both take Halos credentials, never CI tokens.
func (s *Server) mcpToken(w http.ResponseWriter, r *http.Request, f url.Values, ip string) {
	blocked := s.agentFails.blocked(ip)
	bad := func(code int, kind, desc string) { // no verified credential yet
		if blocked {
			tooManyFailures(w)
			return
		}
		oauthErr(w, code, kind, desc)
	}
	if len(s.cfg.WorkloadKey) == 0 {
		bad(http.StatusNotFound, "unsupported_grant_type", "MCP tokens need --workload-key-file")
		return
	}
	org, _, err := s.pol.Get()
	if org == nil {
		s.cfg.Log.Error("mcp token: policy unavailable", "err", err)
		bad(http.StatusServiceUnavailable, "temporarily_unavailable", errPolicyUnavailable)
		return
	}
	if code, kind, desc := checkExchangeForm(f); code != 0 {
		bad(code, kind, desc)
		return
	}
	if f.Has(paramActorID) || len(f[paramResource]) != 1 {
		bad(http.StatusBadRequest, "invalid_request", "exactly one resource, and no actor_id: an agent asks with its own delegated credential")
		return
	}
	now := s.cfg.Now()
	resource := f.Get(paramResource)
	parent, err := s.verifyParent(r.Context(), f.Get("subject_token"), f.Get("subject_token_type"), now)
	switch {
	case errors.Is(err, errRevocationsUnavailable): // ours, but whether it is revoked cannot be told: fail closed, no penalty
		s.metrics.authFailure("mcp_token", "unavailable")
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "revocations cannot be checked; retry")
		return
	case errors.Is(err, errParentRefused): // verified, but it or its root is revoked or deprovisioned (ADR-0026)
		s.metrics.authFailure("mcp_token", "parent_refused")
		d := map[string]string{"reason": err.Error(), "via": parent.via}
		if parent.jti != "" {
			d["parentJti"] = parent.jti
		}
		s.Audit(r.Context(), parent.sub.ID, "mcp.token.denied", resource, d)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	case !signedOnly(err) && blocked:
		tooManyFailures(w)
		return
	case !signedOnly(err):
		s.metrics.authFailure("mcp_token", "unverified")
		s.agentFails.fail(ip)
		s.cfg.Log.Info("mcp token subject token rejected", "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	case err != nil: // ours, but expired or its session gone: not counted
		s.metrics.authFailure("mcp_token", "parent_invalid")
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	}
	sub := parent.sub
	dec := org.DecideMCPToken(policy.Subject{ID: sub.ID, Groups: sub.Groups, Kind: sub.Kind}, resource)
	details := map[string]string{"via": parent.via, "server": dec.Server, "ring": dec.Ring, "unit": dec.Unit, "reason": dec.Reason}
	var actors []string
	if d := sub.Delegation; d != nil {
		details["chain"] = chainDetail(d.Actors)
		actors = actorNames(d.Actors)
	}
	ttl := min(identity.MCPTokenTTL, parent.exp.Sub(now).Truncate(time.Second))
	if dec.Allow && ttl < time.Second {
		dec.Allow, details["reason"] = false, "the subject_token expires too soon"
	}
	if !dec.Allow {
		s.Audit(r.Context(), sub.ID, "mcp.token.denied", resource, details) // best-effort: a refusal grants nothing
		oauthErr(w, http.StatusBadRequest, "invalid_target", details["reason"])
		return
	}
	aud, _ := policy.CanonicalResource(resource) // DecideMCPToken accepted it
	c := identity.MCPClaims{Issuer: identity.WorkloadIssuer, Subject: sub.ID, Audience: aud, Groups: sub.Groups, Kind: sub.Kind,
		Actors: actors, Server: dec.Server, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(ttl).Unix(), ID: randB64(16)}
	tok, err := identity.SignMCPToken(s.cfg.WorkloadKey, c)
	if err != nil {
		s.cfg.Log.Error("sign mcp token", "server", dec.Server, "err", err)
		oauthErr(w, http.StatusInternalServerError, "server_error", "could not mint credential")
		return
	}
	details["jti"], details["ttl"], details["groups"] = c.ID, ttl.String(), strings.Join(sub.Groups, ",")
	if err := s.AuditStrict(r.Context(), sub.ID, "mcp.token.exchange", resource, details); err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", errAuditFailed)
		return
	}
	writeJSON(w, http.StatusOK, TokenExchangeResponse{AccessToken: tok, IssuedTokenType: tokenTypeAccess, TokenType: "Bearer",
		ExpiresIn: int(ttl.Seconds()), Subject: sub.ID, Groups: sub.Groups, Ring: dec.Ring, Actors: actors})
}
