package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

// Agent delegation (ADR-0024): POST /api/v1/token/exchange with a Halos
// credential as subject_token and actor_id naming an agent mints a delegated
// credential: same root subject, an RFC 8693 act chain, a scope that only
// narrows, a lifetime within the parent's. POST /api/v1/agents/egress answers
// whether the caller may call a remote (A2A) agent.

// tokenTypeSession is the subject_token_type of a halo_session cookie value
// (a Halos extension URN; RFC 8693 section 3 allows other token type URIs).
const tokenTypeSession = "urn:halos:params:oauth:token-type:session" //nolint:gosec // token type identifier, not a credential

// Halos extension parameters of the delegation request (RFC 6749 section 8.2).
const (
	paramActorID      = "actor_id"      // agents.actors name; required
	paramActorHarness = "actor_harness" // where the agent runs
	paramActorSession = "actor_session" // the harness session id
	paramExpiresIn    = "expires_in"    // requested lifetime, seconds
)

const maxEgressBody = 4 << 10

// isDelegation: the request asks for an agent credential, or presents a Halos
// credential (which the CI exchange never accepts).
func isDelegation(f url.Values) bool {
	if f.Has(paramActorID) || f.Get("subject_token_type") == tokenTypeSession {
		return true
	}
	t := identity.TokenType(f.Get("subject_token"))
	return t == identity.WorkloadTokenType || t == identity.DelegatedTokenType
}

// parentCred is a verified credential being exchanged.
type parentCred struct {
	sub      policy.Subject // root principal; Delegation set when the parent is itself delegated
	exp      time.Time
	authTime int64 // unix seconds the root authenticated
	jti      string
	via      string // session | workload | agent
}

func (s *Server) workloadPub() []ed25519.PublicKey {
	pub, _ := s.cfg.WorkloadKey.Public().(ed25519.PublicKey)
	return []ed25519.PublicKey{pub}
}

// verifyParent verifies subject_token as a Halos credential: a halo_session
// cookie value, a workload credential or a delegated credential, all signed by
// this server. A human root must still have a live session epoch and be
// provisioned in the SCIM directory. A credential that is ours but no longer
// usable (expired, revoked, deprovisioned) fails with
// identity.ErrClaimsRejected or errParentRefused; anything else failed to
// verify. A workload or delegated parent whose credential is revoked
// (ADR-0026) is errParentRefused; errRevocationsUnavailable when the
// revocation store cannot be read.
func (s *Server) verifyParent(ctx context.Context, raw, typ string, now time.Time) (parentCred, error) {
	switch {
	case typ == tokenTypeSession:
		p, err := s.unseal(raw)
		if err != nil || p.Sub == "" || p.State != "" {
			return parentCred{}, errors.New("not a valid session")
		}
		// The session is ours (sealed): what fails from here is not a forgery.
		if !s.revoked.valid(p.Sub, p.Iat) {
			return parentCred{sub: policy.Subject{ID: p.Sub}, via: "session"}, fmt.Errorf("%w: session revoked", errParentRefused)
		}
		if p.BG != "" { // break-glass recovers access; it never leaves credentials behind (ADR-0036)
			return parentCred{sub: policy.Subject{ID: p.Sub}, via: "session"}, fmt.Errorf("%w: a break-glass session cannot delegate", errParentRefused)
		}
		if err := s.sessionLive(p); err != nil {
			return parentCred{}, signedButRejected(err)
		}
		groups := p.Groups
		if p.SID != "" {
			g, ok := s.oidc.session(p.SID)
			if !ok {
				return parentCred{}, signedButRejected(errors.New("session expired"))
			}
			groups = g
		}
		g, ok := s.directoryGroups(p.Sub, groups)
		if !ok {
			return parentCred{sub: policy.Subject{ID: p.Sub}, via: "session"}, fmt.Errorf("%w: %w", errParentRefused, errDeprovisioned)
		}
		return parentCred{sub: policy.Subject{ID: p.Sub, Groups: g}, exp: time.Unix(p.Exp, 0), authTime: p.Iat / int64(time.Second), via: "session"}, nil
	case typ != tokenTypeJWT && typ != tokenTypeAccess:
		return parentCred{}, fmt.Errorf("subject_token_type must be %s, or %s for a Halos credential", tokenTypeSession, tokenTypeJWT)
	}
	switch identity.TokenType(raw) {
	case identity.WorkloadTokenType:
		c, err := identity.VerifyWorkloadToken(s.workloadPub(), raw, now)
		if err != nil {
			return parentCred{}, err
		}
		pc := parentCred{sub: c.AsSubject(), exp: time.Unix(c.Expiry, 0), authTime: c.IssuedAt, jti: c.ID, via: "workload"}
		return pc, s.parentRevoked(ctx, pc.sub)
	case identity.DelegatedTokenType:
		c, err := identity.VerifyDelegatedToken(s.workloadPub(), raw, now)
		if err != nil {
			return parentCred{}, err
		}
		sub := c.AsSubject()
		if c.RootKind == "" { // a human root: revoked or deprovisioned since kills the whole chain
			g, err := s.liveHumanRoot(c.Subject, c.Groups, c.AuthTime)
			if err != nil {
				return parentCred{sub: sub, jti: c.ID, via: "agent"}, fmt.Errorf("%w: %w", errParentRefused, err)
			}
			sub.Groups = g
		}
		pc := parentCred{sub: sub, exp: time.Unix(c.Expiry, 0), authTime: c.AuthTime, jti: c.ID, via: "agent"}
		return pc, s.parentRevoked(ctx, sub)
	}
	return parentCred{}, errors.New("subject_token is not a Halos credential")
}

// parentRevoked is checkRevoked for a parent credential: a revoked one is
// errParentRefused (audited, not an authentication failure).
func (s *Server) parentRevoked(ctx context.Context, sub policy.Subject) error {
	err := s.checkRevoked(ctx, sub)
	if errors.Is(err, gateway.ErrCredentialRevoked) {
		return fmt.Errorf("%w: %w", errParentRefused, err)
	}
	return err
}

var (
	errDeprovisioned = errors.New("root principal is deactivated or not provisioned in the directory")
	errRootRevoked   = errors.New("root session revoked")
	// errParentRefused wraps the refusal of a parent credential that verified
	// (signature or HMAC, expiry) but whose root is revoked or deprovisioned:
	// audited, and not an authentication failure for the rate limiter.
	errParentRefused = errors.New("verified parent refused")
)

// liveHumanRoot checks that the human root of a delegated credential still
// stands: no session revocation since authTime (unix seconds, the signed
// auth_time claim) and provisioned in the SCIM directory. It returns the
// root's groups narrowed to the directory's (groups only narrow down a chain).
// The exchange (verifyParent) and the egress decision share it.
func (s *Server) liveHumanRoot(root string, groups []string, authTime int64) ([]string, error) {
	if !s.revoked.valid(root, authTime*int64(time.Second)) {
		return nil, errRootRevoked
	}
	g, ok := s.directoryGroups(root, groups)
	if !ok {
		return nil, errDeprovisioned
	}
	return intersect(groups, g), nil
}

// signedButRejected marks err as a failure of a credential this server
// signed: it is not counted against the client IP (see postTokenExchange).
func signedButRejected(err error) error { return fmt.Errorf("%w: %w", identity.ErrClaimsRejected, err) }

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// delegate mints a delegated agent credential (see ADR-0024 for each rule).
// Its failed-attempt budget is agentFails, never the CI exchange's. Only a
// subject_token that does not verify (malformed, forged, not ours) counts;
// a credential this server signed passes even when the IP is blocked, so
// garbage from a shared egress IP cannot lock out the agents behind it.
func (s *Server) delegate(w http.ResponseWriter, r *http.Request, org *policy.Org, f url.Values, ip string) {
	now := s.cfg.Now()
	blocked := s.agentFails.blocked(ip)
	bad := func(code int, kind, desc string) { // no verified credential yet
		if blocked {
			tooManyFailures(w)
			return
		}
		oauthErr(w, code, kind, desc)
	}
	if org.Agents == nil {
		bad(http.StatusNotFound, "unsupported_grant_type", "policy declares no agents")
		return
	}
	agent, harness, session := f.Get(paramActorID), f.Get(paramActorHarness), f.Get(paramActorSession)
	if agent == "" {
		bad(http.StatusBadRequest, "invalid_request", "actor_id is required: the agents.actors name of the agent that will act")
		return
	}
	// Unverified labels reach the audit log below: check their shape first.
	if err := identity.CheckChain([]policy.Actor{{Agent: agent, Harness: harness, Session: session}}); err != nil {
		bad(http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	parent, err := s.verifyParent(r.Context(), f.Get("subject_token"), f.Get("subject_token_type"), now)
	switch {
	case errors.Is(err, errRevocationsUnavailable): // ours, but whether it is revoked cannot be told: fail closed, no penalty
		s.metrics.authFailure("delegation", "unavailable")
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "revocations cannot be checked; retry")
		return
	case errors.Is(err, errParentRefused):
		// The credential verified: an authenticated refusal, audited and not
		// counted against the client's failed-authentication budget.
		s.metrics.authFailure("delegation", "parent_refused")
		d := map[string]string{"reason": err.Error(), "via": parent.via}
		if parent.jti != "" {
			d["parentJti"] = parent.jti
		}
		s.Audit(r.Context(), parent.sub.ID, "agent.token.denied", agent, d)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	case !signedOnly(err) && blocked:
		tooManyFailures(w)
		return
	case !signedOnly(err):
		s.metrics.authFailure("delegation", "unverified")
		s.agentFails.fail(ip) // malformed, forged or not ours: an authentication failure
		s.cfg.Log.Info("delegation subject token rejected", "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	case err != nil: // ours, but expired or its session gone: not counted
		s.metrics.authFailure("delegation", "parent_invalid")
		s.cfg.Log.Info("delegation subject token no longer valid", "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	}
	root := parent.sub
	var chain []policy.Actor
	if root.Delegation != nil {
		chain = slices.Clone(root.Delegation.Actors)
	}
	chain = append(chain, policy.Actor{Agent: agent, Harness: harness, Session: session})
	details := map[string]string{"via": parent.via, "rootKind": kindLabel(root.Kind), "chain": chainDetail(chain), "depth": strconv.Itoa(len(chain))}
	if parent.jti != "" {
		details["parentJti"] = parent.jti
	}
	// deny is a policy refusal of an authenticated caller: audited, not counted
	// as an authentication failure.
	deny := func(code, reason string) {
		s.metrics.authFailure("delegation", "denied")
		d := map[string]string{"reason": reason}
		for k, v := range details {
			d[k] = v
		}
		s.Audit(r.Context(), root.ID, "agent.token.denied", agent, d)
		oauthErr(w, http.StatusBadRequest, code, reason)
	}
	actor := org.Agents.Actor(agent)
	switch {
	case actor == nil:
		deny("invalid_grant", fmt.Sprintf("agent %q is not in agents.actors", agent))
		return
	case len(actor.Harnesses) > 0 && !slices.Contains(actor.Harnesses, harness):
		deny("invalid_grant", fmt.Sprintf("agent %q may run only in %v, not %q", agent, actor.Harnesses, harness))
		return
	case len(actor.Groups) > 0 && !slices.ContainsFunc(actor.Groups, func(g string) bool { return slices.Contains(root.Groups, g) }):
		deny("invalid_grant", fmt.Sprintf("agent %q may act only for members of %v", agent, actor.Groups))
		return
	}
	if err := identity.CheckChain(chain); err != nil {
		deny("invalid_grant", err.Error())
		return
	}
	cohort := policy.Subject{ID: root.ID, Groups: root.Groups, Kind: root.Kind}
	sc, err := org.AgentScopeFor(cohort)
	if err != nil {
		s.cfg.Log.Error("agent scope", "root", root.ID, "err", err)
		d := map[string]string{"reason": "policy cannot be resolved for this principal: " + err.Error()}
		for k, v := range details {
			d[k] = v
		}
		s.Audit(r.Context(), root.ID, "agent.token.denied", agent, d)
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "policy cannot be resolved for this principal")
		return
	}
	details["ring"], details["unit"] = sc.Ring, sc.Unit
	if len(chain) > sc.MaxDepth {
		deny("invalid_grant", fmt.Sprintf("delegation depth %d exceeds the maximum %d (agents.maxDepth, profile and unit agents.maxDepth)", len(chain), sc.MaxDepth))
		return
	}
	models, reason := delegatedModels(org, root, actor, f.Get("scope"))
	if reason != "" {
		deny("invalid_scope", reason)
		return
	}
	bound := min(org.Agents.TTL(), parent.exp.Sub(now).Truncate(time.Second))
	if bound < time.Second {
		deny("invalid_grant", "the subject_token expires too soon to delegate")
		return
	}
	ttl := bound
	if v := f.Get(paramExpiresIn); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			deny("invalid_request", "expires_in must be a positive number of seconds")
			return
		}
		// Compare in seconds before converting: n * time.Second overflows int64
		// for n above about 9.2e9 and would wrap to a negative lifetime.
		if n > int64(bound/time.Second) {
			deny("invalid_scope", fmt.Sprintf("expires_in %ds exceeds %s, the lesser of agents.maxTTLSeconds and the parent credential's remaining lifetime", n, bound))
			return
		}
		ttl = time.Duration(n) * time.Second
	}
	rootKind := ""
	if root.Kind == policy.SubjectWorkload {
		rootKind = policy.SubjectWorkload
	}
	// The credential about to be minted must not be born revoked: an agent or
	// root whose epoch (padded by revocationSkew) is not yet behind us gets
	// no new credential until it is (ADR-0026).
	id, lineage := randB64(16), []string(nil)
	if parent.sub.Credential != nil {
		lineage = parent.sub.Credential.IDs
	}
	child := policy.Subject{ID: root.ID, Kind: root.Kind, Delegation: &policy.DelegationChain{Actors: chain, AuthTime: parent.authTime},
		Credential: &policy.CredentialRef{IDs: append([]string{id}, lineage...), IssuedAt: now.Unix()}}
	if err := s.checkRevoked(r.Context(), child); errors.Is(err, errRevocationsUnavailable) {
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "revocations cannot be checked; retry")
		return
	} else if err != nil {
		deny("invalid_grant", err.Error()+"; a new credential can be issued once the revocation epoch has passed")
		return
	}
	var ancestors []string
	if len(lineage) > 1 {
		ancestors = lineage[1:]
	}
	exp := now.Add(ttl)
	c := identity.DelegatedClaims{Issuer: identity.WorkloadIssuer, Subject: root.ID, Audience: identity.WorkloadAudience, Groups: root.Groups,
		Kind: identity.KindAgent, RootKind: rootKind, Act: identity.ActFromChain(chain), Models: models, AuthTime: parent.authTime, Parent: parent.jti,
		Ancestors: ancestors, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix(), ID: id}
	tok, err := identity.SignDelegatedToken(s.cfg.WorkloadKey, c)
	if err != nil {
		s.cfg.Log.Error("sign delegated token", "agent", agent, "err", err)
		oauthErr(w, http.StatusInternalServerError, "server_error", "could not mint credential")
		return
	}
	details["jti"], details["ttl"], details["expires"] = c.ID, ttl.String(), exp.UTC().Format(time.RFC3339)
	details["groups"], details["models"] = strings.Join(root.Groups, ","), strings.Join(models, ",")
	if err := s.AuditStrict(r.Context(), root.ID, "agent.token.exchange", agent, details); err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", errAuditFailed)
		return
	}
	resp := TokenExchangeResponse{AccessToken: tok, IssuedTokenType: tokenTypeJWT, TokenType: "Bearer", ExpiresIn: int(ttl.Seconds()),
		Subject: root.ID, Groups: root.Groups, Ring: sc.Ring, Actors: actorNames(chain), Models: models}
	if org.Gateway != nil {
		resp.GatewayURL = org.Gateway.BaseURL
	}
	writeJSON(w, http.StatusOK, resp)
}

// delegatedModels returns the child's model scope: the parent's scope
// narrowed by agents.allowedModels and the actor's models, and by the
// request's model: scope entries, which may only pick from it. The reason is
// non-empty when the request escalates (a group or model the parent does not
// hold) or nothing would be left.
func delegatedModels(org *policy.Org, root policy.Subject, actor *policy.AgentActor, scope string) ([]string, string) {
	var parentModels []string
	if root.Delegation != nil {
		parentModels = root.Delegation.Models
	}
	allowed := policy.IntersectScope(parentModels, org.Agents.ModelLimit(actor))
	var want []string
	var groups []string
	for _, tok := range strings.Fields(scope) {
		switch {
		case strings.HasPrefix(tok, "model:"):
			want = append(want, strings.TrimPrefix(tok, "model:"))
		case strings.HasPrefix(tok, "group:"):
			groups = append(groups, strings.TrimPrefix(tok, "group:"))
		default:
			return nil, fmt.Sprintf("scope %q: want model:<alias> or group:<name> entries", tok)
		}
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	for _, g := range groups {
		if !slices.Contains(root.Groups, g) {
			return nil, fmt.Sprintf("group %q is not held by the parent credential; a delegate cannot gain groups", g)
		}
	}
	if len(groups) > 0 && len(groups) != len(root.Groups) {
		return nil, "groups cannot be narrowed: they decide the root's ring, toggles and budgets, so dropping one could move an agent out of a gate; narrow models instead"
	}
	if len(want) > 0 {
		for _, m := range want {
			if allowed != nil && !slices.Contains(allowed, m) {
				return nil, fmt.Sprintf("model %q is outside the parent's scope and agents policy %v; a delegate cannot gain models", m, allowed)
			}
			if org.Gateway != nil {
				if _, ok := org.Gateway.Models[m]; !ok {
					return nil, fmt.Sprintf("model %q is not a gateway.models alias", m)
				}
			}
		}
		slices.Sort(want)
		return slices.Compact(want), ""
	}
	if allowed != nil && len(allowed) == 0 {
		return nil, "no model is left: the parent's scope, agents.allowedModels and the agent's models do not intersect"
	}
	return allowed, ""
}

func kindLabel(k string) string {
	if k == "" {
		return "human"
	}
	return k
}

func actorNames(chain []policy.Actor) []string {
	out := make([]string, len(chain))
	for i, a := range chain {
		out[i] = a.Agent
	}
	return out
}

// chainDetail renders the chain for the audit log, root-side first, with
// each actor's harness and session: planner(claude-code/s1)>reviewer(codex/s2).
func chainDetail(chain []policy.Actor) string {
	parts := make([]string, len(chain))
	for i, a := range chain {
		parts[i] = a.Agent + "(" + a.Harness + "/" + a.Session + ")"
	}
	return strings.Join(parts, ">")
}

// EgressRequest is POST /api/v1/agents/egress: the remote agent by
// agents.remote name, or by a URL on its AgentCard's origin, and optionally
// the skill about to be invoked.
type EgressRequest struct {
	Agent string `json:"agent,omitempty"`
	URL   string `json:"url,omitempty"`
	Skill string `json:"skill,omitempty"`
}

// postAgentEgress answers whether the bearer of a Halos credential (workload
// or delegated agent, signed by this server) may call a remote agent. The
// caller's cohort comes from the verified credential only.
func (s *Server) postAgentEgress(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.agentFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	if len(s.cfg.WorkloadKey) == 0 {
		apiErr(w, http.StatusNotFound, "agent egress decisions need --workload-key-file")
		return
	}
	v := &identity.WorkloadJWT{Keys: s.workloadPub(), Next: noCredentials{}, Now: s.cfg.Now}
	sub, err := v.Verify(r)
	org, _, perr := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, perr)
		return
	}
	if err != nil {
		// An expired credential whose signature verified is routine here: a
		// long agent run outlives its credential, and a fleet behind one NAT
		// must not lock itself out of egress decisions. Nobody without the
		// signing key can produce one (identity.ErrClaimsRejected covers
		// ErrTokenExpired), so it is no guessing signal. Every other failure
		// (bad, forged, unverifiable) counts.
		if !errors.Is(err, identity.ErrClaimsRejected) {
			s.agentFails.fail(ip)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="halos"`)
		apiErr(w, http.StatusUnauthorized, "a Halos workload or delegated agent credential is required")
		return
	}
	var req EgressRequest
	if err := decodeBody(w, r, maxEgressBody, &req); err != nil || (req.Agent == "" && req.URL == "") || len(req.Agent)+len(req.URL)+len(req.Skill) > 2048 {
		apiErr(w, http.StatusBadRequest, "body must be {\"agent\" or \"url\", \"skill\"} under 4KB")
		return
	}
	target := req.Agent
	if target == "" {
		target = req.URL
	}
	details := func(dec policy.RemoteDecision) map[string]string {
		d := map[string]string{"agent": dec.Agent, "url": req.URL, "skill": req.Skill, "reason": dec.Reason, "ring": dec.Ring, "unit": dec.Unit}
		if dl := sub.Delegation; dl != nil {
			d["chain"], d["jti"] = chainDetail(dl.Actors), dl.ID
		}
		return d
	}
	if err := s.checkRevoked(r.Context(), sub); errors.Is(err, errRevocationsUnavailable) {
		apiErr(w, http.StatusServiceUnavailable, "revocations cannot be checked; retry")
		return
	} else if err != nil { // a revoked credential (ADR-0026): refused and audited
		s.Audit(r.Context(), sub.ID, "agent.egress.deny", target, details(policy.RemoteDecision{Reason: err.Error()}))
		apiErr(w, http.StatusForbidden, err.Error())
		return
	}
	if sub.Kind == "" && sub.Delegation != nil { // a human root: revoked sessions and deprovisioned users kill their agents
		g, err := s.liveHumanRoot(sub.ID, sub.Groups, sub.Delegation.AuthTime)
		if err != nil {
			s.Audit(r.Context(), sub.ID, "agent.egress.deny", target, details(policy.RemoteDecision{Reason: err.Error()}))
			apiErr(w, http.StatusForbidden, err.Error())
			return
		}
		sub.Groups = g
	}
	cohort := policy.Subject{ID: sub.ID, Groups: sub.Groups, Kind: sub.Kind}
	dec := org.DecideRemote(cohort, sub.Delegation, req.Agent, req.URL, req.Skill)
	if !dec.Allow {
		s.Audit(r.Context(), sub.ID, "agent.egress.deny", target, details(dec)) // best-effort: a refusal grants nothing
		writeJSON(w, http.StatusOK, dec)
		return
	}
	// No allow without its audit record.
	if err := s.AuditStrict(r.Context(), sub.ID, "agent.egress.allow", target, details(dec)); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	writeJSON(w, http.StatusOK, dec)
}

// noCredentials is the egress endpoint's "human" verifier: humans call remote
// agents through a delegated credential, so anything else is unauthenticated.
type noCredentials struct{}

func (noCredentials) Verify(*http.Request) (policy.Subject, error) {
	return policy.Subject{}, identity.ErrNoCredentials
}
