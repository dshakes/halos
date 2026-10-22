package server

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

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
// identity.ErrClaimsRejected; anything else failed to verify.
func (s *Server) verifyParent(raw, typ string, now time.Time) (parentCred, error) {
	switch {
	case typ == tokenTypeSession:
		p, err := s.unseal(raw)
		if err != nil || p.Sub == "" || p.State != "" {
			return parentCred{}, errors.New("not a valid session")
		}
		// The session is ours (sealed): what fails from here is not a forgery.
		if !s.revoked.valid(p.Sub, p.Iat) {
			return parentCred{}, signedButRejected(errors.New("session revoked"))
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
			return parentCred{}, signedButRejected(errDeprovisioned)
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
		return parentCred{sub: policy.Subject{ID: c.Subject, Groups: c.Groups, Kind: policy.SubjectWorkload}, exp: time.Unix(c.Expiry, 0), authTime: c.IssuedAt, jti: c.ID, via: "workload"}, nil
	case identity.DelegatedTokenType:
		c, err := identity.VerifyDelegatedToken(s.workloadPub(), raw, now)
		if err != nil {
			return parentCred{}, err
		}
		sub := c.AsSubject()
		if c.RootKind == "" { // a human root: revoked or deprovisioned since kills the whole chain
			if !s.revoked.valid(c.Subject, c.AuthTime*int64(time.Second)) {
				return parentCred{}, signedButRejected(errors.New("root session revoked"))
			}
			g, ok := s.directoryGroups(c.Subject, c.Groups)
			if !ok {
				return parentCred{}, signedButRejected(errDeprovisioned)
			}
			sub.Groups = intersect(c.Groups, g) // groups only ever narrow down the chain
		}
		return parentCred{sub: sub, exp: time.Unix(c.Expiry, 0), authTime: c.AuthTime, jti: c.ID, via: "agent"}, nil
	}
	return parentCred{}, errors.New("subject_token is not a Halos credential")
}

var errDeprovisioned = errors.New("root principal is deactivated or not provisioned in the directory")

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
// Like the CI exchange, only an unverifiable subject_token counts against the
// client IP, and a verified one passes even when the IP is blocked.
func (s *Server) delegate(w http.ResponseWriter, r *http.Request, org *policy.Org, f url.Values, ip string, blocked bool) {
	now := s.cfg.Now()
	parent, err := s.verifyParent(f.Get("subject_token"), f.Get("subject_token_type"), now)
	switch {
	case !signedOnly(err) && blocked:
		tooManyFailures(w)
		return
	case !signedOnly(err):
		s.exchangeFails.fail(ip)
		s.cfg.Log.Info("delegation subject token rejected", "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	case err != nil: // ours, but expired, revoked or deprovisioned: not counted
		s.cfg.Log.Info("delegation subject token no longer valid", "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	}
	if org.Agents == nil {
		oauthErr(w, http.StatusNotFound, "unsupported_grant_type", "policy declares no agents")
		return
	}
	agent, harness, session := f.Get(paramActorID), f.Get(paramActorHarness), f.Get(paramActorSession)
	if agent == "" {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "actor_id is required: the agents.actors name of the agent that will act")
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
	deny := func(code, reason string) { // a verified credential: audited, never counted against the IP
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
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			deny("invalid_request", "expires_in must be a positive number of seconds")
			return
		}
		if ttl = time.Duration(n) * time.Second; ttl > bound {
			deny("invalid_scope", fmt.Sprintf("expires_in %ds exceeds %s, the lesser of agents.maxTTLSeconds and the parent credential's remaining lifetime", n, bound))
			return
		}
	}
	rootKind := ""
	if root.Kind == policy.SubjectWorkload {
		rootKind = policy.SubjectWorkload
	}
	exp := now.Add(ttl)
	c := identity.DelegatedClaims{Issuer: identity.WorkloadIssuer, Subject: root.ID, Audience: identity.WorkloadAudience, Groups: root.Groups,
		Kind: identity.KindAgent, RootKind: rootKind, Act: identity.ActFromChain(chain), Models: models, AuthTime: parent.authTime, Parent: parent.jti,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix(), ID: randB64(16)}
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
	blocked := s.exchangeFails.blocked(ip)
	if len(s.cfg.WorkloadKey) == 0 {
		apiErr(w, http.StatusNotFound, "agent egress decisions need --workload-key-file")
		return
	}
	// The credential is checked first (a local ed25519 verify): one this
	// server signed passes even from an IP blocked for failed attempts, as on
	// the token exchange, and only an unverifiable one counts against the IP.
	v := &identity.WorkloadJWT{Keys: s.workloadPub(), Next: noCredentials{}, Now: s.cfg.Now}
	sub, err := v.Verify(r)
	if err != nil && blocked && !errors.Is(err, identity.ErrClaimsRejected) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	org, _, perr := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, perr)
		return
	}
	if err != nil {
		if !errors.Is(err, identity.ErrClaimsRejected) {
			s.exchangeFails.fail(ip)
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
	if sub.Kind == "" { // a human root: deprovisioned users' agents are refused
		g, ok := s.directoryGroups(sub.ID, sub.Groups)
		if !ok {
			apiErr(w, http.StatusForbidden, errDeprovisioned.Error())
			return
		}
		sub.Groups = intersect(sub.Groups, g)
	}
	cohort := policy.Subject{ID: sub.ID, Groups: sub.Groups, Kind: sub.Kind}
	dec := org.DecideRemote(cohort, sub.Delegation, req.Agent, req.URL, req.Skill)
	action := "agent.egress.deny"
	if dec.Allow {
		action = "agent.egress.allow"
	}
	d := map[string]string{"agent": dec.Agent, "url": req.URL, "skill": req.Skill, "reason": dec.Reason, "ring": dec.Ring, "unit": dec.Unit}
	if dl := sub.Delegation; dl != nil {
		d["chain"], d["jti"] = chainDetail(dl.Actors), dl.ID
	}
	target := req.Agent
	if target == "" {
		target = req.URL
	}
	s.Audit(r.Context(), sub.ID, action, target, d)
	writeJSON(w, http.StatusOK, dec)
}

// noCredentials is the egress endpoint's "human" verifier: humans call remote
// agents through a delegated credential, so anything else is unauthenticated.
type noCredentials struct{}

func (noCredentials) Verify(*http.Request) (policy.Subject, error) {
	return policy.Subject{}, identity.ErrNoCredentials
}
