package policy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Agent identity and delegation (ADR-0024). A holder of a verified Halos
// credential (a human session or a workload credential) exchanges it at
// halo-server for a short-lived credential naming an agent that acts for it.
// The subject stays the root principal; the agents are an RFC 8693 actor chain.

const (
	// AgentSubjectPrefix starts every actor's sub in a delegated credential's
	// act claim, so an actor can never be mistaken for a human or a workload.
	AgentSubjectPrefix = "agent:"
	// DefaultAgentMaxDepth is the delegation depth when agents.maxDepth is unset:
	// an agent, and one subagent it spawns.
	DefaultAgentMaxDepth = 2
	// MaxAgentDepth is the hard ceiling: policy cannot raise maxDepth above it
	// and verifiers refuse longer chains whatever the policy says.
	MaxAgentDepth = 5
	// DefaultAgentTTL is the delegated credential lifetime when
	// agents.maxTTLSeconds is unset. The ceiling is MaxWorkloadTTL.
	DefaultAgentTTL = 15 * time.Minute
)

// Actor is one link of a delegation chain.
type Actor struct {
	// Agent is the agents.actors name the credential was minted for.
	Agent string `json:"agent"`
	// Harness and Session say where the agent runs (claude-code, codex, ...;
	// the harness session id). Informational: recorded for audit, never routed on.
	Harness string `json:"harness,omitempty"`
	Session string `json:"session,omitempty"`
}

// DelegationChain is set on a Subject when an agent acts for it. Subject.ID,
// Groups and Kind stay the root principal's, so cohort, ring, budgets and
// posture are the root's.
type DelegationChain struct {
	// Actors is the chain: the root's own delegate first, the current actor last.
	Actors []Actor
	// Models narrows the model aliases the credential may call; nil = not
	// narrowed by the credential (policy still applies).
	Models []string
	// ID is the delegated credential's jti (audit correlation).
	ID string
	// AuthTime is when the root authenticated (unix seconds, the signed
	// auth_time claim): a human root's session revocation after it kills the chain.
	AuthTime int64
}

// Depth is the number of agents in the chain.
func (d *DelegationChain) Depth() int {
	if d == nil {
		return 0
	}
	return len(d.Actors)
}

// Current is the agent making the call.
func (d *DelegationChain) Current() Actor {
	if d == nil || len(d.Actors) == 0 {
		return Actor{}
	}
	return d.Actors[len(d.Actors)-1]
}

// Chain renders the actor chain root-side first, e.g. "planner>reviewer".
func (d *DelegationChain) Chain() string {
	if d == nil {
		return ""
	}
	names := make([]string, len(d.Actors))
	for i, a := range d.Actors {
		names[i] = a.Agent
	}
	return strings.Join(names, ">")
}

// Agents is halos.yaml agents: which agents may act for whom, how deep and
// for how long, what delegated actors may not do, and the remote (A2A) agents
// members may call.
type Agents struct {
	// MaxDepth bounds the delegation chain (default 2, at most 5).
	MaxDepth int `yaml:"maxDepth,omitempty" json:"maxDepth,omitempty"`
	// MaxTTLSeconds caps a delegated credential (default 900, at most 3600). It
	// never outlives its parent either.
	MaxTTLSeconds int `yaml:"maxTTLSeconds,omitempty" json:"maxTTLSeconds,omitempty"`
	// Experiments enrolls delegated callers in experiments with their root.
	// Default false: agent traffic gets control routing and no shadow.
	Experiments bool `yaml:"experiments,omitempty" json:"experiments,omitempty"`
	// AllowedModels are the gateway model aliases any delegated actor may call;
	// empty = every alias the root may call.
	AllowedModels []string `yaml:"allowedModels,omitempty" json:"allowedModels,omitempty"`
	// DeniedTools are tools a delegated actor's model call may not declare:
	// function names (matched ignoring case) and hosted tool identifiers such
	// as web_search, code_execution or mcp:<server> (matched as a prefix,
	// ignoring case and underscores; see DeniesTool). With any set, the
	// gateway refuses an agent call whose tools it cannot read.
	DeniedTools []string `yaml:"deniedTools,omitempty" json:"deniedTools,omitempty"`
	// Actors are the agents that may act. A name not listed is refused.
	Actors []AgentActor `yaml:"actors" json:"actors"`
	// Remote is the allowlist of A2A agents members may call.
	Remote []RemoteAgent `yaml:"remote,omitempty" json:"remote,omitempty"`
}

// AgentActor is one agent that may act for a principal.
type AgentActor struct {
	Name string `yaml:"name" json:"name"`
	// Harnesses it may run in (claude-code, codex, ...); empty = any.
	Harnesses []string `yaml:"harnesses,omitempty" json:"harnesses,omitempty"`
	// Groups: the root principal must hold one of them; empty = any root.
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	// Models narrows agents.allowedModels for this agent; empty = no narrowing.
	Models []string `yaml:"models,omitempty" json:"models,omitempty"`
}

// RemoteAgent is one allowlisted A2A agent (https://a2a-protocol.org).
type RemoteAgent struct {
	Name string `yaml:"name" json:"name"`
	// CardURL is the AgentCard, usually https://host/.well-known/agent-card.json.
	CardURL string `yaml:"cardURL" json:"cardURL"`
	// Digest pins the card: "sha256:<hex>" over its RFC 8785 canonical JSON, as
	// `halo agents verify` prints it. A changed card is a policy change.
	Digest string `yaml:"digest" json:"digest"`
	// PublicKey (PEM) or JWKSURL verifies the card's JWS signatures. With
	// either set, an unsigned card or a bad signature fails verification.
	PublicKey string `yaml:"publicKey,omitempty" json:"publicKey,omitempty"`
	JWKSURL   string `yaml:"jwksURL,omitempty" json:"jwksURL,omitempty"`
	// Skills are the card's skill ids members may invoke; empty = any.
	Skills []string `yaml:"skills,omitempty" json:"skills,omitempty"`
	// Rings and Units that may call it: a caller in a listed ring, or in a
	// listed unit or one below it, may. Both empty = nobody.
	Rings []string `yaml:"rings,omitempty" json:"rings,omitempty"`
	Units []string `yaml:"units,omitempty" json:"units,omitempty"`
}

// AgentLimits is a profile's (or unit overlay's) bound on delegated agents.
// A unit may only lower MaxDepth and narrow Remote (see Loosenings).
type AgentLimits struct {
	// MaxDepth lowers agents.maxDepth for the profile's members; 0 = the org's.
	MaxDepth int `yaml:"maxDepth,omitempty" json:"maxDepth,omitempty"`
	// Remote names the agents.remote entries members may call; empty = every
	// entry whose rings or units admit them.
	Remote []string `yaml:"remote,omitempty" json:"remote,omitempty"`
}

// Depth is the effective org-level maximum delegation depth.
func (a *Agents) Depth() int {
	if a == nil || a.MaxDepth <= 0 {
		return DefaultAgentMaxDepth
	}
	return min(a.MaxDepth, MaxAgentDepth)
}

// TTL is the delegated credential lifetime cap.
func (a *Agents) TTL() time.Duration {
	if a == nil || a.MaxTTLSeconds <= 0 {
		return DefaultAgentTTL
	}
	return min(time.Duration(a.MaxTTLSeconds)*time.Second, MaxWorkloadTTL)
}

// AllowsExperiments reports whether delegated callers may be enrolled in experiments.
func (a *Agents) AllowsExperiments() bool { return a != nil && a.Experiments }

// Actor returns the named agent, or nil.
func (a *Agents) Actor(name string) *AgentActor {
	if a == nil {
		return nil
	}
	for i := range a.Actors {
		if a.Actors[i].Name == name {
			return &a.Actors[i]
		}
	}
	return nil
}

// RemoteAgent returns the named remote agent, or nil.
func (a *Agents) RemoteAgent(name string) *RemoteAgent {
	if a == nil {
		return nil
	}
	for i := range a.Remote {
		if a.Remote[i].Name == name {
			return &a.Remote[i]
		}
	}
	return nil
}

// ModelLimit is the policy's model allowlist for actor: agents.allowedModels
// narrowed by the actor's own models. nil = unrestricted. A non-nil empty
// slice means nothing is allowed (the two lists do not intersect).
func (a *Agents) ModelLimit(actor *AgentActor) []string {
	var lim []string
	if a != nil && len(a.AllowedModels) > 0 {
		lim = slices.Clone(a.AllowedModels)
	}
	if actor != nil && len(actor.Models) > 0 {
		lim = IntersectScope(lim, actor.Models)
	}
	return lim
}

// IntersectScope intersects two model scopes where nil means unrestricted.
// The result is nil only when both are nil; otherwise it is non-nil (possibly
// empty: nothing allowed), so an empty intersection can never widen to "all".
func IntersectScope(a, b []string) []string {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		return append([]string{}, b...)
	case b == nil:
		return append([]string{}, a...)
	}
	out := []string{}
	for _, m := range a {
		if slices.Contains(b, m) && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// DeniesTool reports whether agents.deniedTools denies one tool a model call
// declares. A function tool (run by the client, named in the request) matches
// an entry ignoring case. A hosted tool (run by the provider or built in,
// identified by its type, its Gemini or Bedrock tool key, or mcp:<label>)
// matches an entry when, ignoring case and underscores, its identifier starts
// with the entry: web_search denies web_search_20250305 and
// web_search_preview, code_execution denies codeExecution, and mcp denies
// every mcp:<label>. Hosted identifiers carry versions and vendor spellings,
// so an exact match would let the next version through.
func (a *Agents) DeniesTool(name string, hosted bool) bool {
	if a == nil {
		return false
	}
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, "_", "")) }
	for _, d := range a.DeniedTools {
		if strings.EqualFold(d, name) || (hosted && norm(d) != "" && strings.HasPrefix(norm(name), norm(d))) {
			return true
		}
	}
	return false
}

// AdmitChain re-checks a delegation chain against the current policy for a
// root holding rootGroups: every actor, not only the current one, must still
// be in agents.actors and, when the actor lists groups, the root must hold one
// of them; the chain must be within agents.maxDepth. The credential says what
// policy allowed at issuance, not what it allows now.
func (a *Agents) AdmitChain(rootGroups []string, d *DelegationChain) error {
	if a == nil {
		return errors.New("delegated agent credentials are not accepted: the policy declares no agents")
	}
	for _, ac := range d.actors() {
		actor := a.Actor(ac.Agent)
		switch {
		case actor == nil:
			return fmt.Errorf("agent %q is not in agents.actors", ac.Agent)
		case len(actor.Groups) > 0 && !slices.ContainsFunc(actor.Groups, func(g string) bool { return slices.Contains(rootGroups, g) }):
			return fmt.Errorf("agent %q may act only for members of %v", ac.Agent, actor.Groups)
		}
	}
	if d.Depth() > a.Depth() {
		return fmt.Errorf("delegation depth %d exceeds agents.maxDepth %d", d.Depth(), a.Depth())
	}
	return nil
}

// ChainModelLimit is a delegation chain's model allowlist under the current
// policy: the credential's scope narrowed by agents.allowedModels and by the
// models of every actor along the chain. nil = unrestricted; a non-nil empty
// slice allows nothing.
func (a *Agents) ChainModelLimit(d *DelegationChain) []string {
	var lim []string
	if d != nil {
		lim = d.Models
	}
	lim = IntersectScope(lim, a.ModelLimit(nil))
	for _, ac := range d.actors() {
		if actor := a.Actor(ac.Agent); actor != nil && len(actor.Models) > 0 {
			lim = IntersectScope(lim, actor.Models)
		}
	}
	return lim
}

func (d *DelegationChain) actors() []Actor {
	if d == nil {
		return nil
	}
	return d.Actors
}

// agentDepth is p's effective maximum delegation depth under o.
func (o *Org) agentDepth(p *Profile) int {
	d := o.Agents.Depth()
	if p != nil && p.Agents.MaxDepth > 0 {
		d = min(d, p.Agents.MaxDepth)
	}
	return d
}

// AgentScope is what the policy allows delegated agents of one root principal.
type AgentScope struct {
	Ring, Unit string
	// MaxDepth is the effective maximum chain length for this root.
	MaxDepth int
	// Remote names the agents.remote entries the root's agents may call.
	Remote []string
}

// AgentScopeFor resolves s's ring, profile and unit and returns the effective
// agent limits. An error means the effective profile could not be computed
// (a policy that Validate rejects); callers must fail closed.
func (o *Org) AgentScopeFor(s Subject) (AgentScope, error) {
	var ring, unit string
	if r := o.ResolveRing(s); r != nil {
		ring = r.Name
	}
	if u := o.ResolveUnit(s); u != nil {
		unit = u.Name
	}
	return o.AgentScopeIn(ring, unit)
}

// AgentScopeIn is AgentScopeFor for a caller already resolved to ring and
// unit ("" = none). It depends only on the policy and the two names, so a
// caller may memoise it per policy snapshot.
func (o *Org) AgentScopeIn(ring, unit string) (AgentScope, error) {
	sc := AgentScope{Ring: ring, Unit: unit}
	var prof *Profile
	if i := slices.IndexFunc(o.Rings, func(r *Ring) bool { return r.Name == ring }); ring != "" && i >= 0 {
		base, err := o.ResolveProfile(o.Rings[i].Profile)
		if err != nil {
			return AgentScope{}, err
		}
		prof = base
		if unit != "" {
			eff, err := o.EffectiveProfile(prof, unit)
			if err != nil {
				return AgentScope{}, err
			}
			prof = eff
		}
	}
	sc.MaxDepth = o.agentDepth(prof)
	if o.Agents == nil {
		return sc, nil
	}
	var units []string
	if sc.Unit != "" {
		chain, err := o.UnitChain(sc.Unit)
		if err != nil {
			return AgentScope{}, err
		}
		for _, u := range chain {
			units = append(units, u.Name)
		}
	}
	for _, ra := range o.Agents.Remote {
		admitted := (sc.Ring != "" && slices.Contains(ra.Rings, sc.Ring)) || slices.ContainsFunc(units, func(u string) bool { return slices.Contains(ra.Units, u) })
		if !admitted {
			continue
		}
		if prof != nil && len(prof.Agents.Remote) > 0 && !slices.Contains(prof.Agents.Remote, ra.Name) {
			continue
		}
		sc.Remote = append(sc.Remote, ra.Name)
	}
	return sc, nil
}

// RemoteDecision is the egress verdict for one call to a remote agent.
type RemoteDecision struct {
	Allow  bool   `json:"allow"`
	Agent  string `json:"agent,omitempty"`
	Digest string `json:"digest,omitempty"`
	Reason string `json:"reason"`
	Ring   string `json:"ring,omitempty"`
	Unit   string `json:"unit,omitempty"`
}

// DecideRemote decides whether s (with delegation d, may be nil) may call
// remote agent name (or, when name is empty, the agent whose AgentCard is
// served from target's origin) and, when skill is set, invoke that skill.
func (o *Org) DecideRemote(s Subject, d *DelegationChain, name, target, skill string) RemoteDecision {
	if o.Agents == nil || len(o.Agents.Remote) == 0 {
		return RemoteDecision{Reason: "policy declares no agents.remote"}
	}
	var cands []*RemoteAgent
	switch {
	case name != "":
		if ra := o.Agents.RemoteAgent(name); ra != nil {
			cands = append(cands, ra)
		}
	case target != "":
		for i := range o.Agents.Remote {
			if sameOrigin(o.Agents.Remote[i].CardURL, target) {
				cands = append(cands, &o.Agents.Remote[i])
			}
		}
	}
	if len(cands) == 0 {
		return RemoteDecision{Reason: "not an allowlisted remote agent (agents.remote)"}
	}
	if d.Depth() > 0 {
		if err := o.Agents.AdmitChain(s.Groups, d); err != nil {
			return RemoteDecision{Reason: err.Error()}
		}
	}
	sc, err := o.AgentScopeFor(s)
	if err != nil {
		return RemoteDecision{Reason: "policy cannot be resolved for this caller: " + err.Error()}
	}
	if d.Depth() > sc.MaxDepth {
		return RemoteDecision{Ring: sc.Ring, Unit: sc.Unit, Reason: fmt.Sprintf("delegation depth %d exceeds the maximum %d (agents.maxDepth, profile and unit agents.maxDepth)", d.Depth(), sc.MaxDepth)}
	}
	dec := RemoteDecision{Ring: sc.Ring, Unit: sc.Unit, Reason: "the caller's ring and unit may not call it (agents.remote rings/units, profile agents.remote)"}
	for _, ra := range cands {
		if !slices.Contains(sc.Remote, ra.Name) {
			continue
		}
		if skill != "" && len(ra.Skills) > 0 && !slices.Contains(ra.Skills, skill) {
			dec.Agent, dec.Reason = ra.Name, fmt.Sprintf("skill %q is not in agents.remote[%s].skills", skill, ra.Name)
			continue
		}
		return RemoteDecision{Allow: true, Agent: ra.Name, Digest: ra.Digest, Ring: sc.Ring, Unit: sc.Unit, Reason: "allowed"}
	}
	return dec
}

// sameOrigin reports whether a and b share scheme, host and port.
func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Host != "" && strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

var cardDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// SecureAgentURL reports whether s is an absolute https URL without
// credentials or fragment (an AgentCard or JWKS location).
func SecureAgentURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

// ParseCardKey parses a PEM PUBLIC KEY usable for AgentCard JWS: ed25519,
// ECDSA P-256/P-384 or RSA >= 2048 bits.
func ParseCardKey(pemData string) (any, error) {
	blk, _ := pem.Decode([]byte(pemData))
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM PUBLIC KEY block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	switch k := k.(type) {
	case ed25519.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("ECDSA key must be P-256 or P-384")
		}
		return k, nil
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA key is %d bits, want >= 2048", k.N.BitLen())
		}
		return k, nil
	}
	return nil, fmt.Errorf("unsupported key type %T", k)
}

func (v *validator) agents() {
	a := v.org.Agents
	if a == nil {
		for name, p := range v.org.Profiles {
			if p.Agents.MaxDepth != 0 || len(p.Agents.Remote) > 0 {
				v.errf("profiles["+name+"].agents", "set halos.yaml agents first; profile agents only narrow it")
			}
		}
		for _, u := range v.org.Units {
			if u.Overlay.Agents.MaxDepth != 0 || len(u.Overlay.Agents.Remote) > 0 {
				v.errf("units["+u.Name+"].overlay.agents", "set halos.yaml agents first; unit agents only narrow it")
			}
		}
		return
	}
	if a.MaxDepth < 0 || a.MaxDepth > MaxAgentDepth {
		v.errf("agents.maxDepth", "%d must be 1..%d", a.MaxDepth, MaxAgentDepth)
	}
	if a.MaxTTLSeconds < 0 || time.Duration(a.MaxTTLSeconds)*time.Second > MaxWorkloadTTL {
		v.errf("agents.maxTTLSeconds", "%d must be 1..%d", a.MaxTTLSeconds, int(MaxWorkloadTTL.Seconds()))
	}
	aliasKnown := func(m string) bool {
		if v.org.Gateway == nil {
			return true
		}
		_, ok := v.org.Gateway.Models[m]
		return ok
	}
	for i, m := range a.AllowedModels {
		if !aliasKnown(m) {
			v.errf(fmt.Sprintf("agents.allowedModels[%d]", i), "%q is not a gateway.models alias", m)
		}
	}
	for i, t := range a.DeniedTools {
		if strings.TrimSpace(t) == "" {
			v.errf(fmt.Sprintf("agents.deniedTools[%d]", i), "empty tool name")
		}
	}
	if len(a.Actors) == 0 {
		v.warnf("agents.actors", "no actors: every delegation is refused")
	}
	seen := map[string]bool{}
	for i, ac := range a.Actors {
		p := fmt.Sprintf("agents.actors[%d]", i)
		if !ValidName(ac.Name) {
			v.errf(p+".name", "name %q invalid: must match %s", ac.Name, nameRe)
		} else if seen[ac.Name] {
			v.errf(p+".name", "duplicate actor %q", ac.Name)
		}
		seen[ac.Name] = true
		for _, h := range ac.Harnesses {
			v.oneOf(p+".harnesses", "harness", h, knownHarnesses)
		}
		for j, m := range ac.Models {
			if !aliasKnown(m) {
				v.errf(fmt.Sprintf("%s.models[%d]", p, j), "%q is not a gateway.models alias", m)
			} else if len(a.AllowedModels) > 0 && !slices.Contains(a.AllowedModels, m) {
				v.errf(fmt.Sprintf("%s.models[%d]", p, j), "%q is not in agents.allowedModels; an actor's models only narrow it", m)
			}
		}
	}
	rings := map[string]bool{}
	for _, r := range v.org.Rings {
		rings[r.Name] = true
	}
	remote := map[string]bool{}
	for i, ra := range a.Remote {
		p := fmt.Sprintf("agents.remote[%d]", i)
		if !ValidName(ra.Name) {
			v.errf(p+".name", "name %q invalid: must match %s", ra.Name, nameRe)
		} else if remote[ra.Name] {
			v.errf(p+".name", "duplicate remote agent %q", ra.Name)
		}
		remote[ra.Name] = true
		if !SecureAgentURL(ra.CardURL) {
			v.errf(p+".cardURL", "%q must be an absolute https URL without credentials or fragment", ra.CardURL)
		}
		if !cardDigestRe.MatchString(ra.Digest) {
			v.errf(p+".digest", "%q must be sha256:<64 hex>; run `halo agents verify %s` to get it", ra.Digest, ra.CardURL)
		}
		if ra.PublicKey != "" {
			if _, err := ParseCardKey(ra.PublicKey); err != nil {
				v.errf(p+".publicKey", "%v", err)
			}
		}
		if ra.JWKSURL != "" && !SecureAgentURL(ra.JWKSURL) {
			v.errf(p+".jwksURL", "%q must be an absolute https URL without credentials or fragment", ra.JWKSURL)
		}
		if ra.PublicKey == "" && ra.JWKSURL == "" {
			v.warnf(p, "no publicKey or jwksURL: the card's signature is not verified, only its digest pins it")
		}
		if len(ra.Skills) == 0 {
			v.warnf(p+".skills", "empty: every skill on the card may be invoked")
		}
		if len(ra.Rings)+len(ra.Units) == 0 {
			v.warnf(p, "no rings or units: nobody may call it")
		}
		for _, r := range ra.Rings {
			if !rings[r] {
				v.errf(p+".rings", "%q is not a ring", r)
			}
		}
		for _, u := range ra.Units {
			if v.org.Unit(u) == nil {
				v.errf(p+".units", "%q is not a unit", u)
			}
		}
	}
	limits := func(path string, l AgentLimits) {
		if l.MaxDepth < 0 || l.MaxDepth > a.Depth() {
			v.errf(path+".maxDepth", "%d must be 1..%d (agents.maxDepth); profiles and units only lower it", l.MaxDepth, a.Depth())
		}
		for _, n := range l.Remote {
			if !remote[n] {
				v.errf(path+".remote", "%q is not an agents.remote name", n)
			}
		}
	}
	for _, name := range sortedKeys(v.org.Profiles) {
		limits("profiles["+name+"].agents", v.org.Profiles[name].Agents)
	}
	for _, u := range v.org.Units {
		limits("units["+u.Name+"].overlay.agents", u.Overlay.Agents)
	}
}
