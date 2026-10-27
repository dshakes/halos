package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Delegated agent credentials (ADR-0024): halo-server exchanges a verified
// Halos credential (a human session, a workload credential, or another
// delegated credential) for a short-lived JWT naming the agent that acts for
// the root principal. The act claim is RFC 8693 section 4.1: the top-level act
// is the current actor and each nested act a prior one. Signed with the
// workload key and verified by the same code at halo-server and the gateways.
const (
	// DelegatedTokenType is the JWT typ header of a delegated credential.
	DelegatedTokenType = "halo-agent+jwt" //nolint:gosec // JWT typ value, not a credential
	// KindAgent is the kind claim of a delegated credential.
	KindAgent = "agent"
)

// Act is one RFC 8693 actor claim: the actor, and in Act the actor before it.
type Act struct {
	Subject string `json:"sub"`               // "agent:<name>"
	Harness string `json:"harness,omitempty"` // where it runs, e.g. claude-code
	Session string `json:"session,omitempty"` // the harness session id
	Act     *Act   `json:"act,omitempty"`
}

// DelegatedClaims is the payload of a delegated credential. Subject and Groups
// are the root principal's (RootKind "" human, "workload"); Act is the chain.
type DelegatedClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience string   `json:"aud"`
	Groups   []string `json:"groups,omitempty"`
	Kind     string   `json:"kind"`
	RootKind string   `json:"root_kind,omitempty"`
	Act      *Act     `json:"act"`
	// Models narrows the aliases the credential may call; absent = not
	// narrowed by the credential (policy still applies). halo-server never
	// mints an empty scope: an empty intersection is refused, not widened.
	Models []string `json:"models,omitempty"`
	// AuthTime is when the root authenticated (OIDC auth_time): a session
	// revoked after it kills the credential at its next exchange.
	AuthTime  int64  `json:"auth_time,omitempty"`
	Parent    string `json:"parent_jti,omitempty"` // jti of the credential it was exchanged from
	// Ancestors are the jtis of the credentials before the parent (its
	// parent first), so revoking any ancestor's jti (ADR-0026) also kills
	// this credential. Absent when the parent was minted from a session or
	// from nothing with a jti.
	Ancestors []string `json:"anc_jti,omitempty"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	ID        string `json:"jti"`
}

// Chain returns the actors root-side first (the current actor last).
func (c DelegatedClaims) Chain() []policy.Actor {
	var rev []policy.Actor
	for a := c.Act; a != nil; a = a.Act {
		rev = append(rev, policy.Actor{Agent: strings.TrimPrefix(a.Subject, policy.AgentSubjectPrefix), Harness: a.Harness, Session: a.Session})
	}
	slices.Reverse(rev)
	return rev
}

// ModelScope returns the credential's model scope (nil = not narrowed).
func (c DelegatedClaims) ModelScope() []string {
	if len(c.Models) == 0 {
		return nil
	}
	return append([]string{}, c.Models...)
}

// ActFromChain builds the nested act claim from a chain listed root-side first.
func ActFromChain(chain []policy.Actor) *Act {
	var act *Act
	for _, a := range chain {
		act = &Act{Subject: policy.AgentSubjectPrefix + a.Agent, Harness: a.Harness, Session: a.Session, Act: act}
	}
	return act
}

// AsSubject is the verified caller the gateway routes: the root principal
// with the delegation and the credential's lineage (for revocation) attached.
func (c DelegatedClaims) AsSubject() policy.Subject {
	return policy.Subject{ID: c.Subject, Groups: c.Groups, Kind: c.RootKind,
		Delegation: &policy.DelegationChain{Actors: c.Chain(), Models: c.ModelScope(), ID: c.ID, AuthTime: c.AuthTime},
		Credential: &policy.CredentialRef{IDs: c.Lineage(), IssuedAt: c.IssuedAt}}
}

// Lineage is the credential's jti, then its parent's and the ancestors'.
func (c DelegatedClaims) Lineage() []string {
	ids := []string{c.ID}
	if c.Parent != "" {
		ids = append(ids, c.Parent)
	}
	return append(ids, c.Ancestors...)
}

// SignDelegatedToken signs c with the workload key. It refuses claims
// VerifyDelegatedToken would reject.
func SignDelegatedToken(key ed25519.PrivateKey, c DelegatedClaims) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("identity: delegation signing key is not an ed25519 private key")
	}
	if err := c.check(time.Unix(c.IssuedAt, 0)); err != nil {
		return "", fmt.Errorf("identity: refusing to sign delegated token: %w", err)
	}
	return signJWT(key, DelegatedTokenType, c)
}

// VerifyDelegatedToken checks the signature against keys (by kid), then the
// claims: iss, aud, kind, root subject, act chain (depth <= policy.MaxAgentDepth,
// no agent twice), exp, nbf, iat and the lifetime cap.
func VerifyDelegatedToken(keys []ed25519.PublicKey, tok string, now time.Time) (DelegatedClaims, error) {
	var c DelegatedClaims
	if err := verifyJWT(keys, DelegatedTokenType, tok, &c); err != nil {
		return DelegatedClaims{}, err
	}
	if err := c.check(now); err != nil {
		return DelegatedClaims{}, fmt.Errorf("identity: delegated token rejected: %w", claimsError{err})
	}
	return c, nil
}

func (c DelegatedClaims) check(now time.Time) error {
	exp, nbf, iat := time.Unix(c.Expiry, 0), time.Unix(c.NotBefore, 0), time.Unix(c.IssuedAt, 0)
	switch {
	case c.Issuer != WorkloadIssuer:
		return fmt.Errorf("iss %q, want %q", c.Issuer, WorkloadIssuer)
	case c.Audience != WorkloadAudience:
		return fmt.Errorf("aud %q, want %q", c.Audience, WorkloadAudience)
	case c.Kind != KindAgent:
		return fmt.Errorf("kind %q, want %q", c.Kind, KindAgent)
	case c.Subject == "":
		return errors.New("sub is required")
	case c.RootKind == policy.SubjectWorkload && !strings.HasPrefix(c.Subject, policy.WorkloadSubjectPrefix):
		return fmt.Errorf("workload root %q lacks the %q prefix", c.Subject, policy.WorkloadSubjectPrefix)
	case c.RootKind == "" && CheckHumanID(c.Subject) != nil:
		return fmt.Errorf("human root %q takes the reserved %q prefix", c.Subject, policy.WorkloadSubjectPrefix)
	case c.RootKind != "" && c.RootKind != policy.SubjectWorkload:
		return fmt.Errorf("root_kind %q, want \"\" or %q", c.RootKind, policy.SubjectWorkload)
	case c.Expiry == 0 || c.IssuedAt == 0 || c.NotBefore == 0 || c.ID == "":
		return errors.New("exp, iat, nbf and jti are required")
	case !now.Before(exp):
		return fmt.Errorf("%w at %s", ErrTokenExpired, exp.UTC().Format(time.RFC3339))
	case nbf.After(now.Add(workloadSkew)), iat.After(now.Add(workloadSkew)):
		return errors.New("not yet valid (nbf/iat in the future)")
	case exp.Sub(iat) > policy.MaxWorkloadTTL:
		return fmt.Errorf("lifetime %s exceeds %s", exp.Sub(iat), policy.MaxWorkloadTTL)
	case len(c.Ancestors) > policy.MaxAgentDepth || (len(c.Ancestors) > 0 && c.Parent == "") || slices.Contains(c.Ancestors, ""):
		return errors.New("anc_jti: at most one per possible ancestor, non-empty, and only with a parent_jti")
	}
	return CheckChain(c.Chain())
}

// Limits of an actor's harness and session labels. Both are self-asserted by
// the caller of the exchange: labels for audit and correlation, never a
// control. The character set keeps them from forging structure in the audit
// chain detail ("agent(harness/session)>...") or a terminal.
const (
	maxActorHarness = 64
	maxActorSession = 256
)

var actorLabelRe = regexp.MustCompile(`^[A-Za-z0-9._:-]*$`)

// CheckChain enforces the structure every delegation chain must have: 1 to
// policy.MaxAgentDepth actors, each a valid agent name, none twice (a cycle),
// harness and session labels within their length and character set.
func CheckChain(chain []policy.Actor) error {
	if len(chain) == 0 {
		return errors.New("act claim is required")
	}
	if len(chain) > policy.MaxAgentDepth {
		return fmt.Errorf("delegation depth %d exceeds %d", len(chain), policy.MaxAgentDepth)
	}
	seen := map[string]bool{}
	for _, a := range chain {
		if !policy.ValidName(a.Agent) {
			return fmt.Errorf("actor %q is not an agent name", a.Agent)
		}
		if seen[a.Agent] {
			return fmt.Errorf("delegation cycle: agent %q appears twice", a.Agent)
		}
		seen[a.Agent] = true
		if len(a.Harness) > maxActorHarness || len(a.Session) > maxActorSession {
			return errors.New("actor harness or session too long")
		}
		if !actorLabelRe.MatchString(a.Harness) || !actorLabelRe.MatchString(a.Session) {
			return errors.New("actor harness and session may hold only A-Z a-z 0-9 . _ : -")
		}
	}
	return nil
}

// signJWT encodes c under a typ header with the key's kid and signs it.
func signJWT(key ed25519.PrivateKey, typ string, c any) (string, error) {
	pub, _ := key.Public().(ed25519.PublicKey)
	hb, err := json.Marshal(workloadHeader{Alg: "EdDSA", Typ: typ, Kid: WorkloadKeyID(pub)})
	if err != nil {
		return "", fmt.Errorf("identity: encode %s header: %w", typ, err)
	}
	cb, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("identity: encode %s claims: %w", typ, err)
	}
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	return in + "." + b64.EncodeToString(ed25519.Sign(key, []byte(in))), nil
}

// verifyJWT checks a compact EdDSA JWS of type typ against keys (by kid) and
// decodes its payload into c. Claims are not checked.
func verifyJWT(keys []ed25519.PublicKey, typ, tok string, c any) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return fmt.Errorf("identity: %s is not a compact JWS", typ)
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("identity: %s header: %w", typ, err)
	}
	var hdr workloadHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return fmt.Errorf("identity: %s header: %w", typ, err)
	}
	if hdr.Alg != "EdDSA" || hdr.Typ != typ {
		return fmt.Errorf("identity: token alg %q / typ %q not accepted (want EdDSA / %s)", hdr.Alg, hdr.Typ, typ)
	}
	var key ed25519.PublicKey
	for _, k := range keys {
		if WorkloadKeyID(k) == hdr.Kid {
			key = k
			break
		}
	}
	if key == nil {
		return fmt.Errorf("identity: %s kid %q is not a trusted halo-server key", typ, hdr.Kid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return fmt.Errorf("identity: %s signature invalid", typ)
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("identity: %s payload: %w", typ, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(cb)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("identity: %s payload: %w", typ, err)
	}
	return nil
}

// TokenType returns the (unverified) typ header of a compact JWT, "" when
// unreadable. Used only to pick a verifier.
func TokenType(tok string) string {
	h, _, ok := strings.Cut(tok, ".")
	if !ok {
		return ""
	}
	var hdr workloadHeader
	b, err := b64.DecodeString(h)
	if err != nil || json.Unmarshal(b, &hdr) != nil {
		return ""
	}
	return hdr.Typ
}
