package gateway

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dshakes/halos/internal/policy"
)

// RevocationList is halo-server's active credential revocations (ADR-0026),
// GET /api/v1/gateway/directory?revocations=1. It holds only revocations
// that can still matter: a jti until the longest a credential can live
// (policy.MaxWorkloadTTL) has passed since it was revoked, a subject epoch
// until that long after the epoch. So its size is bounded by what admins
// revoked in the last hour, and halo-server caps it (maxActiveRevocations).
type RevocationList struct {
	// JTIs maps a revoked credential id to when the entry lapses (unix seconds).
	JTIs map[string]int64 `json:"jtis"`
	// Subjects maps a canonical subject (policy.CanonicalUser of a human root
	// id, a "workload:" subject or "agent:<name>") to its revoked-before epoch
	// (unix seconds): see Check.
	Subjects map[string]int64 `json:"subjects"`
}

// ErrCredentialRevoked is the answer for a credential the revocation list kills.
var ErrCredentialRevoked = errors.New("credential revoked")

// RejectCredentialRevoked is the 401, in the caller's protocol, for ErrCredentialRevoked.
func RejectCredentialRevoked(path string) *Rejection {
	return &Rejection{Status: http.StatusUnauthorized, Protocol: protocolOrPrefix(path), Code: "credential_revoked",
		Message: "halos: this credential was revoked; obtain a new one (halo ci token, or a new delegation)"}
}

// Check returns ErrCredentialRevoked (wrapped with the reason) when the
// credential sub was verified from is dead:
//   - its jti, or the jti of any credential it was exchanged from, is revoked;
//   - its root principal has an epoch at or after the root's authentication
//     (a delegated credential's auth_time, a workload credential's iat);
//   - an agent of its delegation chain has an epoch at or after its iat.
//
// A subject with no halo-server credential (an IdP user) is never revoked here.
func (l *RevocationList) Check(sub *policy.Subject) error {
	if l == nil || sub == nil || sub.Credential == nil {
		return nil
	}
	c := sub.Credential
	for _, id := range c.IDs {
		if _, ok := l.JTIs[id]; ok {
			return fmt.Errorf("%w: credential %s", ErrCredentialRevoked, id)
		}
	}
	root := c.IssuedAt
	if sub.Delegation != nil && sub.Delegation.AuthTime != 0 {
		root = sub.Delegation.AuthTime
	}
	if e, ok := l.Subjects[policy.CanonicalUser(sub.ID)]; ok && root <= e {
		return fmt.Errorf("%w: principal %s", ErrCredentialRevoked, sub.ID)
	}
	if sub.Delegation != nil {
		for _, a := range sub.Delegation.Actors {
			if e, ok := l.Subjects[policy.CanonicalUser(policy.AgentSubjectPrefix+a.Agent)]; ok && c.IssuedAt <= e {
				return fmt.Errorf("%w: agent %s", ErrCredentialRevoked, a.Agent)
			}
		}
	}
	return nil
}

// RevocationSubjects are the canonical subjects whose epochs apply to sub's credential
// (its root and every agent of its chain); nil without a credential.
func RevocationSubjects(sub *policy.Subject) []string {
	if sub == nil || sub.Credential == nil {
		return nil
	}
	out := []string{policy.CanonicalUser(sub.ID)}
	if sub.Delegation != nil {
		for _, a := range sub.Delegation.Actors {
			out = append(out, policy.CanonicalUser(policy.AgentSubjectPrefix+a.Agent))
		}
	}
	return out
}

// DirectoryReject maps a DirectoryClient.Resolve error to the rejection a
// gateway answers, in the caller's protocol.
func DirectoryReject(path string, err error) *Rejection {
	switch {
	case errors.Is(err, ErrCredentialRevoked):
		return RejectCredentialRevoked(path)
	case errors.Is(err, ErrDirectoryUnavailable):
		return RejectDirectoryUnavailable(path)
	}
	return RejectNotProvisioned(path)
}
