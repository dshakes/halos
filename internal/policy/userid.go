package policy

import (
	"strings"
	"unicode"
)

// CanonicalUser is the one form in which Halos compares or keys a human user
// id: halo-server's sessions, devices, enrollments, posture, SCIM userName,
// access-request self-approval and whoami, and the per-user budget counters
// (budget.Charges) that halo-server and the gateways share. It trims
// surrounding space and lowercases, so an IdP that provisions
// "Alice@Corp.com" and logs in "alice@corp.com" is one user.
//
// It never merges a lookalike into another letter. strings.ToLower maps the
// Kelvin sign U+212A to "k", U+0130 (I with dot) to "i", the Ohm sign to
// omega and the Angstrom sign to a-ring, so "Kelly" would key the same
// sessions, devices and budget as "kelly". A rune is lowercased only when
// uppercasing the result gives it back (a real case pair: A/a, É/é, Σ/σ);
// compatibility characters are kept as they are, so a lookalike id stays a
// different user. This is the outcome of rejecting such ids without needing
// a refusal at every identity entry point. Not NFKC: compatibility
// normalisation would merge exactly these lookalikes (and fullwidth letters)
// into the ASCII ids they imitate.
func CanonicalUser(id string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x80 {
			if 'A' <= r && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}
		if l := unicode.ToLower(r); l != r && unicode.ToUpper(l) == r {
			return l
		}
		return r
	}, strings.TrimSpace(id))
}
