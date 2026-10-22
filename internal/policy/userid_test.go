package policy

import (
	"strings"
	"testing"
)

// CanonicalUser folds real case pairs, so one person is one user however the
// IdP cases the id, and never folds a lookalike into another letter, so a
// lookalike id is never someone else (strings.ToLower maps the Kelvin sign to
// k and U+0130 to i).
func TestCanonicalUser(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"Alice@Corp.com", "alice@corp.com"},
		{"  bob@x.example\t", "bob@x.example"},
		{"JOSÉ@x.example", "josé@x.example"},
		{"ΣΩΚΡΑΤΗΣ@x.example", "σωκρατησ@x.example"},
	} {
		if CanonicalUser(tc.a) != CanonicalUser(tc.b) {
			t.Errorf("%q and %q: %q != %q, want the same user", tc.a, tc.b, CanonicalUser(tc.a), CanonicalUser(tc.b))
		}
	}
	for _, tc := range []struct{ lookalike, real string }{
		{"Kelly@x.example", "kelly@x.example"}, // Kelvin sign
		{"İnes@x.example", "ines@x.example"},   // I with dot above
		{"Ωmega@x.example", "ωmega@x.example"}, // Ohm sign
		{"Åsa@x.example", "åsa@x.example"},     // Angstrom sign
		{"ｋelly@x.example", "kelly@x.example"}, // fullwidth k
		{"ſam@x.example", "sam@x.example"},     // long s
		{"Kelly@x.example", "Kelly@x.example"}, // itself: equal (sanity)
	} {
		same := CanonicalUser(tc.lookalike) == CanonicalUser(tc.real)
		if want := tc.lookalike == tc.real; same != want {
			t.Errorf("%q vs %q: same=%v, want %v", tc.lookalike, tc.real, same, want)
		}
		if strings.ToLower(tc.lookalike) == strings.ToLower(tc.real) && tc.lookalike != tc.real && CanonicalUser(tc.lookalike) == CanonicalUser(tc.real) {
			t.Errorf("%q: folded like strings.ToLower", tc.lookalike)
		}
	}
}
