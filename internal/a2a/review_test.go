package a2a

import (
	"net/netip"
	"slices"
	"testing"
)

// TestCanonicalizeRefusesLossyUnicode (L4): encoding/json turns invalid
// UTF-8 and lone surrogate escapes into U+FFFD, so without a check these
// distinct cards would share one canonical form and one pinned digest.
func TestCanonicalizeRefusesLossyUnicode(t *testing.T) {
	for _, s := range []string{
		`{"a":"\ud800"}`,   // lone high surrogate
		`{"a":"\udfff"}`,   // lone low surrogate
		`{"a":"\ud800A"}`,  // high followed by a non-surrogate
		`{"a":"x\uDBFFy"}`, // upper-case hex
		"{\"a\":\"\xff\"}", // invalid UTF-8 byte
		"{\"\xc3\":1}",     // truncated sequence in a key
	} {
		if c, err := Canonicalize([]byte(s)); err == nil {
			t.Errorf("%q canonicalized to %s", s, c)
		}
		if _, err := Digest([]byte(s)); err == nil {
			t.Errorf("%q has a digest", s)
		}
	}
	for s, want := range map[string]string{
		`{"a":"😀"}`:       `{"a":"😀"}`,       // a surrogate pair
		`{"a":"\\ud800"}`: `{"a":"\\ud800"}`, // an escaped backslash, not an escape
		`{"a":"\"é"}`:     `{"a":"\"é"}`,
		`{"a":"�"}`:       `{"a":"�"}`, // a real U+FFFD is fine
	} {
		c, err := Canonicalize([]byte(s))
		if err != nil || string(c) != want {
			t.Errorf("%s: %s %v, want %s", s, c, err, want)
		}
	}
}

// TestParseCardExactKeys (L4): skills under a case variant of a key do not
// reach Halos's view of the card.
func TestParseCardExactKeys(t *testing.T) {
	c, err := ParseCard([]byte(`{"name":"x","skills":[{"id":"safe"}],"SKILLS":[{"id":"admin"}],"Skills":[{"ID":"root"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.SkillIDs(); !slices.Equal(got, []string{"safe"}) {
		t.Fatalf("skills %v, want [safe]", got)
	}
	c, err = ParseCard([]byte(`{"NAME":"x","name":"y","skills":[{"ID":"admin","id":"safe"}],"supportedInterfaces":[{"url":"https://a","URL":"https://b"}]}`))
	if err != nil || c.Name != "y" || !slices.Equal(c.SkillIDs(), []string{"safe"}) || c.SupportedInterfaces[0].URL != "https://a" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, s := range []string{`[1]`, `{"name":5}`, `{"name":"x","skills":{"id":"a"}}`, `{"name":"x","skills":["a"]}`, `{"name":"x","securitySchemes":[]}`, `{"name":"x","signatures":[{"header":1}]}`} {
		if _, err := ParseCard([]byte(s)); err == nil {
			t.Errorf("%s parsed", s)
		}
	}
}

// TestPublicAddrTransition (L5): IPv6 transition ranges that embed an IPv4
// address are not public, whatever IPv4 address they carry.
func TestPublicAddrTransition(t *testing.T) {
	for _, a := range []string{
		"64:ff9b::7f00:1",                      // NAT64 well-known, 127.0.0.1
		"64:ff9b::808:808",                     // NAT64 well-known, even 8.8.8.8
		"64:ff9b:1::a00:1",                     // NAT64 local-use, 10.0.0.1
		"2002:7f00:1::1",                       // 6to4, 127.0.0.1
		"2002:a9fe:a9fe::1",                    // 6to4, 169.254.169.254
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
		"::7f00:1",                             // IPv4-compatible 127.0.0.1
		"192.88.99.1",                          // 6to4 relay anycast
	} {
		if publicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s is public", a)
		}
	}
	for _, a := range []string{"2001:4860:4860::8888", "2606:4700::1111", "2003::1"} {
		if !publicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s is not public", a)
		}
	}
}
