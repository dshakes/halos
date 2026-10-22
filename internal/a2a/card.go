// Package a2a fetches and verifies Agent2Agent (A2A) AgentCards for the
// remote-agent allowlist (ADR-0024): bounded, SSRF-safe https fetches, the
// card digest Halos pins into policy and releases, and the card's JWS
// signatures (A2A specification v1.0, section 8.4: RFC 7515 JWS over the RFC
// 8785 canonical card without its signatures field).
package a2a

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Limits of a card or JWKS fetch.
const (
	MaxCardBytes   = 256 << 10
	DefaultTimeout = 10 * time.Second
	maxRedirects   = 3
)

// Errors callers branch on.
var (
	ErrDigestMismatch = errors.New("a2a: AgentCard digest does not match the pinned digest")
	ErrSignature      = errors.New("a2a: AgentCard signature verification failed")
	ErrBlockedAddress = errors.New("a2a: destination address is not public")
)

// Card is the part of an AgentCard Halos reads. Unknown fields are kept in
// the raw bytes (the digest and signatures cover the whole card).
type Card struct {
	Name                string               `json:"name"`
	Description         string               `json:"description"`
	Version             string               `json:"version"`
	SupportedInterfaces []Interface          `json:"supportedInterfaces"`
	URL                 string               `json:"url"` // pre-1.0 cards
	SecuritySchemes     map[string]any       `json:"securitySchemes"`
	Skills              []Skill              `json:"skills"`
	Signatures          []AgentCardSignature `json:"signatures"`
}

// Interface is one AgentInterface (transport binding and URL).
type Interface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion"`
}

// Skill is one AgentSkill.
type Skill struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AgentCardSignature is one JWS over the card (A2A section 4.4.7).
type AgentCardSignature struct {
	Protected string         `json:"protected"`
	Signature string         `json:"signature"`
	Header    map[string]any `json:"header,omitempty"`
}

// SkillIDs lists the card's skill ids.
func (c Card) SkillIDs() []string {
	out := make([]string, 0, len(c.Skills))
	for _, s := range c.Skills {
		out = append(out, s.ID)
	}
	return out
}

// Fetcher fetches cards and key sets: https only, a size and time limit, at
// most three redirects and only to the same host, and (unless AllowPrivate)
// only to public addresses, checked on the address actually dialed so DNS
// rebinding cannot reach an internal service.
type Fetcher struct {
	Timeout time.Duration // 0 = DefaultTimeout
	// AllowPrivate permits loopback, private, link-local and other
	// non-public destinations (an agent on the internal network).
	AllowPrivate bool
	// RootCAs overrides the system roots (tests, private PKI).
	RootCAs *x509.CertPool
}

func (f Fetcher) client() *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if !f.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
			}
			if !publicAddr(ap.Addr()) {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, ap.Addr())
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:               nil, // the dial check must see the destination, not a proxy
		DialContext:         d.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.RootCAs},
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConns:        1,
		DisableKeepAlives:   true,
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		switch {
		case len(via) > maxRedirects:
			return fmt.Errorf("a2a: more than %d redirects", maxRedirects)
		case req.URL.Scheme != "https":
			return fmt.Errorf("a2a: redirect to %s refused: not https", req.URL.Redacted())
		case !strings.EqualFold(req.URL.Host, via[0].URL.Host):
			return fmt.Errorf("a2a: redirect off-host to %s refused", req.URL.Host)
		}
		return nil
	}}
}

// publicAddr reports whether a is a globally routable unicast address.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// nonPublic are special-purpose ranges netip has no predicate for. IPv6
// transition ranges that embed an IPv4 address (NAT64 64:ff9b::/96 and
// 64:ff9b:1::/48, 6to4 2002::/16, Teredo 2001::/32, IPv4-compatible ::/96)
// are blocked outright rather than unwrapped and re-checked: a translator or
// relay on the path could deliver them to an internal IPv4 address, and no
// AgentCard host needs one.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}

// Get fetches rawURL (https only) within the limits and returns the body.
func (f Fetcher) Get(ctx context.Context, rawURL string) ([]byte, error) {
	if !policy.SecureAgentURL(rawURL) {
		return nil, fmt.Errorf("a2a: %q must be an absolute https URL without credentials or fragment", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("a2a: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("a2a: fetch %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("a2a: fetch %s: HTTP %d", rawURL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxCardBytes+1))
	if err != nil {
		return nil, fmt.Errorf("a2a: read %s: %w", rawURL, err)
	}
	if len(b) > MaxCardBytes {
		return nil, fmt.Errorf("a2a: %s is larger than %d bytes", rawURL, MaxCardBytes)
	}
	return b, nil
}

// ParseCard decodes a card. It must be one JSON object without duplicate
// keys. Fields are read by exact key from the same decoded value the digest
// covers: json.Unmarshal matches keys ignoring case, so a card holding both
// "skills" and "SKILLS" could show Halos one skill list and an A2A client
// another.
func ParseCard(raw []byte) (Card, error) {
	v, err := decodeJSON(raw)
	if err != nil {
		return Card{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Card{}, errors.New("a2a: AgentCard is not a JSON object")
	}
	var r cardReader
	c := Card{Name: r.str(m, "name"), Description: r.str(m, "description"), Version: r.str(m, "version"), URL: r.str(m, "url")}
	for _, i := range r.objs(m, "supportedInterfaces") {
		c.SupportedInterfaces = append(c.SupportedInterfaces, Interface{URL: r.str(i, "url"), ProtocolBinding: r.str(i, "protocolBinding"), ProtocolVersion: r.str(i, "protocolVersion")})
	}
	if s, ok := m["securitySchemes"]; ok && s != nil {
		if c.SecuritySchemes, ok = s.(map[string]any); !ok {
			r.bad("securitySchemes")
		}
	}
	for _, s := range r.objs(m, "skills") {
		c.Skills = append(c.Skills, Skill{ID: r.str(s, "id"), Name: r.str(s, "name")})
	}
	for _, s := range r.objs(m, "signatures") {
		sig := AgentCardSignature{Protected: r.str(s, "protected"), Signature: r.str(s, "signature")}
		if h, ok := s["header"]; ok && h != nil {
			if sig.Header, ok = h.(map[string]any); !ok {
				r.bad("header")
			}
		}
		c.Signatures = append(c.Signatures, sig)
	}
	if r.err != nil {
		return Card{}, r.err
	}
	if c.Name == "" {
		return Card{}, errors.New("a2a: AgentCard has no name")
	}
	return c, nil
}

// cardReader reads Card fields by exact key; the first type error sticks.
type cardReader struct{ err error }

func (r *cardReader) bad(k string) {
	if r.err == nil {
		r.err = fmt.Errorf("a2a: AgentCard: %q has the wrong type", k)
	}
}

func (r *cardReader) str(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		r.bad(k)
	}
	return s
}

func (r *cardReader) objs(m map[string]any, k string) []map[string]any {
	v, ok := m[k]
	if !ok || v == nil {
		return nil
	}
	a, ok := v.([]any)
	if !ok {
		r.bad(k)
		return nil
	}
	out := make([]map[string]any, 0, len(a))
	for _, e := range a {
		o, ok := e.(map[string]any)
		if !ok {
			r.bad(k)
			return nil
		}
		out = append(out, o)
	}
	return out
}

// Digest is the pin Halos stores for a card: "sha256:<hex>" over its RFC 8785
// canonical form, signatures included, so whitespace and member order do not
// matter but any change of content does.
func Digest(raw []byte) (string, error) {
	c, err := Canonicalize(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Key is a public key that may have signed a card.
type Key struct {
	ID  string // JWK kid; "" for a pinned PEM key (matches any kid)
	Pub crypto.PublicKey
}

// ParseJWKS reads the keys of an RFC 7517 JWK Set: OKP Ed25519, EC P-256 and
// P-384, RSA (>= 2048 bits). Keys of other types are skipped.
func ParseJWKS(b []byte) ([]Key, error) {
	var set struct {
		Keys []struct {
			Kty, Kid, Crv, X, Y, N, E, Use string
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("a2a: JWKS: %w", err)
	}
	dec := base64.RawURLEncoding.DecodeString
	var out []Key
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "OKP":
			x, err := dec(k.X)
			if k.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
				continue
			}
			out = append(out, Key{ID: k.Kid, Pub: ed25519.PublicKey(x)})
		case "EC":
			x, err1 := dec(k.X)
			y, err2 := dec(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			curve, size := elliptic.P256(), 32
			switch k.Crv {
			case "P-256":
			case "P-384":
				curve, size = elliptic.P384(), 48
			default:
				continue
			}
			if len(x) != size || len(y) != size {
				continue
			}
			// Validates that the point is on the curve.
			if pk, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...)); err == nil {
				out = append(out, Key{ID: k.Kid, Pub: pk})
			}
		case "RSA":
			n, err1 := dec(k.N)
			e, err2 := dec(k.E)
			if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
				continue
			}
			pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			if pk.N.BitLen() >= 2048 {
				out = append(out, Key{ID: k.Kid, Pub: pk})
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("a2a: JWKS has no usable signing key")
	}
	return out, nil
}

// VerifySignatures checks that at least one of the card's signatures verifies
// with one of keys. The payload is the RFC 8785 form of the card without its
// signatures member; a card signed after dropping empty (default-valued)
// members, as section 8.4.1 asks, verifies too. A jku header is never
// followed: keys come from policy only.
func VerifySignatures(raw []byte, keys []Key) error {
	v, err := decodeJSON(raw)
	if err != nil {
		return err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return errors.New("a2a: AgentCard is not a JSON object")
	}
	sigs, _ := obj["signatures"].([]any)
	if len(sigs) == 0 {
		return fmt.Errorf("%w: the card is not signed", ErrSignature)
	}
	delete(obj, "signatures")
	var payloads [][]byte
	for _, o := range []any{obj, pruneDefaults(obj)} {
		var buf bytes.Buffer
		if err := writeJCS(&buf, o); err != nil {
			return err
		}
		payloads = append(payloads, buf.Bytes())
	}
	var last error
	for _, s := range sigs {
		sm, _ := s.(map[string]any)
		prot, _ := sm["protected"].(string)
		sig, _ := sm["signature"].(string)
		for _, p := range payloads {
			if last = verifyJWS(prot, sig, p, keys); last == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: %v", ErrSignature, last)
}

// pruneDefaults drops members whose value is "", [] or {} (proto3 defaults
// of non-optional fields), recursively.
func pruneDefaults(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range v {
			e = pruneDefaults(e)
			switch e := e.(type) {
			case string:
				if e == "" {
					continue
				}
			case []any:
				if len(e) == 0 {
					continue
				}
			case map[string]any:
				if len(e) == 0 {
					continue
				}
			}
			out[k] = e
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = pruneDefaults(e)
		}
		return out
	}
	return v
}

func verifyJWS(protected, signature string, payload []byte, keys []Key) error {
	hb, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return fmt.Errorf("protected header: %w", err)
	}
	var hdr struct {
		Alg, Kid string
		Crit     []string
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return fmt.Errorf("protected header: %w", err)
	}
	if len(hdr.Crit) > 0 {
		return fmt.Errorf("crit header %v not understood", hdr.Crit)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	input := []byte(protected + "." + base64.RawURLEncoding.EncodeToString(payload))
	tried := false
	for _, k := range keys {
		if k.ID != "" && hdr.Kid != k.ID {
			continue
		}
		ok, applicable := verifyAlg(hdr.Alg, k.Pub, input, sig)
		tried = tried || applicable
		if ok {
			return nil
		}
	}
	if !tried {
		return fmt.Errorf("no configured key for alg %q kid %q", hdr.Alg, hdr.Kid)
	}
	return errors.New("signature does not verify")
}

// verifyAlg verifies sig over input with pub under alg. applicable reports
// whether the key type fits the algorithm (none, HS* and unknown never do).
func verifyAlg(alg string, pub crypto.PublicKey, input, sig []byte) (ok, applicable bool) {
	switch alg {
	case "EdDSA", "Ed25519":
		k, is := pub.(ed25519.PublicKey)
		return is && ed25519.Verify(k, input, sig), is
	case "ES256", "ES384":
		k, is := pub.(*ecdsa.PublicKey)
		size, h := 32, crypto.SHA256
		if alg == "ES384" {
			size, h = 48, crypto.SHA384
		}
		if !is || k.Curve.Params().BitSize != size*8 {
			return false, false
		}
		if len(sig) != 2*size {
			return false, true
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, digest(h, input), r, s), true
	case "RS256", "PS256":
		k, is := pub.(*rsa.PublicKey)
		if !is {
			return false, false
		}
		d := digest(crypto.SHA256, input)
		if alg == "RS256" {
			return rsa.VerifyPKCS1v15(k, crypto.SHA256, d, sig) == nil, true
		}
		return rsa.VerifyPSS(k, crypto.SHA256, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil, true
	}
	return false, false
}

func digest(h crypto.Hash, b []byte) []byte {
	if h == crypto.SHA384 {
		s := sha512.Sum384(b)
		return s[:]
	}
	s := sha256.Sum256(b)
	return s[:]
}

// Expect is what policy pins for a card.
type Expect struct {
	Digest    string // sha256:<hex>; "" = not checked
	PublicKey string // PEM
	JWKSURL   string
}

// Result is a fetched and verified card.
type Result struct {
	Card   Card   `json:"card"`
	Digest string `json:"digest"`
	// Signed: the card carries signatures; Verified: one verified with the
	// pinned key or JWKS (false when none is configured).
	Signed   bool `json:"signed"`
	Verified bool `json:"verified"`
}

// Verify fetches cardURL and checks it against exp: the JWS signature when a
// key or JWKS is pinned (an unsigned card then fails), and the digest when
// one is pinned. The Result is returned with the error, for reporting.
func (f Fetcher) Verify(ctx context.Context, cardURL string, exp Expect) (Result, error) {
	raw, err := f.Get(ctx, cardURL)
	if err != nil {
		return Result{}, err
	}
	card, err := ParseCard(raw)
	if err != nil {
		return Result{}, err
	}
	dg, err := Digest(raw)
	if err != nil {
		return Result{}, err
	}
	res := Result{Card: card, Digest: dg, Signed: len(card.Signatures) > 0}
	var keys []Key
	if exp.PublicKey != "" {
		k, err := policy.ParseCardKey(exp.PublicKey)
		if err != nil {
			return res, fmt.Errorf("a2a: pinned public key: %w", err)
		}
		keys = append(keys, Key{Pub: k})
	}
	if exp.JWKSURL != "" {
		b, err := f.Get(ctx, exp.JWKSURL)
		if err != nil {
			return res, err
		}
		ks, err := ParseJWKS(b)
		if err != nil {
			return res, err
		}
		keys = append(keys, ks...)
	}
	if len(keys) > 0 {
		if err := VerifySignatures(raw, keys); err != nil {
			return res, err
		}
		res.Verified = true
	}
	if exp.Digest != "" && exp.Digest != dg {
		return res, fmt.Errorf("%w: pinned %s, served %s", ErrDigestMismatch, exp.Digest, dg)
	}
	return res, nil
}
