package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// ErrClaimsRejected marks a token whose signature verified against a trusted
// key but whose claims did not pass (expired, wrong audience, not yet valid,
// a revoked session, ...). It is not a forgery: callers that rate-limit
// failed attempts per client IP do not count it, because anyone on a shared
// CI runner can mint such tokens and would otherwise lock out its other jobs.
var ErrClaimsRejected = errors.New("identity: token signature valid, claims rejected")

// claimsError wraps a claim check that failed after the signature verified,
// so errors.Is(err, ErrClaimsRejected) holds and the message stays err's.
type claimsError struct{ error }

func (e claimsError) Unwrap() error      { return e.error }
func (claimsError) Is(target error) bool { return target == ErrClaimsRejected }

type cacheOnlyKey struct{}

// CacheOnly marks ctx so OIDC verification uses only discovery documents and
// JWKS keys already cached, never fetching: a request from a client IP
// blocked for failed attempts can still prove it holds a signed token without
// being able to make halo-server call the issuer.
func CacheOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, cacheOnlyKey{}, true)
}

func cacheOnly(ctx context.Context) bool { b, _ := ctx.Value(cacheOnlyKey{}).(bool); return b }

// sigVerified records, for one Claims call, that the signature verified.
type sigVerified struct{ ok bool }

type sigVerifiedKey struct{}

// jwksKeySet is an issuer's JWKS for oidc.NewVerifier: keys are cached and
// refetched when no cached key verifies a token (key rotation), except for a
// CacheOnly context. One fetch runs at a time; callers that waited for it
// use its result instead of fetching again.
type jwksKeySet struct {
	url    string
	client *http.Client

	mu   sync.RWMutex
	keys []jose.JSONWebKey
	gen  uint64 // bumped by every completed fetch

	fetchMu sync.Mutex
}

// maxJWKSBody bounds a JWKS response.
const maxJWKSBody = 1 << 20

func joseAlgs() []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, len(AllowedAlgs))
	for i, a := range AllowedAlgs {
		out[i] = jose.SignatureAlgorithm(a)
	}
	return out
}

// VerifySignature implements oidc.KeySet.
func (k *jwksKeySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, joseAlgs())
	if err != nil {
		return nil, fmt.Errorf("identity: malformed jwt: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("identity: jwt must carry exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID
	k.mu.RLock()
	keys, gen := k.keys, k.gen
	k.mu.RUnlock()
	payload, ok := verifyWith(jws, kid, keys)
	if !ok && !cacheOnly(ctx) {
		if keys, err = k.refresh(ctx, gen); err != nil {
			return nil, err
		}
		payload, ok = verifyWith(jws, kid, keys)
	}
	if !ok {
		return nil, errors.New("identity: jwt signature does not verify against the issuer's keys")
	}
	if s, _ := ctx.Value(sigVerifiedKey{}).(*sigVerified); s != nil {
		s.ok = true
	}
	return payload, nil
}

func verifyWith(jws *jose.JSONWebSignature, kid string, keys []jose.JSONWebKey) ([]byte, bool) {
	for i := range keys {
		if kid == "" || keys[i].KeyID == kid {
			if p, err := jws.Verify(&keys[i]); err == nil {
				return p, true
			}
		}
	}
	return nil, false
}

// refresh fetches the JWKS unless a fetch completed since the caller read
// generation seen, and returns the current keys.
func (k *jwksKeySet) refresh(ctx context.Context, seen uint64) ([]jose.JSONWebKey, error) {
	k.fetchMu.Lock()
	defer k.fetchMu.Unlock()
	k.mu.RLock()
	keys, gen := k.keys, k.gen
	k.mu.RUnlock()
	if gen != seen {
		return keys, nil
	}
	keys, err := k.fetch(ctx)
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	k.keys, k.gen = keys, k.gen+1
	k.mu.Unlock()
	return keys, nil
}

func (k *jwksKeySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, fmt.Errorf("identity: jwks request %s: %w", k.url, err)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: fetch jwks %s: %w", k.url, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: fetch jwks %s: HTTP %d", k.url, resp.StatusCode)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBody)).Decode(&set); err != nil {
		return nil, fmt.Errorf("identity: decode jwks %s: %w", k.url, err)
	}
	var keys []jose.JSONWebKey
	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		// Skip keys go-jose cannot use (unknown kty, curves) rather than fail
		// the whole set, as RFC 7517 section 5 asks.
		if json.Unmarshal(raw, &key) != nil || !key.Valid() || !key.IsPublic() {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}
