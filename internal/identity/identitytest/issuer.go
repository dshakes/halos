// Package identitytest is a tiny OIDC issuer (discovery + JWKS + token
// minting + an auto-approving authorization-code/PKCE flow) for tests and the
// compose demo. Not for production use.
package identitytest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

// Issuer serves /.well-known/openid-configuration and /jwks.
type Issuer struct {
	URL string // issuer identifier; set once serving
	Key *rsa.PrivateKey
	KID string

	mu    sync.Mutex
	login map[string]any   // claims /authorize grants next (SetLogin)
	codes map[string]grant // outstanding authorization codes (single use)
}

type grant struct {
	clientID, redirect, nonce, challenge string
	claims                               map[string]any
}

// SetLogin sets the claims (e.g. email, groups) the /authorize endpoint
// auto-approves for subsequent code flows; nil makes /authorize refuse.
func (i *Issuer) SetLogin(claims map[string]any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.login = claims
}

// NewIssuer generates a key. Call Handler (demo) or Serve (tests) next.
func NewIssuer(kid string) (*Issuer, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("identitytest: generate key: %w", err)
	}
	return &Issuer{Key: k, KID: kid}, nil
}

// Handler serves discovery and JWKS; i.URL must already be the public issuer URL.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": i.URL, "jwks_uri": i.URL + "/jwks", "authorization_endpoint": i.URL + "/authorize",
			"token_endpoint": i.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code", "id_token"}, "subject_types_supported": []string{"public"},
			"code_challenge_methods_supported": []string{"S256"}, "grant_types_supported": []string{"authorization_code"},
		})
	})
	mux.HandleFunc("GET /authorize", i.authorize)
	mux.HandleFunc("POST /token", i.token)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{i.JWK()}})
	})
	return mux
}

// Serve starts an httptest server and points i.URL at it. Caller closes.
func (i *Issuer) Serve() *httptest.Server {
	s := httptest.NewUnstartedServer(nil)
	s.Config.Handler = i.Handler()
	s.Start()
	i.URL = s.URL
	return s
}

// JWK is the public key as a JSON Web Key.
func (i *Issuer) JWK() map[string]string {
	e := big.NewInt(int64(i.Key.E)).Bytes()
	return map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": i.KID,
		"n": b64(i.Key.N.Bytes()), "e": b64(e)}
}

// Mint signs claims (RS256) with the issuer key. iss/exp/iat are defaulted,
// and email_verified=true when an email is present (as a real IdP would); a
// nil claim value removes the claim (e.g. "email_verified": nil).
func (i *Issuer) Mint(claims map[string]any) (string, error) {
	c := map[string]any{"iss": i.URL, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	if _, ok := claims["email"]; ok {
		c["email_verified"] = true
	}
	for k, v := range claims {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return Sign(map[string]any{"alg": "RS256", "typ": "JWT", "kid": i.KID}, c, func(in []byte) ([]byte, error) {
		h := sha256.Sum256(in)
		return rsa.SignPKCS1v15(rand.Reader, i.Key, crypto.SHA256, h[:])
	})
}

// Sign assembles header.payload.signature with a caller-supplied signer
// (nil signer => empty signature, for alg=none tests).
func Sign(header, claims map[string]any, sign func([]byte) ([]byte, error)) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64(hb) + "." + b64(cb)
	var sig []byte
	if sign != nil {
		if sig, err = sign([]byte(in)); err != nil {
			return "", fmt.Errorf("identitytest: sign: %w", err)
		}
	}
	return in + "." + b64(sig), nil
}

// authorize auto-approves the SetLogin identity: it requires response_type=code
// and an S256 PKCE challenge, then redirects back with a single-use code.
func (i *Issuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ru, err := url.Parse(q.Get("redirect_uri"))
	switch {
	case q.Get("response_type") != "code", q.Get("client_id") == "", err != nil, ru.Host == "":
		http.Error(w, "response_type=code, client_id and an absolute redirect_uri are required", http.StatusBadRequest)
		return
	case q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	claims := i.login
	code := randString()
	if claims != nil {
		if i.codes == nil {
			i.codes = map[string]grant{}
		}
		i.codes[code] = grant{q.Get("client_id"), q.Get("redirect_uri"), q.Get("nonce"), q.Get("code_challenge"), claims}
	}
	i.mu.Unlock()
	back := ru.Query()
	if claims == nil {
		back.Set("error", "access_denied")
	} else {
		back.Set("code", code)
	}
	back.Set("state", q.Get("state"))
	ru.RawQuery = back.Encode()
	http.Redirect(w, r, ru.String(), http.StatusFound) //nolint:gosec // test issuer; redirect target is the registered test redirect URI
}

// token redeems a code once, checking client, redirect_uri and the PKCE verifier.
func (i *Issuer) token(w http.ResponseWriter, r *http.Request) {
	fail := func(e string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": e})
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "authorization_code" {
		fail("unsupported_grant_type")
		return
	}
	client := r.PostForm.Get("client_id")
	if u, _, ok := r.BasicAuth(); ok {
		client, _ = url.QueryUnescape(u)
	}
	i.mu.Lock()
	g, ok := i.codes[r.PostForm.Get("code")]
	delete(i.codes, r.PostForm.Get("code"))
	i.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !ok, g.clientID != client, g.redirect != r.PostForm.Get("redirect_uri"), b64(sum[:]) != g.challenge:
		fail("invalid_grant")
		return
	}
	claims := map[string]any{"aud": g.clientID, "sub": "identitytest-user"} // g.claims may override sub
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	for k, v := range g.claims {
		claims[k] = v
	}
	idt, err := i.Mint(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": randString(), "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
}

func randString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand never fails on supported platforms
	return b64(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
