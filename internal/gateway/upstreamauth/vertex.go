package upstreamauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource yields a bearer token for a provider API. Implementations cache
// and refresh; they are safe for concurrent use.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

const (
	gcpScope        = "https://www.googleapis.com/auth/cloud-platform"
	metadataBase    = "http://metadata.google.internal"
	tokenRefreshGap = time.Minute
)

// tokenCache serialises refreshes and serves a token until shortly before it expires.
type tokenCache struct {
	mu  sync.Mutex
	tok string
	exp time.Time
}

func (c *tokenCache) get(now time.Time, fetch func() (string, time.Duration, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != "" && now.Add(tokenRefreshGap).Before(c.exp) {
		return c.tok, nil
	}
	tok, ttl, err := fetch()
	if err != nil {
		return "", err
	}
	c.tok, c.exp = tok, now.Add(ttl)
	return tok, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func decodeToken(resp *http.Response, what string) (string, time.Duration, error) {
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("upstreamauth: %s: read response: %w", what, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("upstreamauth: %s: HTTP %d", what, resp.StatusCode) // body may echo credentials: not logged
	}
	var t tokenResponse
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", 0, fmt.Errorf("upstreamauth: %s: response has no access_token", what)
	}
	return t.AccessToken, time.Duration(t.ExpiresIn) * time.Second, nil
}

// MetadataTokenSource reads tokens from the GCE/GKE metadata server (workload
// identity, attached service account).
type MetadataTokenSource struct {
	BaseURL string       // default http://metadata.google.internal
	Client  *http.Client // default 5s timeout
	now     func() time.Time
	cache   tokenCache
}

func (m *MetadataTokenSource) Token(ctx context.Context) (string, error) {
	now := time.Now
	if m.now != nil {
		now = m.now
	}
	return m.cache.get(now(), func() (string, time.Duration, error) {
		base, cl := m.BaseURL, m.Client
		if base == "" {
			base = metadataBase
		}
		if cl == nil {
			cl = &http.Client{Timeout: 5 * time.Second}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
		if err != nil {
			return "", 0, fmt.Errorf("upstreamauth: metadata token: %w", err)
		}
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := cl.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("upstreamauth: metadata token: %w", err)
		}
		return decodeToken(resp, "metadata token")
	})
}

// ServiceAccountTokenSource exchanges a service-account key (JSON file) for
// tokens with the OAuth2 JWT-bearer grant.
type ServiceAccountTokenSource struct {
	Client   *http.Client
	key      *rsa.PrivateKey
	email    string
	tokenURI string
	now      func() time.Time
	cache    tokenCache
}

// NewServiceAccountTokenSource parses a service-account key. token_uri must be
// an https googleapis.com host: the signed assertion is only sent there.
func NewServiceAccountTokenSource(keyJSON []byte) (*ServiceAccountTokenSource, error) {
	var k struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(keyJSON, &k); err != nil {
		return nil, fmt.Errorf("upstreamauth: parse service account key: %w", err)
	}
	if k.Type != "service_account" {
		return nil, fmt.Errorf("upstreamauth: credential file type %q unsupported: want service_account (use workload identity / the metadata server for other kinds)", k.Type)
	}
	if k.TokenURI == "" {
		k.TokenURI = "https://oauth2.googleapis.com/token"
	}
	u, err := url.Parse(k.TokenURI)
	if err != nil || u.Scheme != "https" || (u.Hostname() != "googleapis.com" && !strings.HasSuffix(u.Hostname(), ".googleapis.com")) {
		return nil, fmt.Errorf("upstreamauth: token_uri %q must be an https googleapis.com URL", k.TokenURI)
	}
	blk, _ := pem.Decode([]byte(k.PrivateKey))
	if blk == nil || k.ClientEmail == "" {
		return nil, errors.New("upstreamauth: service account key needs client_email and a PEM private_key")
	}
	var key *rsa.PrivateKey
	if pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		var ok bool
		if key, ok = pk.(*rsa.PrivateKey); !ok {
			return nil, errors.New("upstreamauth: service account private_key is not RSA")
		}
	} else if key, err = x509.ParsePKCS1PrivateKey(blk.Bytes); err != nil {
		return nil, fmt.Errorf("upstreamauth: parse service account private_key: %w", err)
	}
	return &ServiceAccountTokenSource{key: key, email: k.ClientEmail, tokenURI: k.TokenURI}, nil
}

func (s *ServiceAccountTokenSource) Token(ctx context.Context) (string, error) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	return s.cache.get(now(), func() (string, time.Duration, error) {
		assertion, err := s.assertion(now())
		if err != nil {
			return "", 0, err
		}
		cl := s.Client
		if cl == nil {
			cl = &http.Client{Timeout: 10 * time.Second}
		}
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURI, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, fmt.Errorf("upstreamauth: service account token: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := cl.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("upstreamauth: service account token: %w", err)
		}
		return decodeToken(resp, "service account token")
	})
}

func (s *ServiceAccountTokenSource) assertion(now time.Time) (string, error) {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signing := enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." +
		enc(map[string]any{"iss": s.email, "scope": gcpScope, "aud": s.tokenURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("upstreamauth: sign service account assertion: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// DefaultTokenSource is Google ADC, minus the gcloud user credentials: the
// service-account key at $GOOGLE_APPLICATION_CREDENTIALS when set, else the
// metadata server (GKE workload identity, GCE, Cloud Run).
func DefaultTokenSource(getenv func(string) string) (TokenSource, error) {
	if p := getenv("GOOGLE_APPLICATION_CREDENTIALS"); p != "" {
		b, err := os.ReadFile(p) //nolint:gosec // operator-supplied path is the point
		if err != nil {
			return nil, fmt.Errorf("upstreamauth: read GOOGLE_APPLICATION_CREDENTIALS: %w", err)
		}
		return NewServiceAccountTokenSource(b)
	}
	return &MetadataTokenSource{}, nil
}
